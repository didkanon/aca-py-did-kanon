"""Auto-publish to AnonCredsStatusRegistry and/or MerkleStateRegistry
whenever an issue_credential_v2_0 record reaches `state=done` with
`role=issuer`.

Routes by the cred-def's on-chain `policyMask`:

    TIER_ONE_TIME (1) → AnonCredsStatusRegistry.issueCredential
    TIER_ZK_SNARK (2) → MerkleStateRegistry.batchUpdate add leaf
    TIER_ALL      (3) → both

This is the Python equivalent of the credo-ts plugin's
`KanonIssuanceTracker`. The two together let the issuer side of either
agent type dual-write on issuance without any caller intervention.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Optional

from acapy_agent.core.event_bus import Event, EventBus
from acapy_agent.core.profile import Profile

from did_kanon.v1_0.config import DidKanonConfig
from did_kanon.v1_0.contracts.cred_def_registry import TIER_ONE_TIME, TIER_ZK_SNARK
from did_kanon.v1_0.contracts.pool import KanonRegistryPool
from did_kanon.v1_0.zk.zk_issuer import KanonZkIssuer


LOGGER = logging.getLogger(__name__)

# `BaseExchangeRecord.emit_event` builds topics as
# `{EVENT_NAMESPACE}::{RECORD_TOPIC}::{state}`. EVENT_NAMESPACE defaults to
# `acapy::record`, RECORD_TOPIC on `V20CredExRecord` is `issue_credential_v2_0`,
# and the state we care about is `done`. We subscribe with a regex so a future
# upstream change in the topic shape surfaces here, not silently.
ISSUE_CREDENTIAL_DONE_PATTERN = re.compile(
    r"^acapy::record::issue_credential_v2_0::done$"
)

# kanon's bookkeeping attribute name. Mirrored from
# `did_kanon.v1_0.cred_id_hash.KANON_CRED_ID_ATTRIBUTE` to avoid the import
# cycle (cred_id_hash also pulls web3, which is fine, but the constant is
# stable).
KANON_CRED_ID_ATTRIBUTE = "kanonCredId"

# Per-process cache so we don't re-fetch the cred-def's policyMask for every
# issuance. The mask is immutable post-registration on chain, but cache a
# TTL alongside the value so a redeployed/re-registered credDef eventually
# surfaces the new mask without requiring a process restart.
_POLICY_MASK_TTL_S = 5 * 60
_POLICY_MASK_CACHE: dict[bytes, tuple[int, float]] = {}


def attach(context, config: DidKanonConfig, pool: KanonRegistryPool) -> None:
    """Subscribe the listener on the agent's EventBus. Idempotent —
    duplicate calls re-register the same subscription which is harmless.
    """
    event_bus = context.inject_or(EventBus)
    if event_bus is None:
        LOGGER.warning(
            "did:kanon: no EventBus in context; issuance auto-publish disabled"
        )
        return

    async def _handler(profile: Profile, event: Event) -> None:
        try:
            await _on_issue_credential_done(profile, event, config, pool)
        except Exception as err:
            LOGGER.exception(
                "did:kanon: issuance listener failed (continuing): %s", err
            )

    event_bus.subscribe(ISSUE_CREDENTIAL_DONE_PATTERN, _handler)
    LOGGER.info(
        "did:kanon: issuance auto-publish listener attached "
        "(pattern=%s)",
        ISSUE_CREDENTIAL_DONE_PATTERN.pattern,
    )


async def _on_issue_credential_done(
    profile: Profile,
    event: Event,
    config: DidKanonConfig,
    pool: KanonRegistryPool,
) -> None:
    payload = event.payload or {}

    # Filter to issuer role only — holder-side `done` events would otherwise
    # double-fire.
    if payload.get("role") != "issuer":
        return

    cred_def_id = _extract_cred_def_id(payload)
    record_payload: dict = payload
    if not cred_def_id:
        # The `done`-state payload from `V20CredExRecord.emit_event` is a
        # serialized form that drops `by_format`/`cred_proposal` (they're
        # large, and the record-storage callers only need the top-level
        # state for routing). Re-fetch the full record so we can recover
        # both `cred_def_id` AND the issued attribute values (kanonCredId,
        # domain attrs) for Mode B leaf reconstruction.
        record_payload = await _refetch_full_record(
            profile, payload.get("cred_ex_id")
        )
        cred_def_id = _extract_cred_def_id(record_payload) or await _lookup_cred_def_id_from_record(
            profile, payload.get("cred_ex_id")
        )
    if not cred_def_id:
        LOGGER.debug(
            "did:kanon: skipping issuance auto-publish — no cred_def_id on payload "
            "or detail record (cred_ex_id=%s)", payload.get("cred_ex_id"),
        )
        return
    # From here on, use `record_payload` for value-extraction (kanonCredId,
    # domain attrs) — the trimmed `payload` won't have them.
    payload = record_payload

    cred_def_bytes = _b32(cred_def_id)
    network = pool.network_config()
    registries = pool.for_network(network.name)

    policy_mask = await _resolve_policy_mask(registries, cred_def_bytes)

    # ── kanonCredId resolution ──
    # Mode B / TIER_ALL credentials carry `kanonCredId` as an issued
    # attribute (the SDK + prepare-mode-b inject it because the BJJ leaf
    # signature is keyed by it). Mode A credDefs are schema-clean — no
    # kanonCredId attribute — so we auto-generate one here and remember
    # the `cred_ex_id ↔ kanon_cred_id` binding. The revoke route then
    # accepts the visible cred_ex_id from the admin API.
    cred_id = _extract_kanon_cred_id(payload)
    auto_generated = False
    if not cred_id:
        if policy_mask & TIER_ZK_SNARK:
            # Mode B / TIER_ALL without an injected credId can't be
            # auto-recovered — the BJJ leaf signature is built BEFORE
            # issuance over a credId we'd need to have signed already.
            # Surface this as a no-op + warning.
            LOGGER.warning(
                "did:kanon: cred %s (credDef %s) policy_mask=%d requires "
                "Mode B — but no kanonCredId attribute was issued. Use "
                "/did/kanon/zk/prepare-mode-b to obtain attrs.",
                payload.get("cred_ex_id"), cred_def_id, policy_mask,
            )
            return
        import uuid

        cred_id = f"kc-{uuid.uuid4().hex}"
        auto_generated = True

    if auto_generated:
        cred_ex_id = payload.get("cred_ex_id")
        if cred_ex_id:
            try:
                from did_kanon.v1_0.anoncreds.revreg_state import (
                    remember_credex_cred_id,
                )

                await remember_credex_cred_id(
                    profile,
                    cred_ex_id=cred_ex_id,
                    kanon_cred_id=cred_id,
                    cred_def_id=cred_def_id,
                )
                LOGGER.info(
                    "did:kanon: auto-generated kanonCredId for cred_ex_id=%s → %s",
                    cred_ex_id, cred_id,
                )
            except Exception as err:  # noqa: BLE001
                LOGGER.warning(
                    "did:kanon: failed to persist cred_ex_id → kanonCredId "
                    "binding (cred_ex_id=%s, cred_id=%s): %s",
                    cred_ex_id, cred_id, err,
                )
    LOGGER.info(
        "did:kanon: issuance done for %s (credDef=%s, policyMask=%d)",
        cred_id, cred_def_id, policy_mask,
    )

    # ── Mode A ──
    if policy_mask & TIER_ONE_TIME:
        from web3 import Web3

        cred_id_hash = Web3.keccak(text=cred_id)
        try:
            await registries.status.issue_credential(cred_def_bytes, cred_id_hash)
            LOGGER.info("did:kanon: Mode A issue recorded for %s", cred_id)
        except Exception as err:
            LOGGER.error(
                "did:kanon: Mode A issue write failed for %s: %s", cred_id, err
            )

    # ── Mode B ──
    if policy_mask & TIER_ZK_SNARK:
        try:
            domain_attributes = _extract_domain_attributes(payload)
            LOGGER.info(
                "did:kanon: Mode B publish start cred=%s, %d domain attrs",
                cred_id, len(domain_attributes),
            )
            issuer = KanonZkIssuer(registries.merkle, profile)
            # `add_issued` expects a 32-byte credDef id (hex or raw bytes),
            # not a DID URL. Hash the URL the same way the on-chain side
            # does so leaf state is keyed identically across both surfaces.
            receipt = await issuer.add_issued(
                cred_def_bytes, [(cred_id, domain_attributes)]
            )
            LOGGER.info(
                "did:kanon: Mode B leaf published for %s (%d domain attrs, receipt=%s)",
                cred_id, len(domain_attributes),
                receipt.get("tx_hash") if isinstance(receipt, dict) else receipt,
            )
        except Exception as err:
            LOGGER.exception(
                "did:kanon: Mode B leaf publish failed for %s: %s", cred_id, err
            )

    # ── Rev-reg-index binding ──
    # ACA-Py revokes by (rev_reg_id, cred_rev_id) integer index. To make
    # `/anoncreds/revocation/revoke` flow through to the kanon revoke
    # path, we remember which kanonCredId each (rev_reg_id, cred_rev_id)
    # was issued under. Cheap (one BaseStorage write per issuance) and
    # only populated when the credDef opted in to AnonCreds-style
    # revocation. Mode-A-only credefs that revoke through
    # /did/kanon/revoke don't need the binding.
    rev_reg_id, cred_rev_id = _extract_rev_reg_binding(payload)
    if rev_reg_id and cred_rev_id is not None:
        try:
            from did_kanon.v1_0.anoncreds.revreg_state import remember_cred_index

            await remember_cred_index(
                profile,
                rev_reg_id=rev_reg_id,
                cred_rev_id=cred_rev_id,
                kanon_cred_id=cred_id,
            )
            LOGGER.debug(
                "did:kanon: bound (%s, %d) → %s for revocation translation",
                rev_reg_id, cred_rev_id, cred_id,
            )
        except Exception as err:  # noqa: BLE001
            LOGGER.warning(
                "did:kanon: failed to persist rev-reg index binding "
                "(%s, %s) → %s: %s",
                rev_reg_id, cred_rev_id, cred_id, err,
            )


async def _resolve_policy_mask(registries, cred_def_id_bytes: bytes) -> int:
    """Read + cache the on-chain `policyMask` for a credDef. Falls back to
    `TIER_ONE_TIME` if the credDef is missing — the contract write will then
    fail loudly, which is the right behaviour."""
    cached = _POLICY_MASK_CACHE.get(cred_def_id_bytes)
    if cached is not None:
        mask, expires_at = cached
        if time.monotonic() < expires_at:
            return mask
    try:
        record = await registries.cred_def.get_credential_definition(
            cred_def_id_bytes
        )
        mask = int(record["policy_mask"]) if record else TIER_ONE_TIME
    except Exception as err:
        LOGGER.warning(
            "did:kanon: getCredDef(%s) failed (%s); defaulting to TIER_ONE_TIME",
            cred_def_id_bytes.hex(), err,
        )
        mask = TIER_ONE_TIME
    _POLICY_MASK_CACHE[cred_def_id_bytes] = (
        mask,
        time.monotonic() + _POLICY_MASK_TTL_S,
    )
    return mask


async def _refetch_full_record(profile, cred_ex_id: Optional[str]) -> dict:
    """Re-fetch the V20CredExRecord serialization (full `by_format`+`cred_*`).

    The `done`-state event payload is trimmed. The full record carries
    `by_format.cred_issue.<fmt>.values` (with `kanonCredId`) and
    `cred_proposal.filters~attach` (with `cred_def_id`). Returns `{}` on
    any failure — callers handle that gracefully.
    """
    if not cred_ex_id:
        return {}
    try:
        from acapy_agent.protocols.issue_credential.v2_0.models.cred_ex_record import (
            V20CredExRecord,
        )

        async with profile.session() as session:
            cred_ex = await V20CredExRecord.retrieve_by_id(session, cred_ex_id)
            if cred_ex is not None:
                return cred_ex.serialize()
    except Exception as err:  # noqa: BLE001
        LOGGER.debug(
            "did:kanon: full record refetch for cred_ex_id=%s failed: %s",
            cred_ex_id, err,
        )
    return {}


async def _lookup_cred_def_id_from_record(
    profile, cred_ex_id: Optional[str]
) -> Optional[str]:
    """Re-fetch the cred-ex record + anoncreds detail by `cred_ex_id`.

    ACA-Py's `V20CredExRecord.emit_event` serializes a trimmed payload at
    the `done` state; `by_format` and `cred_proposal` are dropped. The
    credDef id we need lives on the anoncreds-detail sibling record
    (`V20CredExRecordAnonCreds`) which is queried by `cred_ex_id`.
    """
    if not cred_ex_id:
        return None
    try:
        from acapy_agent.protocols.issue_credential.v2_0.models.cred_ex_record import (
            V20CredExRecord,
        )
        from acapy_agent.protocols.issue_credential.v2_0.models.detail.anoncreds import (
            V20CredExRecordAnonCreds,
        )

        async with profile.session() as session:
            try:
                cred_ex = await V20CredExRecord.retrieve_by_id(session, cred_ex_id)
            except Exception:  # noqa: BLE001
                cred_ex = None

            # Fast path — `by_format` on the record carries cred_def_id.
            if cred_ex is not None:
                from_record = _extract_cred_def_id(cred_ex.serialize())
                if from_record:
                    return from_record

            # Detail-row path: V20CredExRecordAnonCreds.cred_def_id.
            details = await V20CredExRecordAnonCreds.query_by_cred_ex_id(
                session, cred_ex_id
            )
            for det in details or []:
                cd = getattr(det, "cred_def_id", None)
                if isinstance(cd, str) and cd:
                    return cd
    except Exception as err:  # noqa: BLE001
        LOGGER.debug(
            "did:kanon: cred_def_id lookup for cred_ex_id=%s failed: %s",
            cred_ex_id, err,
        )
    return None


def _extract_cred_def_id(payload: dict) -> Optional[str]:
    """Find the cred-def id in a v2_0 cred-ex payload. Lives in the
    by_format / cred_issue / anoncreds / cred_def_id path, or as a direct
    `cred_def_id` attribute on older record shapes.
    """
    direct = payload.get("cred_def_id") or payload.get("credential_definition_id")
    if isinstance(direct, str) and direct:
        return direct
    by_format = payload.get("by_format") or {}
    for slot in ("cred_issue", "cred_offer"):
        fmt = by_format.get(slot) or {}
        for fmt_name in ("anoncreds", "indy"):
            entry = fmt.get(fmt_name) or {}
            cd = entry.get("cred_def_id")
            if isinstance(cd, str) and cd:
                return cd
    return None


def _extract_rev_reg_binding(payload: dict) -> tuple[Optional[str], Optional[int]]:
    """Pull `(rev_reg_id, cred_rev_id)` from a v2_0 cred-ex payload.

    AnonCreds-RS stamps the credential with both values at issuance time
    when the credDef opts into revocation. They live on the cred-issue
    record alongside `cred_def_id` and the values map.

    Returns `(None, None)` for non-revocable credentials — the credDef
    didn't have `support_revocation=true` so ACA-Py never allocated a
    rev_reg slot, and the revoke flow doesn't apply.
    """
    direct_rev_reg = payload.get("rev_reg_id") or payload.get("revocation_registry_id")
    direct_cred_rev = payload.get("cred_rev_id") or payload.get("credential_revocation_id")
    if isinstance(direct_rev_reg, str) and direct_rev_reg:
        try:
            return direct_rev_reg, int(direct_cred_rev) if direct_cred_rev is not None else None
        except (TypeError, ValueError):
            pass

    by_format = payload.get("by_format") or {}
    for slot in ("cred_issue", "cred_offer"):
        fmt = by_format.get(slot) or {}
        for fmt_name in ("anoncreds", "indy"):
            entry = fmt.get(fmt_name) or {}
            rrid = entry.get("rev_reg_id") or entry.get("revocation_registry_id")
            crid = entry.get("cred_rev_id") or entry.get("credential_revocation_id")
            if isinstance(rrid, str) and rrid:
                try:
                    return rrid, int(crid) if crid is not None else None
                except (TypeError, ValueError):
                    return rrid, None
    return None, None


def _extract_domain_attributes(payload: dict) -> dict[str, str]:
    """Extract the credential's domain attributes from a v2_0 cred-ex payload.

    "Domain" means everything EXCEPT the kanon-reserved attribute names
    (`kanonCredId`, `kanonZkSig`, `kanonZkProof`) — the same exclusion the
    SDK applies in `encode_attributes_canonical`. The result is the
    {name: value} map the issuer signed in the CL signature; the holder,
    the verifier, and the Mode B leaf computation must all agree on the
    same set to reproduce the same Poseidon leaf.

    Returns an empty dict if no values are reachable — caller decides
    whether that's a hard error.
    """
    from did_kanon.v1_0.zk.attributes import KANON_ZK_RESERVED_ATTRIBUTE_NAMES

    reserved = set(KANON_ZK_RESERVED_ATTRIBUTE_NAMES)
    out: dict[str, str] = {}
    by_format = payload.get("by_format") or {}
    for slot in ("cred_issue", "cred_offer"):
        fmt = by_format.get(slot) or {}
        for fmt_name in ("anoncreds", "indy"):
            entry = fmt.get(fmt_name) or {}
            # Issued-credential value map: {attr: {raw, encoded}}
            values = entry.get("values") or {}
            for name, val in values.items():
                if name in reserved:
                    continue
                if isinstance(val, dict) and isinstance(val.get("raw"), str):
                    out[name] = val["raw"]
            # Fallback: credential preview attributes (on offer-side).
            if not out:
                preview = entry.get("credential_preview") or {}
                for attr in preview.get("attributes") or []:
                    name = attr.get("name")
                    value = attr.get("value")
                    if (
                        isinstance(name, str)
                        and isinstance(value, str)
                        and name not in reserved
                    ):
                        out[name] = value
            if out:
                return out
    return out


def _extract_kanon_cred_id(payload: dict) -> Optional[str]:
    """Pull the disclosed `kanonCredId` attribute value out of a v2_0
    cred-ex payload. Lives in `by_format.cred_issue.<fmt>.values.kanonCredId`
    (issuer-side after issuance) or in the credential preview attributes
    (offer-side).
    """
    by_format = payload.get("by_format") or {}
    for slot in ("cred_issue", "cred_offer"):
        fmt = by_format.get(slot) or {}
        for fmt_name in ("anoncreds", "indy"):
            entry = fmt.get(fmt_name) or {}
            # issued credential values
            values = entry.get("values") or {}
            raw = values.get(KANON_CRED_ID_ATTRIBUTE)
            if isinstance(raw, dict) and isinstance(raw.get("raw"), str):
                return raw["raw"]
            # credential offer preview attributes
            preview = entry.get("credential_preview") or {}
            for attr in (preview.get("attributes") or []):
                if attr.get("name") == KANON_CRED_ID_ATTRIBUTE and isinstance(
                    attr.get("value"), str
                ):
                    return attr["value"]
    return None


def _b32(text: str) -> bytes:
    """Mirrors the same hash used by KanonAnonCredsRegistry — see
    `did_kanon.v1_0.anoncreds.registry._b32`. The cred-def id is its
    full DID URL; the on-chain key is `keccak256(utf8(resource_id))`.
    """
    from web3 import Web3

    return Web3.keccak(text=text)
