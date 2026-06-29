from __future__ import annotations

import base64
import json
import logging
from re import Pattern
from typing import Optional, Sequence

from acapy_agent.anoncreds.base import (
    AnonCredsObjectNotFound,
    AnonCredsRegistrationError,
    AnonCredsResolutionError,
    BaseAnonCredsRegistrar,
    BaseAnonCredsResolver,
)
from acapy_agent.anoncreds.models.credential_definition import (
    CredDef,
    CredDefResult,
    CredDefState,
    GetCredDefResult,
)
from acapy_agent.anoncreds.models.revocation import (
    GetRevListResult,
    GetRevRegDefResult,
    RevList,
    RevListResult,
    RevRegDef,
    RevRegDefResult,
)
from acapy_agent.anoncreds.models.schema import (
    AnonCredsSchema,
    GetSchemaResult,
    SchemaResult,
    SchemaState,
)
from acapy_agent.anoncreds.models.schema_info import AnonCredsSchemaInfo
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.profile import Profile
from acapy_agent.storage.base import BaseStorage
from acapy_agent.storage.error import StorageNotFoundError
from acapy_agent.storage.record import StorageRecord
from web3 import Web3

from did_kanon.v1_0.contracts._base import RegistryClientError
from did_kanon.v1_0.contracts.cred_def_registry import TIER_ONE_TIME, TIER_ZK_SNARK
from did_kanon.v1_0.contracts.pool import KanonRegistryPool
from did_kanon.v1_0.identifiers import (
    KANON_PREFIX_REGEX,
    cred_def_resource_id,
    parse_kanon_did,
    schema_resource_id,
)

LOGGER = logging.getLogger(__name__)

# Local-store record type for credential-definition bodies. kanon's
# CredentialDefinitionRegistry now stores the full AnonCreds CL body inline as
# a data: URI (the source of truth on resolve, mirroring SchemaRegistry); this
# local record is kept only as an optional fast-path cache for the issuer.
_CRED_DEF_RECORD = "kanon_cred_def_body"

# Upstream ACA-Py stores the schema body locally on every successful
# ``register_schema`` (see ``acapy_agent.anoncreds.issuer.AnonCredsIssuer.
# store_schema`` — record category ``CATEGORY_SCHEMA = "schema"``). For
# every schema this agent published, the full body is already in the
# wallet — there's no reason for ``get_schema`` to hit the chain on the
# issuer side. We read from that existing store and only fall back to
# chain for schemas this agent didn't publish (the cross-agent resolver
# path), back-filling the same record so the second read is free.
_ACAPY_SCHEMA_CATEGORY = "schema"


def _b32(text: str) -> bytes:
    return Web3.keccak(text=text)


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _data_uri_from_canonical(raw: bytes) -> str:
    return "data:application/json;base64," + base64.b64encode(raw).decode("ascii")


def _decode_data_uri(uri: str) -> Optional[dict]:
    if not uri.startswith("data:"):
        return None
    try:
        meta, _, payload = uri.partition(",")
        raw = base64.b64decode(payload) if "base64" in meta else payload.encode("utf-8")
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else None
    except (ValueError, json.JSONDecodeError):
        return None


def _issuer_org_id(issuer_did: str, kind: str) -> str:
    """The bytes32 orgId (0x<64 hex>) of an org-scoped issuer DID."""
    parsed = parse_kanon_did(issuer_did)
    if parsed is None or parsed.scope != "org" or parsed.org_id is None:
        raise AnonCredsRegistrationError(
            f"did:kanon: {kind} issuer must be an org DID "
            f"(did:kanon:org:0x<64 hex>), got {issuer_did!r}"
        )
    return parsed.org_id


def _resolve_policy_mask(options: Optional[dict], network) -> int:
    """Compute the on-chain `policyMask` for a registerCredentialDefinition
    call. Priority:

      1. `options["policy_mask"]` — explicit per-cred-def setting from the
         AnonCreds caller (CLI flag, REST body, etc.)
      2. `network.default_policy_mask` — issuer-wide default for the network
         (set via plugin-config `default_policy_mask:` or env
         `KANON_DEFAULT_POLICY_MASK`)
      3. `TIER_ONE_TIME` — legacy fallback

    Accepts the mask as an int or a string token ("TIER_ALL", "ZK_SNARK", …).
    """
    accepted = {1, 2, 3}
    token_map = {
        "TIER_ONE_TIME": 1, "ONE_TIME": 1, "1": 1,
        "TIER_ZK_SNARK": 2, "ZK_SNARK": 2, "ZK": 2, "2": 2,
        "TIER_ALL": 3, "ALL": 3, "3": 3,
    }

    def _coerce(raw, source: str) -> Optional[int]:
        if raw is None:
            return None
        if isinstance(raw, bool):
            raise AnonCredsRegistrationError(
                f"did:kanon: {source} must be one of {sorted(accepted)} "
                "or one of TIER_ONE_TIME / TIER_ZK_SNARK / TIER_ALL; "
                f"got bool {raw!r}"
            )
        if isinstance(raw, int):
            if raw in accepted:
                return raw
            raise AnonCredsRegistrationError(
                f"did:kanon: {source} = {raw} is not a valid policyMask "
                f"(must be one of {sorted(accepted)})"
            )
        if isinstance(raw, str):
            token = raw.strip().upper()
            if token in token_map:
                return token_map[token]
            raise AnonCredsRegistrationError(
                f"did:kanon: {source} = {raw!r} is not a recognised "
                "policyMask token"
            )
        raise AnonCredsRegistrationError(
            f"did:kanon: {source} must be an int or token string; got {type(raw).__name__}"
        )

    if options:
        for key in ("policy_mask", "policyMask", "tier", "tiers"):
            if key in options:
                resolved = _coerce(options[key], f"options[{key!r}]")
                if resolved is not None:
                    return resolved

    if network is not None:
        net_default = getattr(network, "default_policy_mask", None)
        resolved = _coerce(net_default, f"network {getattr(network, 'name', '?')!r} default_policy_mask")
        if resolved is not None:
            return resolved

    return TIER_ONE_TIME


class KanonAnonCredsRegistry(BaseAnonCredsRegistrar, BaseAnonCredsResolver):
    """AnonCreds schemas + cred-defs over the kanon registries.

    Both schemas and cred-defs are anchored in their registries with the full
    AnonCreds body stored inline as a `data:` URI, so they resolve cross-agent.
    The chain also anchors (schemaId, issuerOrg, policy) and, for cred-defs,
    issuerPubKey = keccak(canonical body) as the integrity anchor.
    Per-credential revocation uses the AnonCredsStatusRegistry (outside this
    registrar interface).
    """

    def __init__(self, pool: KanonRegistryPool):
        super().__init__()
        self._pool = pool

    @property
    def supported_identifiers_regex(self) -> Pattern:
        return KANON_PREFIX_REGEX

    async def setup(self, context: InjectionContext) -> None:  # noqa: D401
        """No-op — pool is constructed at plugin setup time."""

    # ── Schemas ──────────────────────────────────────────────────────────

    async def register_schema(
        self,
        profile: Profile,
        schema: AnonCredsSchema,
        options: Optional[dict] = None,
    ) -> SchemaResult:
        org_id = _issuer_org_id(schema.issuer_id, "schema")
        schema_id = schema_resource_id(schema.issuer_id, schema.name, schema.version)
        body = {
            "name": schema.name,
            "version": schema.version,
            "attrNames": list(schema.attr_names),
            "issuerId": schema.issuer_id,
        }
        # schemaHash = keccak256(canonical JSON) — the convention the SDK
        # verifier (`VerifierService.validateSchemaJson`) checks against. The
        # same canonical bytes are stored inline as the data: URI.
        canonical = _canonical(body)
        uri = _data_uri_from_canonical(canonical)
        schema_hash = Web3.keccak(canonical)
        registries = self._pool.for_network()
        try:
            tx = await registries.schema.register_schema(
                org_id, _b32(schema_id), schema_hash, uri
            )
        except RegistryClientError as err:
            LOGGER.exception("did:kanon: registerSchema failed")
            raise AnonCredsRegistrationError("did:kanon: failed to register schema") from err
        # No local cache write here — ACA-Py's AnonCredsIssuer.store_schema
        # populates record category "schema" automatically after this
        # method returns, and ``get_schema`` reads from there.
        return SchemaResult(
            job_id=None,
            schema_state=SchemaState(
                state=SchemaState.STATE_FINISHED, schema_id=schema_id, schema=schema
            ),
            registration_metadata={"tx_hash": tx.tx_hash},
            schema_metadata={},
        )

    async def get_schema(self, profile: Profile, schema_id: str) -> GetSchemaResult:
        # Schemas are immutable on-chain — once published, the body never
        # changes — so the wallet's local copy is always authoritative.
        # ACA-Py's AnonCredsIssuer.store_schema writes the body under
        # record category "schema" on every successful register_schema, so
        # for any schema this agent published the cache hit is permanent.
        # We only fall back to chain (and back-fill the same record) for
        # cross-agent resolves where this wallet never saw the publish.
        body = await self._load_acapy_schema_body(profile, schema_id)
        if body is None:
            registries = self._pool.for_network()
            try:
                record = await registries.schema.get_schema(_b32(schema_id))
            except RegistryClientError as err:
                raise AnonCredsResolutionError(
                    f"did:kanon: transport failure reading schema {schema_id}"
                ) from err
            if not record:
                raise AnonCredsObjectNotFound(
                    f"did:kanon: schema not found: {schema_id}", {"schema_id": schema_id}
                )
            body = _decode_data_uri(record.get("uri", ""))
            if not body:
                raise AnonCredsResolutionError(
                    f"did:kanon: schema {schema_id} has no inline body (uri not a data: URI)"
                )
            # Back-fill the ACA-Py record so the next reader skips the chain.
            try:
                await self._store_acapy_schema_body(profile, schema_id, body)
            except Exception as err:  # pragma: no cover
                LOGGER.warning(
                    "did:kanon: schema record back-fill failed for %s: %s",
                    schema_id,
                    err,
                )
        try:
            schema = AnonCredsSchema(
                issuer_id=body["issuerId"],
                attr_names=list(body["attrNames"]),
                name=body["name"],
                version=str(body["version"]),
            )
        except (KeyError, TypeError) as err:
            raise AnonCredsResolutionError(
                f"did:kanon: malformed schema body for {schema_id}: missing/invalid {err}"
            ) from err
        return GetSchemaResult(
            schema=schema, schema_id=schema_id, resolution_metadata={}, schema_metadata={}
        )

    async def get_schema_info_by_id(
        self, profile: Profile, schema_id: str
    ) -> AnonCredsSchemaInfo:
        result = await self.get_schema(profile, schema_id)
        return AnonCredsSchemaInfo(
            issuer_id=result.schema.issuer_id,
            name=result.schema.name,
            version=result.schema.version,
        )

    # ── Credential definitions ───────────────────────────────────────────

    async def register_credential_definition(
        self,
        profile: Profile,
        schema: GetSchemaResult,
        credential_definition: CredDef,
        options: Optional[dict] = None,
    ) -> CredDefResult:
        issuer_id = credential_definition.issuer_id
        _issuer_org_id(issuer_id, "cred-def")  # validate org-scoped issuer DID
        cred_def_id = cred_def_resource_id(
            issuer_id, schema.schema.name, credential_definition.tag
        )
        body = credential_definition.serialize()
        # Store the full CL body inline as a data: URI (source of truth on
        # resolve, mirroring SchemaRegistry). issuerPubKey = keccak(canonical
        # body) stays the integrity anchor binding the entry to the body.
        canonical = _canonical(body)
        uri = _data_uri_from_canonical(canonical)
        issuer_pub_key = Web3.keccak(canonical)

        # Pick the policyMask in priority order:
        #   1. explicit `options["policy_mask"]` from the AnonCreds caller
        #   2. `default_policy_mask` on the chosen network
        #   3. TIER_ONE_TIME (Mode A only) — legacy fallback
        policy_mask = _resolve_policy_mask(options, self._pool.network_config())

        await self._store_cred_def_body(profile, cred_def_id, body)
        registries = self._pool.for_network()

        # Mode B credDefs (`policy_mask & TIER_ZK_SNARK`) require a
        # BabyJubjub-EdDSA issuer key on-chain — the verifier of
        # `non_revocation.circom` binds publicSignals[3..4] to (ax, ay).
        # Provision the key BEFORE the register tx so failure happens
        # before any chain state is touched. Mode A registrations pass
        # (0, 0) — the contract rejects non-zero values for Mode A with
        # `UnexpectedIssuerZkPubKey`.
        issuer_zk_ax = 0
        issuer_zk_ay = 0
        if policy_mask & TIER_ZK_SNARK:
            from did_kanon.v1_0.zk.zk_issuer_key import KanonZkIssuerKeyService

            zk_key_service = KanonZkIssuerKeyService(profile)
            issuer_zk_ax, issuer_zk_ay = await zk_key_service.provision_public_key(
                _b32(cred_def_id)
            )

        try:
            tx = await registries.cred_def.register_credential_definition(
                _b32(cred_def_id),
                _b32(credential_definition.schema_id),
                issuer_pub_key,
                policy_mask,
                uri,
                issuer_zk_ax,
                issuer_zk_ay,
            )
        except RegistryClientError as err:
            LOGGER.exception("did:kanon: registerCredentialDefinition failed")
            raise AnonCredsRegistrationError("did:kanon: failed to register cred-def") from err
        LOGGER.info(
            "did:kanon: registered credDef %s with policyMask=%d (tx %s)",
            cred_def_id, policy_mask, tx,
        )
        return CredDefResult(
            job_id=None,
            credential_definition_state=CredDefState(
                state=CredDefState.STATE_FINISHED,
                credential_definition_id=cred_def_id,
                credential_definition=credential_definition,
            ),
            registration_metadata={"tx_hash": tx.tx_hash},
            credential_definition_metadata={},
        )

    async def get_credential_definition(
        self, profile: Profile, credential_definition_id: str
    ) -> GetCredDefResult:
        # The full CL body is stored inline on-chain as a data: URI (source of
        # truth, mirroring schemas), so cross-agent resolution works. The local
        # store is kept only as an optional fast-path cache.
        body = await self._load_cred_def_body(profile, credential_definition_id)
        if body is None:
            registries = self._pool.for_network()
            try:
                record = await registries.cred_def.get_credential_definition(
                    _b32(credential_definition_id)
                )
            except RegistryClientError as err:
                raise AnonCredsResolutionError(
                    "did:kanon: transport failure reading cred-def "
                    f"{credential_definition_id}"
                ) from err
            if not record:
                raise AnonCredsObjectNotFound(
                    f"did:kanon: cred-def not found: {credential_definition_id}",
                    {"credential_definition_id": credential_definition_id},
                )
            body = _decode_data_uri(record.get("uri", ""))
            if not body:
                raise AnonCredsResolutionError(
                    f"did:kanon: cred-def {credential_definition_id} has no inline "
                    "body (uri not a data: URI)"
                )
        cred_def = CredDef.deserialize(body)

        # Strip the CL revocation key from the returned CredDef.
        #
        # ACA-Py's `AnonCredsIssuer.cred_def_supports_revocation` (which
        # `AnonCredsRevocation._create_credential_helper` consults to
        # decide whether to allocate `cred_rev_id` + look up a rev-reg-def
        # + read a tails file) only returns True when
        # `cred_def.value.revocation is not None`. did:kanon credentials
        # use on-chain revocation (status_registry / MerkleStateRegistry)
        # rather than the CL accumulator math, so the CL revocation key
        # is unused. Returning it would force ACA-Py to allocate
        # cred_rev_id from a rev-reg whose tails file we deliberately
        # never wrote — issuance would fail with "revocation registry or
        # list is in a bad state". Stripping it makes ACA-Py treat the
        # credef as non-revocable for its standard issuance path; our
        # `KanonAwareRevocationSetup` ALSO suppresses the
        # `CredDefFinishedEvent` rev-reg cascade so no tails file is
        # ever written anywhere.
        #
        # The credef's CHAIN-side revocation behavior is unchanged: the
        # on-chain `policyMask` decides Mode A vs Mode B vs ALL and
        # `/did/kanon/revoke/{cred_def_id}` (or the standard
        # `/anoncreds/revocation/revoke` once it's routed through the
        # synthesised rev-reg meta) writes to chain.
        if cred_def.value is not None and getattr(cred_def.value, "revocation", None) is not None:
            cred_def.value.revocation = None
        return GetCredDefResult(
            credential_definition=cred_def,
            credential_definition_id=credential_definition_id,
            resolution_metadata={
                "kanon": {
                    "cl_revocation_stripped": True,
                    "revocation_via": "policy_mask + /did/kanon/revoke",
                }
            },
            credential_definition_metadata={},
        )

    async def _store_cred_def_body(
        self, profile: Profile, cred_def_id: str, body: dict
    ) -> None:
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            record = StorageRecord(
                _CRED_DEF_RECORD,
                json.dumps(body),
                {"cred_def_id": cred_def_id},
                cred_def_id,
            )
            try:
                await storage.add_record(record)
            except Exception:
                # Already stored (idempotent re-register) — overwrite the value.
                await storage.update_record(record, record.value, record.tags)

    async def _load_cred_def_body(
        self, profile: Profile, cred_def_id: str
    ) -> Optional[dict]:
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            try:
                record = await storage.get_record(_CRED_DEF_RECORD, cred_def_id)
            except StorageNotFoundError:
                return None
        try:
            return json.loads(record.value)
        except json.JSONDecodeError:
            return None

    async def _load_acapy_schema_body(
        self, profile: Profile, schema_id: str
    ) -> Optional[dict]:
        """Read the schema body from ACA-Py's own ``"schema"`` record.

        Upstream stores the same body JSON our resolver needs —
        ``{"issuerId": ..., "attrNames": [...], "name": ..., "version": ...}``
        — so we just deserialize and hand it back. Missing record means
        this wallet never published or back-filled this schema; the caller
        falls back to chain.
        """
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            try:
                record = await storage.get_record(_ACAPY_SCHEMA_CATEGORY, schema_id)
            except StorageNotFoundError:
                return None
        try:
            return json.loads(record.value)
        except json.JSONDecodeError:
            return None

    async def _store_acapy_schema_body(
        self, profile: Profile, schema_id: str, body: dict
    ) -> None:
        """Back-fill ACA-Py's ``"schema"`` record after a chain resolve.

        Mirrors the tag set produced by
        ``AnonCredsIssuer.store_schema`` so list/search by
        ``name``/``version``/``issuer_id`` still works on back-filled
        records. Idempotent — duplicate insert flips to update.
        """
        tags = {
            "name": body.get("name", ""),
            "version": str(body.get("version", "")),
            "issuer_id": body.get("issuerId", ""),
            "state": "finished",
        }
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            record = StorageRecord(
                _ACAPY_SCHEMA_CATEGORY,
                json.dumps(body),
                tags,
                schema_id,
            )
            try:
                await storage.add_record(record)
            except Exception:
                await storage.update_record(record, record.value, record.tags)

    # ── Revocation ──────────────────────────────────────────────────────
    #
    # `/anoncreds/revocation/revoke` flows through ACA-Py's standard
    # rev-reg + rev-list machinery and ultimately lands on the four
    # methods below. We don't anchor a separate revocation registry on
    # chain — kanon revocation lives on the credDef's existing on-chain
    # state (AnonCredsStatusRegistry leaf for Mode A, MerkleStateRegistry
    # leaf for Mode B). What we DO is:
    #
    #   1. Accept the rev_reg_def ACA-Py builds (via anoncreds-rs) and
    #      persist a binding from rev_reg_id → cred_def_id + policy_mask
    #      in BaseStorage. The credDef's policy_mask was set at
    #      registration; we read it here and stash it so the revoke flow
    #      doesn't have to do another chain round-trip.
    #
    #   2. `register_revocation_list` is the initial empty state ACA-Py
    #      ships post-registration. Persist alongside the meta so future
    #      `get_revocation_list` calls are deterministic.
    #
    #   3. `update_revocation_list` is the actual revoke hook. ACA-Py
    #      hands us `revoked: list[cred_rev_id]` — we translate each
    #      index to the kanonCredId via the issuance-listener's index map
    #      and call the same `KanonZkIssuer.revoke` / `status.revoke`
    #      flows the `/did/kanon/revoke/{cred_def_id}` route uses. The
    #      two routes therefore converge on the same on-chain effect.
    #
    #   4. Look-ups reconstruct the rev_reg_def / rev_list from local
    #      state — no chain reads. The current accumulator is just the
    #      one anoncreds-rs computed at create/update time and we passed
    #      through unchanged.

    async def get_revocation_registry_definition(
        self, profile: Profile, revocation_registry_id: str
    ) -> GetRevRegDefResult:
        from did_kanon.v1_0.anoncreds.revreg_state import load_revreg_meta

        meta = await load_revreg_meta(profile, revocation_registry_id)
        if meta is None:
            raise AnonCredsObjectNotFound(
                f"did:kanon: revocation registry {revocation_registry_id} not found"
            )
        rev_reg_def = RevRegDef.deserialize(json.loads(meta["rev_reg_def"]))
        return GetRevRegDefResult(
            revocation_registry=rev_reg_def,
            revocation_registry_id=revocation_registry_id,
            resolution_metadata={},
            revocation_registry_metadata={
                "policy_mask": meta["policy_mask"],
            },
        )

    async def register_revocation_registry_definition(
        self,
        profile: Profile,
        revocation_registry_definition: RevRegDef,
        options: Optional[dict] = None,
    ) -> RevRegDefResult:
        from did_kanon.v1_0.anoncreds.revreg_state import save_revreg_meta
        from acapy_agent.anoncreds.models.revocation import (
            RevRegDefState,
        )

        rev_reg_def = revocation_registry_definition
        cred_def_id = rev_reg_def.cred_def_id
        rev_reg_id = (
            f"{cred_def_id}/revoc/{rev_reg_def.tag}"
            if not getattr(rev_reg_def, "rev_reg_def_id", None)
            else rev_reg_def.rev_reg_def_id
        )

        # Read the credDef's policy_mask from chain so the revoke flow
        # later knows which tier(s) to dispatch to.
        cd_bytes = _b32(cred_def_id)
        try:
            registries = self._pool.for_network()
            cd_record = await registries.cred_def.get_credential_definition(cd_bytes)
        except RegistryClientError as err:
            raise AnonCredsRegistrationError(
                f"did:kanon: failed to read credDef policy_mask for {cred_def_id}: {err}"
            ) from err
        if cd_record is None:
            raise AnonCredsRegistrationError(
                f"did:kanon: credDef {cred_def_id} not found on chain"
            )
        policy_mask = int(cd_record["policy_mask"])

        await save_revreg_meta(
            profile,
            rev_reg_id=rev_reg_id,
            cred_def_id=cred_def_id,
            policy_mask=policy_mask,
            max_cred_num=int(rev_reg_def.value.max_cred_num),
            rev_reg_def_json=json.dumps(rev_reg_def.serialize()),
        )
        LOGGER.info(
            "did:kanon: bound rev_reg_id=%s → credDef=%s (policy_mask=%d)",
            rev_reg_id, cred_def_id, policy_mask,
        )

        return RevRegDefResult(
            job_id=None,
            revocation_registry_definition_state=RevRegDefState(
                state=RevRegDefState.STATE_FINISHED,
                revocation_registry_definition_id=rev_reg_id,
                revocation_registry_definition=rev_reg_def,
            ),
            registration_metadata={},
            revocation_registry_definition_metadata={
                "policy_mask": policy_mask,
            },
        )

    async def get_revocation_list(
        self,
        profile: Profile,
        revocation_registry_id: str,
        timestamp_from: Optional[int] = 0,
        timestamp_to: Optional[int] = None,
    ) -> GetRevListResult:
        from did_kanon.v1_0.anoncreds.revreg_state import load_revreg_meta

        meta = await load_revreg_meta(profile, revocation_registry_id)
        if meta is None:
            raise AnonCredsObjectNotFound(
                f"did:kanon: revocation registry {revocation_registry_id} not found"
            )
        if not meta.get("initial_rev_list"):
            raise AnonCredsObjectNotFound(
                f"did:kanon: no rev-list registered yet for {revocation_registry_id}"
            )
        rev_list = RevList.deserialize(json.loads(meta["initial_rev_list"]))
        return GetRevListResult(
            revocation_list=rev_list,
            resolution_metadata={},
            revocation_registry_metadata={
                "policy_mask": meta["policy_mask"],
            },
        )

    async def register_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        rev_list: RevList,
        options: Optional[dict] = None,
    ) -> RevListResult:
        from did_kanon.v1_0.anoncreds.revreg_state import (
            load_revreg_meta,
            save_revreg_meta,
        )
        from acapy_agent.anoncreds.models.revocation import RevListState

        rev_reg_id = rev_list.rev_reg_def_id
        meta = await load_revreg_meta(profile, rev_reg_id)
        if meta is None:
            # Fall back to a synthesised meta from the rev_reg_def in case
            # register_revocation_registry_definition was bypassed in some
            # exotic flow. policy_mask is read live in this case.
            cd_bytes = _b32(rev_reg_def.cred_def_id)
            cd_record = await self._pool.for_network().cred_def.get_credential_definition(cd_bytes)
            policy_mask = int(cd_record["policy_mask"]) if cd_record else TIER_ONE_TIME
        else:
            policy_mask = int(meta["policy_mask"])

        await save_revreg_meta(
            profile,
            rev_reg_id=rev_reg_id,
            cred_def_id=rev_reg_def.cred_def_id,
            policy_mask=policy_mask,
            max_cred_num=int(rev_reg_def.value.max_cred_num),
            rev_reg_def_json=json.dumps(rev_reg_def.serialize()),
            initial_rev_list_json=json.dumps(rev_list.serialize()),
        )
        LOGGER.info(
            "did:kanon: registered initial rev-list for rev_reg_id=%s "
            "(%d slots, policy_mask=%d)",
            rev_reg_id, len(rev_list.revocation_list or []), policy_mask,
        )

        return RevListResult(
            job_id=None,
            revocation_list_state=RevListState(
                state=RevListState.STATE_FINISHED,
                revocation_list=rev_list,
            ),
            registration_metadata={},
            revocation_list_metadata={"policy_mask": policy_mask},
        )

    async def update_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        prev_list: RevList,
        curr_list: RevList,
        revoked: Sequence[int],
        options: Optional[dict] = None,
    ) -> RevListResult:
        """Translate ACA-Py's revoke list to kanonCredIds and dispatch.

        The credDef's on-chain `policy_mask` drives the per-tier
        publication: Mode A → AnonCredsStatusRegistry.revoke, Mode B
        → MerkleStateRegistry leaf removal, TIER_ALL → both. We reuse
        the existing /did/kanon/revoke dispatcher logic for parity —
        both routes (`/anoncreds/revocation/revoke` and the kanon
        admin route) converge on the same on-chain writes.
        """
        from did_kanon.v1_0.anoncreds.revreg_state import (
            load_revreg_meta,
            lookup_cred_id,
            save_revreg_meta,
        )
        from acapy_agent.anoncreds.models.revocation import RevListState

        rev_reg_id = rev_reg_def.rev_reg_def_id if getattr(
            rev_reg_def, "rev_reg_def_id", None
        ) else f"{rev_reg_def.cred_def_id}/revoc/{rev_reg_def.tag}"

        meta = await load_revreg_meta(profile, rev_reg_id)
        if meta is None:
            raise AnonCredsRegistrationError(
                f"did:kanon: no revreg meta for {rev_reg_id} — "
                f"register_revocation_registry_definition must run first"
            )
        cred_def_id = meta["cred_def_id"]
        policy_mask = int(meta["policy_mask"])

        if not revoked:
            # Nothing to revoke — just persist the updated curr_list.
            await save_revreg_meta(
                profile,
                rev_reg_id=rev_reg_id,
                cred_def_id=cred_def_id,
                policy_mask=policy_mask,
                max_cred_num=int(meta["max_cred_num"]),
                rev_reg_def_json=meta["rev_reg_def"],
                initial_rev_list_json=json.dumps(curr_list.serialize()),
            )
            return RevListResult(
                job_id=None,
                revocation_list_state=RevListState(
                    state=RevListState.STATE_FINISHED,
                    revocation_list=curr_list,
                ),
                registration_metadata={},
                revocation_list_metadata={"policy_mask": policy_mask},
            )

        # Translate cred_rev_id → kanonCredId via the issuance-listener
        # map. Misses are fatal: the wallet would otherwise believe a
        # revoke succeeded while no on-chain write happened.
        cred_ids: list[str] = []
        missing: list[int] = []
        for crid in revoked:
            kanon_cred_id = await lookup_cred_id(profile, rev_reg_id, int(crid))
            if kanon_cred_id is None:
                missing.append(int(crid))
            else:
                cred_ids.append(kanon_cred_id)
        if missing:
            raise AnonCredsRegistrationError(
                f"did:kanon: cannot map cred_rev_id(s) {missing} on rev_reg "
                f"{rev_reg_id} — the issuance listener must record the "
                f"(rev_reg_id, cred_rev_id) → kanonCredId binding before revoke"
            )

        cd_bytes = _b32(cred_def_id)
        registries = self._pool.for_network()

        # Mode A — AnonCredsStatusRegistry per-credential revoke.
        if policy_mask & TIER_ONE_TIME:
            for cid in cred_ids:
                cred_id_hash = Web3.keccak(text=cid)
                try:
                    await registries.status.revoke_credential(cd_bytes, cred_id_hash)
                except Exception as err:  # noqa: BLE001
                    LOGGER.error(
                        "did:kanon: Mode A revoke failed for %s: %s", cid, err
                    )
                    raise AnonCredsRegistrationError(
                        f"did:kanon: Mode A revoke failed for {cid}: {err}"
                    ) from err
            LOGGER.info(
                "did:kanon: Mode A revoked %d credential(s) on credDef %s",
                len(cred_ids), cred_def_id,
            )

        # Mode B — MerkleStateRegistry leaf removal + root rotation.
        if policy_mask & TIER_ZK_SNARK:
            from did_kanon.v1_0.zk.zk_issuer import KanonZkIssuer

            issuer = KanonZkIssuer(registries.merkle, profile)
            try:
                await issuer.revoke(cred_def_id, cred_ids)
            except Exception as err:  # noqa: BLE001
                LOGGER.error(
                    "did:kanon: Mode B revoke failed on credDef %s: %s",
                    cred_def_id, err,
                )
                raise AnonCredsRegistrationError(
                    f"did:kanon: Mode B revoke failed: {err}"
                ) from err
            LOGGER.info(
                "did:kanon: Mode B revoked %d credential(s) on credDef %s",
                len(cred_ids), cred_def_id,
            )

        # Persist the latest curr_list — `get_revocation_list` returns it
        # so verifier queries see the post-revoke state.
        await save_revreg_meta(
            profile,
            rev_reg_id=rev_reg_id,
            cred_def_id=cred_def_id,
            policy_mask=policy_mask,
            max_cred_num=int(meta["max_cred_num"]),
            rev_reg_def_json=meta["rev_reg_def"],
            initial_rev_list_json=json.dumps(curr_list.serialize()),
        )

        return RevListResult(
            job_id=None,
            revocation_list_state=RevListState(
                state=RevListState.STATE_FINISHED,
                revocation_list=curr_list,
            ),
            registration_metadata={},
            revocation_list_metadata={
                "policy_mask": policy_mask,
                "revoked_count": len(cred_ids),
            },
        )
