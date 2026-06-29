"""Per-rev-reg local state for the did:kanon plugin.

Standard AnonCreds revocation is keyed by `rev_reg_id` + `cred_rev_id`
(an integer index in `[0, max_cred_num)`). Kanon revocation is keyed by
`cred_def_id` + `credId` (the bookkeeping kanonCredId attribute on the
credential). To bridge ACA-Py's `/anoncreds/revocation/revoke` flow
through to the chain, we maintain two BaseStorage record types:

  ``kanon/revreg/meta``        — one per rev_reg_id, carries the
                                 cred_def_id binding, the policy_mask
                                 active when the rev-reg was registered,
                                 and the rev_reg_def serialized so
                                 `get_revocation_registry_definition`
                                 can return it without re-deriving.

  ``kanon/revreg/index``       — one per (rev_reg_id, cred_rev_id), maps
                                 to the issued kanonCredId. Written by
                                 the issuance listener at issue time;
                                 read by `update_revocation_list` to
                                 translate ACA-Py's `revoked: list[int]`
                                 into the kanonCredIds the existing
                                 `/did/kanon/revoke` flow already takes.

Both record types are profile-scoped (per-tenant wallet), encrypted at
rest by the askar storage backend.
"""

from __future__ import annotations

import json
import logging
from typing import Optional


LOGGER = logging.getLogger(__name__)

REVREG_META_RECORD_TYPE: str = "kanon/revreg/meta"
REVREG_INDEX_RECORD_TYPE: str = "kanon/revreg/index"
# `cred_ex_id → kanon_cred_id` map. Written by the issuance listener so
# callers can revoke by the ACA-Py-assigned `cred_ex_id` (visible in the
# admin API and in webhooks) without ever knowing the auto-generated
# kanonCredId. Powers the schema-clean Mode A path: schemas don't carry
# `kanonCredId` as an attribute, the plugin generates one on issuance,
# and the revoke route resolves the binding here.
CRED_EX_CRED_ID_RECORD_TYPE: str = "kanon/credex/credid"


def _meta_id(rev_reg_id: str) -> str:
    return f"kanon-revreg-meta:{rev_reg_id}"


def _index_id(rev_reg_id: str, cred_rev_id: int) -> str:
    return f"kanon-revreg-index:{rev_reg_id}:{int(cred_rev_id)}"


# ─── Rev-reg metadata ────────────────────────────────────────────────────


async def save_revreg_meta(
    profile,
    *,
    rev_reg_id: str,
    cred_def_id: str,
    policy_mask: int,
    max_cred_num: int,
    rev_reg_def_json: str,
    initial_rev_list_json: Optional[str] = None,
) -> None:
    """Persist (or update) the rev-reg metadata for a credDef."""
    from acapy_agent.storage.base import BaseStorage
    from acapy_agent.storage.record import StorageRecord

    payload = json.dumps(
        {
            "rev_reg_id": rev_reg_id,
            "cred_def_id": cred_def_id,
            "policy_mask": int(policy_mask),
            "max_cred_num": int(max_cred_num),
            "rev_reg_def": rev_reg_def_json,
            "initial_rev_list": initial_rev_list_json,
        }
    )
    record_id = _meta_id(rev_reg_id)

    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        try:
            existing = await storage.get_record(REVREG_META_RECORD_TYPE, record_id)
        except Exception:  # noqa: BLE001
            existing = None
        if existing is not None:
            await storage.update_record(existing, payload, existing.tags)
        else:
            await storage.add_record(
                StorageRecord(
                    type=REVREG_META_RECORD_TYPE,
                    value=payload,
                    tags={
                        "credDefId": cred_def_id,
                        "revRegId": rev_reg_id,
                    },
                    id=record_id,
                )
            )


async def load_revreg_meta(profile, rev_reg_id: str) -> Optional[dict]:
    """Return the persisted meta dict for `rev_reg_id`, or `None`."""
    from acapy_agent.storage.base import BaseStorage

    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        try:
            rec = await storage.get_record(REVREG_META_RECORD_TYPE, _meta_id(rev_reg_id))
        except Exception:  # noqa: BLE001
            return None
        if rec is None or not rec.value:
            return None
        try:
            return json.loads(rec.value)
        except json.JSONDecodeError:
            LOGGER.warning(
                "did:kanon: corrupt revreg meta record %s — ignoring", rev_reg_id
            )
            return None


# ─── Index → kanonCredId map ─────────────────────────────────────────────


async def remember_cred_index(
    profile,
    *,
    rev_reg_id: str,
    cred_rev_id: int,
    kanon_cred_id: str,
) -> None:
    """Record the (rev_reg_id, cred_rev_id) → kanonCredId binding.

    Written by the issuance listener immediately after a successful
    issue; consumed by `update_revocation_list` at revoke time.
    """
    from acapy_agent.storage.base import BaseStorage
    from acapy_agent.storage.record import StorageRecord

    record_id = _index_id(rev_reg_id, cred_rev_id)
    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        try:
            existing = await storage.get_record(REVREG_INDEX_RECORD_TYPE, record_id)
        except Exception:  # noqa: BLE001
            existing = None
        if existing is not None:
            await storage.update_record(existing, kanon_cred_id, existing.tags)
        else:
            await storage.add_record(
                StorageRecord(
                    type=REVREG_INDEX_RECORD_TYPE,
                    value=kanon_cred_id,
                    tags={"revRegId": rev_reg_id, "credRevId": str(int(cred_rev_id))},
                    id=record_id,
                )
            )


async def lookup_cred_id(
    profile, rev_reg_id: str, cred_rev_id: int
) -> Optional[str]:
    """Return the kanonCredId for a (rev_reg_id, cred_rev_id), or `None`."""
    from acapy_agent.storage.base import BaseStorage

    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        try:
            rec = await storage.get_record(
                REVREG_INDEX_RECORD_TYPE, _index_id(rev_reg_id, cred_rev_id)
            )
        except Exception:  # noqa: BLE001
            return None
        if rec is None or not rec.value:
            return None
        return rec.value


# ─── cred_ex_id → kanon_cred_id map ──────────────────────────────────────


def _credex_id(cred_ex_id: str) -> str:
    return f"kanon-credex-credid:{cred_ex_id}"


async def remember_credex_cred_id(
    profile, *, cred_ex_id: str, kanon_cred_id: str, cred_def_id: str
) -> None:
    """Record the `cred_ex_id → kanon_cred_id` binding.

    Used by Mode A where the kanonCredId is auto-generated by the plugin
    at issuance (the schema does NOT include a `kanonCredId` attribute).
    Callers revoke by the visible `cred_ex_id` and the route resolves
    here to the on-chain cred_id.
    """
    from acapy_agent.storage.base import BaseStorage
    from acapy_agent.storage.record import StorageRecord

    record_id = _credex_id(cred_ex_id)
    payload = json.dumps({"kanon_cred_id": kanon_cred_id, "cred_def_id": cred_def_id})
    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        try:
            existing = await storage.get_record(CRED_EX_CRED_ID_RECORD_TYPE, record_id)
        except Exception:  # noqa: BLE001
            existing = None
        if existing is not None:
            await storage.update_record(existing, payload, existing.tags)
        else:
            await storage.add_record(
                StorageRecord(
                    type=CRED_EX_CRED_ID_RECORD_TYPE,
                    value=payload,
                    tags={"credExId": cred_ex_id, "credDefId": cred_def_id},
                    id=record_id,
                )
            )


async def lookup_cred_id_by_credex(
    profile, cred_ex_id: str
) -> Optional[dict]:
    """Return `{kanon_cred_id, cred_def_id}` for a cred_ex_id, or `None`."""
    from acapy_agent.storage.base import BaseStorage

    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        try:
            rec = await storage.get_record(
                CRED_EX_CRED_ID_RECORD_TYPE, _credex_id(cred_ex_id)
            )
        except Exception:  # noqa: BLE001
            return None
        if rec is None or not rec.value:
            return None
        try:
            return json.loads(rec.value)
        except json.JSONDecodeError:
            return None


__all__ = [
    "REVREG_META_RECORD_TYPE",
    "REVREG_INDEX_RECORD_TYPE",
    "CRED_EX_CRED_ID_RECORD_TYPE",
    "save_revreg_meta",
    "load_revreg_meta",
    "remember_cred_index",
    "lookup_cred_id",
    "remember_credex_cred_id",
    "lookup_cred_id_by_credex",
]
