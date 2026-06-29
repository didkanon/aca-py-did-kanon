"""KanonZkIssuerKeyService — BabyJubjub issuer-key lifecycle (off-chain).

Mode B credDefs publish a BabyJubjub-EdDSA public key on chain via
`CredentialDefinitionRegistry.registerCredentialDefinition(..., ax, ay)`.
Registration and key publication happen atomically in one transaction, so
this service does NOT touch the chain itself — it just generates +
persists the keypair so:

  1. The credDef registrar can read `(ax, ay)` to pass through to the
     `registerCredentialDefinition` call.
  2. The issuance side can later read the private key to sign the
     credential leaf (`sign_poseidon`).

Persistence: ACA-Py `BaseStorage`, one record per credDef, keyed by
`kanon-zk-issuer-key:<lowercased credDefId>`. The wallet encrypts records
at rest, so the on-disk form is safe.

Hardening choices mirroring the credo-ts plugin:

  - Only the public coords `(Ax, Ay)` are cached in-process. Public coords
    are safe to keep — they're literally published on chain. The PRIVATE
    key is loaded from the wallet on every signing operation and the
    Python reference dropped immediately after.

  - `with_private_key(fn)` lets callers compute with the privkey in a
    tight scope. Python doesn't guarantee zeroing (strings are immutable,
    GC may have copied) but removing the strong reference still cuts the
    window for a heap-dump attacker.

  - `provision` is serialised per credDef via a single-flight asyncio
    lock. Two concurrent calls for the same credDef can't both generate
    fresh keys and race on the BaseStorage write — the second caller
    awaits the first's result.

Rotation is unsupported by design — rotating would silently break every
previously-issued Mode B proof.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Awaitable, Callable, Dict, Optional, Tuple, TypeVar

from did_kanon.v1_0.zk import eddsa


LOGGER = logging.getLogger(__name__)

#: Storage namespace for persisted issuer keys. Distinct from
#: `kanon/zk/sync-checkpoint` (the per-credDef leaf-set checkpoint).
ISSUER_KEY_RECORD_TYPE: str = "kanon/zk/issuer-key"

T = TypeVar("T")

# ─── Helpers ─────────────────────────────────────────────────────────────


def _normalize_cred_def_id(cred_def_id: bytes | str) -> str:
    """Canonicalise to a lowercase `0x<64-hex>` string for keying."""
    if isinstance(cred_def_id, bytes):
        if len(cred_def_id) != 32:
            raise ValueError("cred_def_id bytes must be 32")
        return "0x" + cred_def_id.hex()
    if not isinstance(cred_def_id, str):
        raise TypeError(
            f"cred_def_id must be bytes or str, got {type(cred_def_id).__name__}"
        )
    s = cred_def_id.lower()
    if not s.startswith("0x"):
        s = "0x" + s
    if len(s) != 66:  # '0x' + 64
        raise ValueError(f"cred_def_id must be 32 bytes hex; got {s!r}")
    int(s, 16)  # validate hex
    return s


def _record_id(cred_def_id_norm: str) -> str:
    return f"kanon-zk-issuer-key:{cred_def_id_norm}"


# ─── Service ─────────────────────────────────────────────────────────────


class KanonZkIssuerKeyService:
    """Per-credDef BJJ issuer-key lifecycle on top of ACA-Py BaseStorage.

    Constructed with the ACA-Py `profile` because BaseStorage is
    profile-scoped (each tenant has its own encrypted wallet).
    """

    # In-process locks shared across instances FOR THE SAME EVENT LOOP.
    # ACA-Py is single-process, single-loop, so a module-level dict is the
    # natural place — the locks are bound by credDefId, not by service
    # instance lifetime.
    _provision_locks: Dict[str, asyncio.Lock] = {}

    def __init__(self, profile) -> None:
        self._profile = profile
        # PUBLIC-key-only in-memory cache. Cleared by `invalidate`.
        self._public_cache: Dict[str, Tuple[int, int]] = {}

    # ── Provision (idempotent, single-flight) ──────────────────────────

    async def provision_public_key(
        self, cred_def_id: bytes | str
    ) -> Tuple[int, int]:
        """Get-or-create the BJJ keypair for `cred_def_id`; return `(ax, ay)`.

        Concurrent calls for the same credDef serialise on the asyncio
        lock — only one fresh key is generated.
        """
        norm = _normalize_cred_def_id(cred_def_id)

        cached = self._public_cache.get(norm)
        if cached is not None:
            return cached

        lock = self._provision_locks.setdefault(norm, asyncio.Lock())
        async with lock:
            # Double-check inside the lock — another waiter may have just
            # populated the cache.
            cached = self._public_cache.get(norm)
            if cached is not None:
                return cached

            existing = await self._load_record(norm)
            if existing is not None:
                ax, ay = existing
                self._public_cache[norm] = (ax, ay)
                return (ax, ay)

            # Generate + persist a fresh keypair.
            key = eddsa.generate_issuer_key()
            await self._save_record(norm, key)
            self._public_cache[norm] = (key.Ax, key.Ay)
            LOGGER.info(
                "kanon-zk: provisioned issuer key for credDef %s (ax=%s…)",
                norm,
                hex(key.Ax)[:18],
            )
            return (key.Ax, key.Ay)

    # ── Load existing public key (no privkey touch) ────────────────────

    async def load_public_key(
        self, cred_def_id: bytes | str
    ) -> Optional[Tuple[int, int]]:
        """Return the on-disk `(ax, ay)` for `cred_def_id`, or `None`.

        Does NOT touch the private key — convenient on the verifier-side
        sanity-check path. Use `provision_public_key` if you want
        get-or-create semantics.
        """
        norm = _normalize_cred_def_id(cred_def_id)
        cached = self._public_cache.get(norm)
        if cached is not None:
            return cached
        existing = await self._load_record(norm)
        if existing is None:
            return None
        self._public_cache[norm] = existing
        return existing

    # ── Scoped private-key access ──────────────────────────────────────

    async def with_private_key(
        self,
        cred_def_id: bytes | str,
        fn: Callable[[eddsa.KanonZkIssuerKey], Awaitable[T]],
    ) -> T:
        """Invoke `fn` with the issuer's BJJ key for `cred_def_id`.

        The private key is loaded from the wallet, passed to `fn`, and the
        local reference dropped on return. Callers MUST do their signing
        inside `fn` — don't stash the privkey hex elsewhere.
        """
        norm = _normalize_cred_def_id(cred_def_id)
        priv_hex = await self._load_record_private(norm)
        if priv_hex is None:
            raise KanonZkIssuerKeyError(
                f"no issuer key persisted for credDef {norm} — "
                f"call provision_public_key during credDef registration"
            )
        key = eddsa.restore_issuer_key(priv_hex)
        try:
            return await fn(key)
        finally:
            # Best-effort scrub. Python strings are immutable so we can't
            # overwrite the buffer, but drop the named reference so the
            # privkey hex becomes GC-collectible after `fn` returns.
            del priv_hex  # noqa: F841
            del key

    # ── Cache management ───────────────────────────────────────────────

    def invalidate(self, cred_def_id: bytes | str) -> None:
        """Drop the in-process public-key cache entry for `cred_def_id`."""
        norm = _normalize_cred_def_id(cred_def_id)
        self._public_cache.pop(norm, None)
        # The provisioning lock outlives a single call but is bound to
        # the credDef, not the service instance. Prune it here so a
        # long-running agent that churns through many credDefs doesn't
        # accumulate unbounded asyncio.Lock objects in the class dict.
        # Safe because `invalidate` is only called after a credDef is
        # rotated/replaced; in-flight callers either already hold the
        # lock or will re-create it on next `provision_public_key`.
        self._provision_locks.pop(norm, None)

    # ── Storage internals ──────────────────────────────────────────────

    async def _load_record(
        self, cred_def_id_norm: str
    ) -> Optional[Tuple[int, int]]:
        """Read `(ax, ay)` from BaseStorage without exposing the privkey."""
        record = await self._read_raw(cred_def_id_norm)
        if record is None:
            return None
        try:
            ax = int(record["ax"])
            ay = int(record["ay"])
            return (ax, ay)
        except (KeyError, ValueError, TypeError) as err:
            raise KanonZkIssuerKeyError(
                f"corrupt issuer-key record for {cred_def_id_norm}: {err}"
            ) from err

    async def _load_record_private(
        self, cred_def_id_norm: str
    ) -> Optional[str]:
        record = await self._read_raw(cred_def_id_norm)
        if record is None:
            return None
        priv = record.get("privateKeyHex")
        if not isinstance(priv, str):
            raise KanonZkIssuerKeyError(
                f"corrupt issuer-key record for {cred_def_id_norm}: no privateKeyHex"
            )
        return priv

    async def _read_raw(self, cred_def_id_norm: str) -> Optional[dict]:
        from acapy_agent.storage.base import BaseStorage  # type: ignore
        from acapy_agent.storage.error import StorageNotFoundError  # type: ignore

        try:
            async with self._profile.session() as session:
                storage = session.inject(BaseStorage)
                rec = await storage.get_record(
                    ISSUER_KEY_RECORD_TYPE, _record_id(cred_def_id_norm)
                )
        except StorageNotFoundError:
            return None
        if rec is None or not rec.value:
            return None
        return json.loads(rec.value)

    async def _save_record(
        self, cred_def_id_norm: str, key: eddsa.KanonZkIssuerKey
    ) -> None:
        from acapy_agent.storage.base import BaseStorage  # type: ignore
        from acapy_agent.storage.record import StorageRecord  # type: ignore

        payload = json.dumps(
            {
                "privateKeyHex": key.private_key_hex,
                "ax": str(key.Ax),
                "ay": str(key.Ay),
            }
        )
        record_id = _record_id(cred_def_id_norm)

        async with self._profile.session() as session:
            storage = session.inject(BaseStorage)
            try:
                existing = await storage.get_record(
                    ISSUER_KEY_RECORD_TYPE, record_id
                )
            except Exception:  # noqa: BLE001
                existing = None
            if existing is not None:
                await storage.update_record(existing, payload, existing.tags)
            else:
                await storage.add_record(
                    StorageRecord(
                        type=ISSUER_KEY_RECORD_TYPE,
                        value=payload,
                        tags={"credDefId": cred_def_id_norm},
                        id=record_id,
                    )
                )


class KanonZkIssuerKeyError(Exception):
    """Issuer-key persistence / retrieval failure."""


__all__ = [
    "ISSUER_KEY_RECORD_TYPE",
    "KanonZkIssuerKeyService",
    "KanonZkIssuerKeyError",
]
