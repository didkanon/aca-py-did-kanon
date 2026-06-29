"""KanonZkIssuer — restart-survivable Mode B issuer state for the Python plugin.

Mirrors the credo-ts plugin's `KanonZkService`:

  * Maintains an in-process active-leaf map (`keccak -> poseidon`) per
    cred_def_id.
  * On first use after restart, reads a checkpoint from ACA-Py BaseStorage
    (`record_type=kanon/zk/sync-checkpoint`) and replays any chain events
    since the last synced block. Both `keccak` and `poseidon` leaves come
    straight from the `CredentialAdded` / `CredentialRevoked` event payloads.
  * `revoke(cred_def_id, cred_ids)` derives keccak leaves via the same
    `deriveLeaf` shape the SDK uses (`keccak(keccak(credId))`), recomputes the
    new keccak root over the remaining active leaves with OZ-standard merkle,
    and publishes `batchUpdate` on `MerkleStateRegistry`.

Both root forms are real:
  * Keccak root via the OZ-StandardMerkleTree over all active leaves
    (matches the on-chain `MerkleStateRegistry.deriveLeaf` ordering).
  * Poseidon root via a depth-26 fixed-depth tagged-Poseidon tree
    (matches the `non_revocation.circom` `MerkleInclusion` template).
The SDK's `KanonZkService.addIssued` does the same — both sides agree on
the published roots byte-for-byte.
"""

from __future__ import annotations

import json
import logging
from typing import Optional, Sequence

from web3 import Web3

from did_kanon.v1_0.contracts.merkle_state import (
    KanonMerkleStateRegistry,
)
from did_kanon.v1_0.zk.attributes import (
    KANON_CRED_ID_ATTRIBUTE,
    KANON_ZK_CIRCUIT_ATTRS,
    KANON_ZK_PROOF_ATTRIBUTE,
    KANON_ZK_RESERVED_ATTRIBUTE_NAMES,
    KANON_ZK_SIG_ATTRIBUTE,
    attr_value_to_felt,
    encode_attributes_canonical,
    pad_attrs_to_circuit,
)
from did_kanon.v1_0.zk.merkle_keccak import OZStandardMerkleTree
from did_kanon.v1_0.zk.poseidon import poseidon_hash, BN254_PRIME


LOGGER = logging.getLogger(__name__)

CHECKPOINT_RECORD_TYPE = "kanon/zk/sync-checkpoint"


def _cred_def_id_bytes(cred_def_id: bytes | str) -> bytes:
    if isinstance(cred_def_id, str):
        cred_def_id = bytes.fromhex(
            cred_def_id[2:] if cred_def_id.lower().startswith("0x") else cred_def_id
        )
    if len(cred_def_id) != 32:
        raise ValueError("cred_def_id must be exactly 32 bytes")
    return bytes(cred_def_id)


def derive_leaf(cred_id: str | bytes) -> bytes:
    """Match the SDK's `deriveLeaf` — `keccak256(keccak256(credId))`.

    `credId` is a 32-byte secret (the SDK's `generateCredentialId()` returns it
    as `0x<64 hex>`). The Solidity `deriveLeaf(bytes32)` does
    `keccak256(bytes.concat(keccak256(abi.encode(credId))))`; since
    `abi.encode(bytes32)` is the 32 raw bytes, this is just
    `keccak256(keccak256(credIdBytes))`. We mirror that — *not* a utf-8 keccak.

    Accepts either a `0x<64 hex>` string or raw 32 bytes so callers don't have
    to remember which form the credId arrived in.
    """
    if isinstance(cred_id, str):
        s = cred_id[2:] if cred_id.lower().startswith("0x") else cred_id
        if len(s) != 64:
            raise ValueError(
                f"cred_id hex must be exactly 64 chars (32 bytes), got {len(s)}"
            )
        cred_bytes = bytes.fromhex(s)
    elif isinstance(cred_id, (bytes, bytearray)):
        if len(cred_id) != 32:
            raise ValueError(
                f"cred_id bytes must be exactly 32, got {len(cred_id)}"
            )
        cred_bytes = bytes(cred_id)
    else:
        raise TypeError("cred_id must be hex string (0x…) or 32 bytes")
    inner = Web3.keccak(cred_bytes)
    return Web3.keccak(inner)


# Note: the historical `poseidon_placeholder_leaf` helper was removed.
# The plugin now always computes the real tagged-Poseidon leaf via
# `compute_zk_leaf` and the real depth-26 Poseidon-Merkle root in
# `KanonZkIssuer._compute_poseidon_root`, mirroring the v6 credo plugin.


# ─── Mode B leaf primitives ──────────────────────────────────────────────
#
# These mirror `kanonv2/sdk/src/zk/eddsa.ts` and the `non_revocation.circom`
# circuit's leaf step. The output is a BN254 scalar (`int < BN254_PRIME`); the
# on-chain `MerkleStateRegistry.poseidonLeaf` field carries this as 32-byte
# big-endian. Keeping the int representation here is convenient because the
# Poseidon implementation already returns ints; callers convert via
# `felt_to_bytes32()` when they need the on-chain encoding.

# Domain-separation constant — MUST match `non_revocation.circom`'s
# `var LEAF_TAG = 1;`. See the docstring at the top of that file for why.
KANON_ZK_LEAF_TAG: int = 1


def felt_to_bytes32(felt: int) -> bytes:
    """Encode a BN254 felt as 32 big-endian bytes for on-chain storage.

    The on-chain `MerkleStateRegistry` accepts arbitrary bytes32; we adopt
    the convention `bytes32(uint256(felt))` so a verifier can hash-compare
    against a `publicSignals[0]` (root) that snarkjs already gives us as a
    decimal-encoded uint256 string.
    """
    return (int(felt) % BN254_PRIME).to_bytes(32, "big")


def cred_id_to_felt(cred_id: str | bytes) -> int:
    """Convert a 32-byte AnonCreds-bookkeeping credId to a BN254 felt.

    The SDK's `generateCredentialId()` returns a 32-byte secret; both sides
    agree to interpret it big-endian as a uint256 and reduce mod the BN254
    scalar field. Reducing (rather than rejecting) keeps the API total at
    the cost of a vanishingly small chance the felt differs from the int —
    safe because the reduced value is what's signed anyway.
    """
    if isinstance(cred_id, str):
        s = cred_id[2:] if cred_id.lower().startswith("0x") else cred_id
        if len(s) != 64:
            raise ValueError(
                f"cred_id hex must be 64 chars (32 bytes), got {len(s)}"
            )
        cred_bytes = bytes.fromhex(s)
    elif isinstance(cred_id, (bytes, bytearray)):
        if len(cred_id) != 32:
            raise ValueError(
                f"cred_id bytes must be 32, got {len(cred_id)}"
            )
        cred_bytes = bytes(cred_id)
    else:
        raise TypeError("cred_id must be 0x-hex string or 32 raw bytes")
    return int.from_bytes(cred_bytes, "big") % BN254_PRIME


def cred_def_id_to_felt(cred_def_id: str | bytes) -> int:
    """Convert a 32-byte credDefId to a BN254 felt.

    `credDefId` in kanon is `keccak256(utf8(resource_path))` — 32 bytes — so
    the same big-endian-mod-p convention used for credId works here.
    """
    return cred_id_to_felt(cred_def_id)


def compute_zk_leaf(
    cred_def_id: str | bytes,
    cred_id: str | bytes,
    attributes: Sequence[int],
) -> int:
    """Compute the Mode B credential leaf.

    Returns the same field element the circuit and the SDK compute:

        leaf = Poseidon(LEAF_TAG=1, credDefId, credId, Poseidon(attributes))

    `attributes` must be a list of 16 BN254 felts (the circuit's compiled
    arity). The circuit's `Poseidon(16)` and the inner `Poseidon` here use
    identical parameters, so the resulting leaf is byte-for-byte the value
    the verifier accepts.
    """
    if len(attributes) != 16:
        raise ValueError(
            f"compute_zk_leaf expects exactly 16 attributes, got {len(attributes)}"
        )
    cd_felt = cred_def_id_to_felt(cred_def_id)
    cr_felt = cred_id_to_felt(cred_id)
    attr_hash = poseidon_hash([int(a) % BN254_PRIME for a in attributes])
    return poseidon_hash([KANON_ZK_LEAF_TAG, cd_felt, cr_felt, attr_hash])


class KanonZkIssuerError(Exception):
    """Issuer-side Mode B failure."""


class KanonZkIssuerState:
    """Per-cred-def working set + sync watermark."""

    __slots__ = ("active", "last_synced_block")

    def __init__(self) -> None:
        # keccak (hex, no 0x) -> poseidon (hex, no 0x)
        self.active: dict[str, str] = {}
        self.last_synced_block: int = 0

    def to_dict(self) -> dict:
        return {
            "lastSyncedBlock": self.last_synced_block,
            "active": {
                "keccak": list(self.active.keys()),
                "poseidon": list(self.active.values()),
            },
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "KanonZkIssuerState":
        st = cls()
        st.last_synced_block = int(raw.get("lastSyncedBlock", 0))
        active = raw.get("active", {})
        ks = active.get("keccak", []) or []
        ps = active.get("poseidon", []) or []
        if len(ks) != len(ps):
            raise ValueError(
                "checkpoint keccak/poseidon arrays length mismatch"
            )
        st.active = {k.lower(): p.lower() for k, p in zip(ks, ps)}
        return st


class KanonZkIssuer:
    """Issuer-side Mode B facade. One instance per ACA-Py agent.

    Constructor takes the registry handle (which already has the operator
    key for tx signing) and the ACA-Py `profile` for BaseStorage access.
    """

    def __init__(self, merkle: KanonMerkleStateRegistry, profile) -> None:
        self._merkle = merkle
        self._profile = profile
        self._cache: dict[str, KanonZkIssuerState] = {}
        # Per-credef "we've already lazy-init'd this on chain" set, so we
        # don't burn a chain call on every issuance after the first. Kept
        # off `KanonZkIssuerState` (which is __slots__'d + serialised) so
        # the marker is process-local and doesn't leak into storage.
        self._chain_initialized: set[str] = set()

    # ────────────────────────────────────────────────────────────────
    # Public API
    # ────────────────────────────────────────────────────────────────

    async def get_or_init(self, cred_def_id: bytes | str) -> KanonZkIssuerState:
        """Idempotent: load checkpoint if any → incremental chain replay → cache."""
        cd = _cred_def_id_bytes(cred_def_id)
        key = cd.hex()
        cached = self._cache.get(key)
        if cached is not None:
            LOGGER.info("get_or_init: cache hit cd=%s", key)
            return cached
        LOGGER.info("get_or_init: cache miss cd=%s — loading", key)
        state = await self._load_checkpoint(cd)
        LOGGER.info("get_or_init: checkpoint loaded for cd=%s, replaying chain", key)
        await self._replay_from_chain(cd, state)
        LOGGER.info("get_or_init: chain replay done for cd=%s, saving", key)
        await self._save_checkpoint(cd, state)
        self._cache[key] = state
        return state

    async def revoke(self, cred_def_id: bytes | str, cred_ids: Sequence[str]) -> Optional[dict]:
        """Drop `cred_ids` from the published Mode B root. No-op on empty input."""
        if not cred_ids:
            return None
        cd = _cred_def_id_bytes(cred_def_id)
        state = await self.get_or_init(cd)

        revoked_keccak: list[bytes] = []
        revoked_poseidon: list[bytes] = []
        for cid in cred_ids:
            leaf = derive_leaf(cid)
            leaf_hex = leaf.hex()
            companion_hex = state.active.get(leaf_hex)
            if companion_hex is None:
                raise KanonZkIssuerError(
                    f"credId not in active set: {cid} (leaf=0x{leaf_hex})"
                )
            revoked_keccak.append(leaf)
            revoked_poseidon.append(bytes.fromhex(companion_hex))
            del state.active[leaf_hex]

        new_keccak_root = self._compute_keccak_root(state)
        new_poseidon_root = self._compute_poseidon_root(state)

        receipt = await self._merkle.batch_update(
            cd,
            added_leaves_keccak=[],
            added_leaves_poseidon=[],
            revoked_leaves_keccak=revoked_keccak,
            revoked_leaves_poseidon=revoked_poseidon,
            new_root_keccak=new_keccak_root,
            new_root_poseidon=new_poseidon_root,
        )
        state.last_synced_block = max(state.last_synced_block, int(receipt["block_number"]))
        await self._save_checkpoint(cd, state)
        return receipt

    async def add_issued(
        self,
        cred_def_id: bytes | str,
        credentials: Sequence[tuple[str, dict[str, str]]],
    ) -> Optional[dict]:
        """Publish issuance leaves for newly-issued credentials.

        `credentials` is a sequence of `(cred_id, domain_attributes)` pairs.
        `domain_attributes` MUST be the same value map the issuer signed
        at issuance time (sans the SDK-reserved names) — the holder, the
        verifier, and this leaf-tracking step must all encode to the
        identical felt vector or the SNARK side won't verify.

        Computed leaves (both ALWAYS real — no placeholders):

          - Mode A leaf (keccak path):
              `keccak256(keccak256(utf8(credId)))`
            — matches `MerkleStateRegistry.deriveLeaf(bytes32)` on chain.

          - Mode B leaf (tagged Poseidon):
              `Poseidon(LEAF_TAG=1, credDefFelt, credIdFelt, Poseidon(attrFelts))`
            — matches `non_revocation.circom`'s `MerkleInclusion` template
            byte-for-byte. The attrFelts vector is the canonical
            (alphabetical-name) encoding of `domain_attributes` padded to
            the circuit's 16-felt width.

        Both roots are recomputed over the full active leaf set after
        folding in the new entries:

          - Keccak root  → OZ-StandardMerkleTree.root
          - Poseidon root → depth-26 tagged Poseidon-Merkle tree root
                            (same depth/tag the circuit verifies against).

        No-op on empty input.

        NOTE: leaves are published *without* a BabyJubjub signature here.
        The signature is carried inside the credential's `kanonZkSig`
        attribute (set by `prepare_mode_b_credential` at issuance time).
        The chain stores only the leaves; the SNARK presentation flow is
        what binds the signature to the leaf.
        """
        if not credentials:
            return None

        cd = _cred_def_id_bytes(cred_def_id)
        LOGGER.info("add_issued: %d creds, calling get_or_init", len(credentials))
        state = await self.get_or_init(cd)
        LOGGER.info("add_issued: get_or_init returned, computing leaves")

        # Lazy on-chain initialisation. The MerkleStateRegistry requires
        # `initializeCredDefState` before any `batchUpdate`, but our
        # credef-create flow doesn't currently invoke it (it's a separate
        # write on a separate contract). Do it the first time we publish
        # leaves for a credDef; the registry method is idempotent so a
        # re-run after a process restart is a no-op.
        if cd.hex() not in self._chain_initialized:
            try:
                receipt = await self._merkle.initialize_cred_def_state(cd)
                if receipt is not None:
                    LOGGER.info(
                        "add_issued: initialized merkle state for cd=%s (tx=%s)",
                        cd.hex(),
                        receipt.get("tx_hash"),
                    )
                self._chain_initialized.add(cd.hex())
            except Exception as err:  # noqa: BLE001
                LOGGER.warning(
                    "add_issued: initializeCredDefState failed for cd=%s (continuing — "
                    "batchUpdate will surface the real error): %s",
                    cd.hex(), err,
                )

        # Defer the attribute-encoding imports so a Mode A-only deployment
        # that never calls `add_issued` doesn't pay the import cost.
        from did_kanon.v1_0.zk.attributes import (
            encode_attributes_canonical,
            pad_attrs_to_circuit,
        )

        added_keccak: list[bytes] = []
        added_poseidon: list[bytes] = []
        for cid, attrs in credentials:
            keccak_leaf = derive_leaf(cid)
            keccak_hex = keccak_leaf.hex()
            if keccak_hex in state.active:
                # Already published — skip to keep `batchUpdate` clean.
                continue

            # Real Mode B leaf — felt-encode the domain attrs in
            # canonical order, pad to circuit width, then tagged Poseidon.
            attr_felts = encode_attributes_canonical(attrs)
            padded = pad_attrs_to_circuit(attr_felts)
            # `compute_zk_leaf` does the cred_id felt reduction internally
            # (it big-endian reads the bytes then mods by p). To match the
            # holder side — which reduces `keccak256(utf8(credId)) mod p`
            # — we hand it the keccak-hash bytes, not the raw credId
            # string. This matters because `kanonCredId` carries a `0x`
            # prefix that would otherwise show up in the felt.
            cred_id_keccak = Web3.keccak(text=cid)  # 32 bytes
            poseidon_int = compute_zk_leaf(cd, cred_id_keccak, padded)
            poseidon_leaf = felt_to_bytes32(poseidon_int)

            poseidon_hex = poseidon_leaf.hex()
            state.active[keccak_hex] = poseidon_hex
            added_keccak.append(keccak_leaf)
            added_poseidon.append(poseidon_leaf)

        if not added_keccak:
            LOGGER.info("add_issued: no new leaves to publish")
            return None

        # Snapshot the cache before chain write so we can roll back on
        # failure. `state.active` is mutated for the in-process proof
        # path above; if `batch_update` reverts at the chain layer the
        # cache must not keep the leaves the contract never accepted,
        # otherwise the next call would compute a root over a superset
        # and proofs generated against it would diverge from on-chain
        # state.
        active_before = dict(state.active)
        last_synced_block_before = state.last_synced_block

        LOGGER.info("add_issued: computing keccak root over %d leaves", len(state.active))
        new_keccak_root = self._compute_keccak_root(state)
        LOGGER.info("add_issued: computing poseidon root over %d leaves", len(state.active))
        new_poseidon_root = self._compute_poseidon_root(state)
        LOGGER.info(
            "add_issued: calling batch_update — adding %d, keccak_root=%s, poseidon_root=%s",
            len(added_keccak), new_keccak_root.hex()[:16], new_poseidon_root.hex()[:16],
        )

        try:
            receipt = await self._merkle.batch_update(
                cd,
                added_leaves_keccak=added_keccak,
                added_leaves_poseidon=added_poseidon,
                revoked_leaves_keccak=[],
                revoked_leaves_poseidon=[],
                new_root_keccak=new_keccak_root,
                new_root_poseidon=new_poseidon_root,
            )
        except Exception:
            # Roll back the in-memory cache; the chain never accepted
            # these leaves, so they must not survive in `state.active`.
            state.active = active_before
            state.last_synced_block = last_synced_block_before
            raise
        LOGGER.info(
            "add_issued: batch_update returned tx=%s block=%s status=%s",
            receipt.get("tx_hash") if isinstance(receipt, dict) else receipt,
            receipt.get("block_number") if isinstance(receipt, dict) else "?",
            receipt.get("status") if isinstance(receipt, dict) else "?",
        )
        state.last_synced_block = max(
            state.last_synced_block, int(receipt["block_number"])
        )
        await self._save_checkpoint(cd, state)
        return receipt

    async def get_checkpoint(self, cred_def_id: bytes | str) -> dict:
        """Snapshot the active leaf set for a cred-def (mostly for routes)."""
        state = await self.get_or_init(cred_def_id)
        return state.to_dict()

    def invalidate(self, cred_def_id: bytes | str) -> None:
        cd = _cred_def_id_bytes(cred_def_id)
        self._cache.pop(cd.hex(), None)

    # ────────────────────────────────────────────────────────────────
    # Internals
    # ────────────────────────────────────────────────────────────────

    def _compute_keccak_root(self, state: KanonZkIssuerState) -> bytes:
        if not state.active:
            # Match the SDK's empty-tree convention: a single zero leaf.
            return OZStandardMerkleTree([b"\x00" * 32]).root
        leaves = [bytes.fromhex(k) for k in state.active.keys()]
        return OZStandardMerkleTree(leaves).root

    # Tree depth — must match the compiled circuit (`NonRevocation(26, …)`)
    # AND the SDK's `PoseidonTree(26, …)`. Both sides agree on this constant.
    _POSEIDON_TREE_DEPTH: int = 26

    def _compute_poseidon_root(self, state: KanonZkIssuerState) -> bytes:
        """Real depth-26 tagged-Poseidon Merkle root over the active Poseidon
        leaves — matches the SDK's `PoseidonTree(26, allPoseidonBig).root`
        and the circuit's `MerkleInclusion` template (NODE_TAG=2).
        """
        from did_kanon.v1_0.zk.merkle_poseidon import PoseidonMerkleTree

        poseidon_felts = [int(h, 16) for h in state.active.values()]
        tree = PoseidonMerkleTree(self._POSEIDON_TREE_DEPTH, poseidon_felts)
        return felt_to_bytes32(tree.root)

    async def _replay_from_chain(
        self, cred_def_id: bytes, state: KanonZkIssuerState
    ) -> None:
        events = await self._merkle.get_leaf_events(
            cred_def_id, from_block=state.last_synced_block
        )
        for ev in events:
            k = ev["keccak"].lower()
            p = ev["poseidon"].lower()
            if ev["kind"] == "add":
                state.active[k] = p
            else:
                state.active.pop(k, None)
        state.last_synced_block = self._merkle.latest_block

    async def _load_checkpoint(self, cred_def_id: bytes) -> KanonZkIssuerState:
        record_id = self._checkpoint_record_id(cred_def_id)
        try:
            from acapy_agent.storage.base import BaseStorage  # type: ignore

            async with self._profile.session() as session:
                storage = session.inject(BaseStorage)
                rec = await storage.get_record(CHECKPOINT_RECORD_TYPE, record_id)
                if rec and rec.value:
                    return KanonZkIssuerState.from_dict(json.loads(rec.value))
        except Exception as err:
            # Missing record or storage hiccup → start fresh; chain replay below
            # rehydrates correctness.
            LOGGER.debug(
                "kanon-zk checkpoint not found (treating as fresh): %s", err
            )
        return KanonZkIssuerState()

    async def _save_checkpoint(
        self, cred_def_id: bytes, state: KanonZkIssuerState
    ) -> None:
        record_id = self._checkpoint_record_id(cred_def_id)
        try:
            from acapy_agent.storage.base import BaseStorage  # type: ignore
            from acapy_agent.storage.record import StorageRecord  # type: ignore

            async with self._profile.session() as session:
                storage = session.inject(BaseStorage)
                value = json.dumps(state.to_dict())
                try:
                    existing = await storage.get_record(
                        CHECKPOINT_RECORD_TYPE, record_id
                    )
                except Exception:
                    existing = None
                if existing is not None:
                    await storage.update_record(existing, value, existing.tags)
                else:
                    await storage.add_record(
                        StorageRecord(
                            type=CHECKPOINT_RECORD_TYPE,
                            value=value,
                            tags={"credDefId": cred_def_id.hex()},
                            id=record_id,
                        )
                    )
        except Exception as err:
            LOGGER.warning(
                "kanon-zk: failed to persist checkpoint for %s: %s",
                cred_def_id.hex(),
                err,
            )

    @staticmethod
    def _checkpoint_record_id(cred_def_id: bytes) -> str:
        return f"kanon-zk-sync:{cred_def_id.hex()}"


__all__ = [
    "KanonZkIssuer",
    "KanonZkIssuerError",
    "KanonZkIssuerState",
    "derive_leaf",
    "compute_zk_leaf",
    "cred_id_to_felt",
    "cred_def_id_to_felt",
    "felt_to_bytes32",
    "KANON_ZK_LEAF_TAG",
    "CHECKPOINT_RECORD_TYPE",
    # Re-exported from .attributes — mirrors @ajna-inc/kanon-sdk/anoncreds.
    "KANON_CRED_ID_ATTRIBUTE",
    "KANON_ZK_SIG_ATTRIBUTE",
    "KANON_ZK_PROOF_ATTRIBUTE",
    "KANON_ZK_RESERVED_ATTRIBUTE_NAMES",
    "KANON_ZK_CIRCUIT_ATTRS",
    "attr_value_to_felt",
    "encode_attributes_canonical",
    "pad_attrs_to_circuit",
]
