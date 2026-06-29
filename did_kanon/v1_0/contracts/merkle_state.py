"""KanonMerkleStateRegistry — Tier-1 nullifier set + Tier-2 on-chain ZK verify.

The Python wrapper. Only the methods the plugin actually uses are exposed;
add more as the integration grows.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional, Sequence, Union

from web3 import Web3
from web3.contract import Contract
from web3.exceptions import ContractLogicError, Web3Exception

from .abis import MERKLE_STATE_REGISTRY_ABI

LOGGER = logging.getLogger(__name__)

Bytes32Like = Union[bytes, str]


def _to_bytes32(value: Bytes32Like, name: str = "value") -> bytes:
    if isinstance(value, str):
        if value.startswith("0x") or value.startswith("0X"):
            value = bytes.fromhex(value[2:])
        else:
            value = bytes.fromhex(value)
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes or hex string")
    if len(value) != 32:
        raise ValueError(f"{name} must be exactly 32 bytes, got {len(value)}")
    return bytes(value)


def _to_bytes(value: Union[bytes, str], name: str = "value") -> bytes:
    if isinstance(value, str):
        if value.startswith("0x") or value.startswith("0X"):
            return bytes.fromhex(value[2:])
        return bytes.fromhex(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise TypeError(f"{name} must be bytes or hex string")


@dataclass
class MerkleRoots:
    keccak_root: bytes
    poseidon_root: bytes


class KanonMerkleStateRegistryError(Exception):
    """Transport or contract-side failure."""


class KanonMerkleStateRegistry:
    """Read + Mode-B-issuer write client.

    Holder/verifier paths only ever read; Mode B issuance + revocation needs
    the `batchUpdate` write path, which requires an operator key supplied at
    construction. Reads work whether or not a key is configured.
    """

    def __init__(
        self,
        w3: Web3,
        address: str,
        *,
        operator_key: Optional[str] = None,
        tx_timeout: int = 60,
    ):
        self._w3 = w3
        self._contract: Contract = w3.eth.contract(
            address=Web3.to_checksum_address(address),
            abi=MERKLE_STATE_REGISTRY_ABI,
        )
        self._account = (
            w3.eth.account.from_key(operator_key) if operator_key else None
        )
        self._tx_timeout = tx_timeout
        self._send_lock = asyncio.Lock()

    @property
    def operator_address(self) -> Optional[str]:
        return self._account.address if self._account else None

    @property
    def address(self) -> str:
        return self._contract.address

    # ────────────────────────────────────────────────────────────────
    # Reads — all `eth_call`, free, no gas
    # ────────────────────────────────────────────────────────────────

    async def verify_zk_membership(
        self,
        cred_def_id: Bytes32Like,
        proof_bytes: Union[bytes, str],
        public_signals: Sequence[Bytes32Like],
    ) -> bool:
        """Mode B verification — calls `verifyZKMembership` view function.

        Verifier-side: takes the Groth16 proof bytes + the 7 public signals
        (`[root, credDefId, challenge, Ax, Ay, idx, val]`) and returns
        True iff the proof is valid against the verifier registered for
        this credDef. No gas, no transaction — a pure RPC simulation.
        """
        cd = _to_bytes32(cred_def_id, "cred_def_id")
        pb = _to_bytes(proof_bytes, "proof_bytes")
        signals = [_to_bytes32(s, f"public_signals[{i}]") for i, s in enumerate(public_signals)]

        def _call() -> bool:
            return bool(
                self._contract.functions.verifyZKMembership(cd, pb, signals).call()
            )

        try:
            return await asyncio.to_thread(_call)
        except ContractLogicError as err:
            LOGGER.debug(
                "verifyZKMembership reverted (treated as false): %s", err
            )
            return False
        except (Web3Exception, ValueError, OSError) as err:
            raise KanonMerkleStateRegistryError(
                f"verifyZKMembership transport error: {err}"
            ) from err

    async def current_roots(self, cred_def_id: Bytes32Like) -> Optional[MerkleRoots]:
        """Current (keccak, poseidon) roots, read from `getState`."""
        cd = _to_bytes32(cred_def_id, "cred_def_id")

        def _call():
            return self._contract.functions.getState(cd).call()

        try:
            state = await asyncio.to_thread(_call)
        except ContractLogicError:
            return None
        except (Web3Exception, ValueError, OSError) as err:
            raise KanonMerkleStateRegistryError(
                f"getState transport error: {err}"
            ) from err
        # tuple: (rootKeccak, rootPoseidon, epoch, lastUpdated, issuedCount, revokedCount)
        return MerkleRoots(keccak_root=bytes(state[0]), poseidon_root=bytes(state[1]))

    async def is_recent_keccak_root(
        self, cred_def_id: Bytes32Like, root: Bytes32Like
    ) -> bool:
        """Tier-1: is `root` within the recent Keccak-root window?"""
        return await self._is_recent("isRecentKeccakRoot", cred_def_id, root)

    async def is_recent_poseidon_root(
        self, cred_def_id: Bytes32Like, root: Bytes32Like
    ) -> bool:
        """Tier-2 (ZK): is `root` within the recent Poseidon-root window?"""
        return await self._is_recent("isRecentPoseidonRoot", cred_def_id, root)

    async def _is_recent(
        self, fn_name: str, cred_def_id: Bytes32Like, root: Bytes32Like
    ) -> bool:
        cd = _to_bytes32(cred_def_id, "cred_def_id")
        r = _to_bytes32(root, "root")

        def _call() -> bool:
            return bool(self._contract.functions[fn_name](cd, r).call())

        try:
            return await asyncio.to_thread(_call)
        except ContractLogicError:
            return False
        except (Web3Exception, ValueError, OSError) as err:
            raise KanonMerkleStateRegistryError(
                f"{fn_name} transport error: {err}"
            ) from err

    async def is_nullifier_used(
        self, cred_def_id: Bytes32Like, nullifier: Bytes32Like
    ) -> bool:
        cd = _to_bytes32(cred_def_id, "cred_def_id")
        n = _to_bytes32(nullifier, "nullifier")

        def _call() -> bool:
            return bool(self._contract.functions.isNullifierUsed(cd, n).call())

        try:
            return await asyncio.to_thread(_call)
        except ContractLogicError:
            return False
        except (Web3Exception, ValueError, OSError) as err:
            raise KanonMerkleStateRegistryError(
                f"isNullifierUsed transport error: {err}"
            ) from err

    # ────────────────────────────────────────────────────────────────
    # Writes — require operator_key
    # ────────────────────────────────────────────────────────────────

    async def initialize_cred_def_state(
        self,
        cred_def_id: Bytes32Like,
        initial_root_keccak: Bytes32Like = b"\x00" * 32,
        initial_root_poseidon: Bytes32Like = b"\x00" * 32,
    ) -> Optional[dict]:
        """One-time initialisation of a credDef's MerkleState slot.

        `batchUpdate` reverts with `NotInitialized(credDefId)` until this
        call lands. The contract is idempotent in the sense that a second
        call reverts with `AlreadyInitialized` — we treat that as a no-op
        so callers don't have to track which credDefs they've handled.
        """
        if self._account is None:
            raise KanonMerkleStateRegistryError(
                "initialize_cred_def_state: no operator key configured"
            )
        cd = _to_bytes32(cred_def_id, "cred_def_id")
        rk = _to_bytes32(initial_root_keccak, "initial_root_keccak")
        rp = _to_bytes32(initial_root_poseidon, "initial_root_poseidon")

        def _build_send() -> dict:
            fn = self._contract.functions.initializeCredDefState(cd, rk, rp)
            tx_fields = {
                "from": self._account.address,
                "nonce": self._w3.eth.get_transaction_count(
                    self._account.address, "pending"
                ),
                "chainId": self._w3.eth.chain_id,
            }
            tx_fields["gas"] = fn.estimate_gas({"from": self._account.address})
            try:
                latest = self._w3.eth.get_block("latest")
                base_fee = latest.get("baseFeePerGas")
            except Exception:
                base_fee = None
            if base_fee is not None:
                try:
                    max_priority = self._w3.eth.max_priority_fee
                except Exception:
                    max_priority = self._w3.to_wei(2, "gwei")
                tx_fields.update(
                    {
                        "maxFeePerGas": int(base_fee * 2.0) + int(max_priority),
                        "maxPriorityFeePerGas": int(max_priority),
                    }
                )
            else:
                tx_fields["gasPrice"] = self._w3.eth.gas_price

            tx = fn.build_transaction(tx_fields)
            signed = self._account.sign_transaction(tx)
            raw = (
                signed.raw_transaction
                if hasattr(signed, "raw_transaction")
                else signed.rawTransaction
            )
            tx_hash = self._w3.eth.send_raw_transaction(raw)
            receipt = self._w3.eth.wait_for_transaction_receipt(
                tx_hash, timeout=self._tx_timeout, poll_latency=2
            )
            return {
                "tx_hash": receipt["transactionHash"].hex(),
                "block_number": receipt["blockNumber"],
                "status": receipt["status"],
            }

        async with self._send_lock:
            try:
                return await asyncio.to_thread(_build_send)
            except ContractLogicError as err:
                # `AlreadyInitialized` is the idempotent path — treat as
                # success since the slot is in the state we wanted.
                if "AlreadyInitialized" in str(err) or "0x0dc149f0" in str(err):
                    return None
                raise KanonMerkleStateRegistryError(
                    f"initializeCredDefState reverted: {err}"
                ) from err
            except (Web3Exception, ValueError, OSError) as err:
                # Pre-flight gas estimation may bubble the revert here when
                # the credDef is already initialised. Treat as no-op too.
                if "AlreadyInitialized" in str(err):
                    return None
                raise KanonMerkleStateRegistryError(
                    f"initializeCredDefState transport error: {err}"
                ) from err

    async def is_initialized(self, cred_def_id: Bytes32Like) -> bool:
        cd = _to_bytes32(cred_def_id, "cred_def_id")
        try:
            return bool(
                await asyncio.to_thread(
                    self._contract.functions.isInitialized(cd).call
                )
            )
        except Exception:  # noqa: BLE001
            return False

    async def batch_update(
        self,
        cred_def_id: Bytes32Like,
        added_leaves_keccak: Sequence[Bytes32Like],
        added_leaves_poseidon: Sequence[Bytes32Like],
        revoked_leaves_keccak: Sequence[Bytes32Like],
        revoked_leaves_poseidon: Sequence[Bytes32Like],
        new_root_keccak: Bytes32Like,
        new_root_poseidon: Bytes32Like,
    ) -> dict:
        """Publish a Mode B Merkle root rotation.

        Calling without `operator_key` configured raises. Sizes for the added
        / revoked parallel arrays must match, otherwise the contract reverts.
        Returns a dict with `tx_hash`, `block_number`, and `status`.
        """
        if self._account is None:
            raise KanonMerkleStateRegistryError(
                "batch_update: no operator key configured"
            )
        if len(added_leaves_keccak) != len(added_leaves_poseidon):
            raise KanonMerkleStateRegistryError(
                "batch_update: added keccak/poseidon arrays length mismatch"
            )
        if len(revoked_leaves_keccak) != len(revoked_leaves_poseidon):
            raise KanonMerkleStateRegistryError(
                "batch_update: revoked keccak/poseidon arrays length mismatch"
            )

        cd = _to_bytes32(cred_def_id, "cred_def_id")
        added_k = [_to_bytes32(b, "added_keccak") for b in added_leaves_keccak]
        added_p = [_to_bytes32(b, "added_poseidon") for b in added_leaves_poseidon]
        revoked_k = [_to_bytes32(b, "revoked_keccak") for b in revoked_leaves_keccak]
        revoked_p = [_to_bytes32(b, "revoked_poseidon") for b in revoked_leaves_poseidon]
        rk = _to_bytes32(new_root_keccak, "new_root_keccak")
        rp = _to_bytes32(new_root_poseidon, "new_root_poseidon")

        def _build_send() -> dict:
            fn = self._contract.functions.batchUpdate(
                cd, added_k, added_p, revoked_k, revoked_p, rk, rp
            )
            tx_fields = {
                "from": self._account.address,
                "nonce": self._w3.eth.get_transaction_count(
                    self._account.address, "pending"
                ),
                "chainId": self._w3.eth.chain_id,
            }
            tx_fields["gas"] = fn.estimate_gas({"from": self._account.address})
            try:
                latest = self._w3.eth.get_block("latest")
                base_fee = latest.get("baseFeePerGas")
            except Exception:
                base_fee = None
            if base_fee is not None:
                try:
                    max_priority = self._w3.eth.max_priority_fee
                except Exception:
                    max_priority = self._w3.to_wei(2, "gwei")
                tx_fields.update(
                    {
                        "maxFeePerGas": int(base_fee * 2.0) + int(max_priority),
                        "maxPriorityFeePerGas": int(max_priority),
                    }
                )
            else:
                tx_fields["gasPrice"] = self._w3.eth.gas_price

            tx = fn.build_transaction(tx_fields)
            signed = self._account.sign_transaction(tx)
            raw = (
                signed.raw_transaction
                if hasattr(signed, "raw_transaction")
                else signed.rawTransaction
            )
            tx_hash = self._w3.eth.send_raw_transaction(raw)
            receipt = self._w3.eth.wait_for_transaction_receipt(
                tx_hash, timeout=self._tx_timeout, poll_latency=2
            )
            return {
                "tx_hash": receipt["transactionHash"].hex(),
                "block_number": receipt["blockNumber"],
                "status": receipt["status"],
            }

        async with self._send_lock:
            try:
                return await asyncio.to_thread(_build_send)
            except ContractLogicError as err:
                raise KanonMerkleStateRegistryError(
                    f"batchUpdate reverted: {err}"
                ) from err
            except (Web3Exception, ValueError, OSError) as err:
                raise KanonMerkleStateRegistryError(
                    f"batchUpdate transport error: {err}"
                ) from err

    # ────────────────────────────────────────────────────────────────
    # Event scan — issuer chain-replay reconstruction
    # ────────────────────────────────────────────────────────────────

    async def get_leaf_events(
        self,
        cred_def_id: Bytes32Like,
        from_block: int = 0,
        to_block: Optional[int] = None,
    ) -> list[dict]:
        """Scan `CredentialAdded` + `CredentialRevoked` for `cred_def_id`.

        Returns a list of dicts sorted by (block, log_index) with keys
        `block`, `log_index`, `kind` ("add" / "revoke"), `keccak`, `poseidon`.
        Both leaf forms are pulled from the event payload — no recomputation.
        """
        cd = _to_bytes32(cred_def_id, "cred_def_id")
        tip = to_block if to_block is not None else self._w3.eth.block_number

        def _scan() -> list[dict]:
            added_filter = self._contract.events.CredentialAdded.create_filter(
                from_block=from_block,
                to_block=tip,
                argument_filters={"credDefId": cd},
            )
            revoked_filter = self._contract.events.CredentialRevoked.create_filter(
                from_block=from_block,
                to_block=tip,
                argument_filters={"credDefId": cd},
            )
            events: list[dict] = []
            for ev in added_filter.get_all_entries():
                events.append(
                    {
                        "block": ev["blockNumber"],
                        "log_index": ev["logIndex"],
                        "kind": "add",
                        "keccak": bytes(ev["args"]["leafKeccak"]).hex(),
                        "poseidon": bytes(ev["args"]["leafPoseidon"]).hex(),
                    }
                )
            for ev in revoked_filter.get_all_entries():
                events.append(
                    {
                        "block": ev["blockNumber"],
                        "log_index": ev["logIndex"],
                        "kind": "revoke",
                        "keccak": bytes(ev["args"]["leafKeccak"]).hex(),
                        "poseidon": bytes(ev["args"]["leafPoseidon"]).hex(),
                    }
                )
            events.sort(key=lambda e: (e["block"], e["log_index"]))
            return events

        try:
            return await asyncio.to_thread(_scan)
        except (Web3Exception, ValueError, OSError) as err:
            raise KanonMerkleStateRegistryError(
                f"get_leaf_events transport error: {err}"
            ) from err

    @property
    def latest_block(self) -> int:
        return self._w3.eth.block_number
