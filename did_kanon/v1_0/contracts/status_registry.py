"""KanonAnonCredsStatusRegistry — per-credential issuance + revocation client.

The on-chain primitive that the Python plugin (acting as an issuer or
verifier) uses for Mode A revocation. Mirrors the JS-side
`@ajna-inc/kanon-sdk` interface so a verifier check is a single eth_call
after AnonCreds proof verification.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Union

from web3 import Web3
from web3.contract import Contract
from web3.exceptions import ContractLogicError, Web3Exception

from .abis import ANONCREDS_STATUS_REGISTRY_ABI

LOGGER = logging.getLogger(__name__)

Bytes32Like = Union[bytes, str]


class StatusEnum(IntEnum):
    UNKNOWN = 0
    ISSUED = 1
    REVOKED = 2


@dataclass
class StatusRegistryTxResult:
    tx_hash: str
    block_number: int
    status: int


class KanonAnonCredsStatusRegistryError(Exception):
    """Raised on transport / logic errors talking to the registry."""


def _to_bytes32(value: Bytes32Like, name: str = "value") -> bytes:
    """Coerce a `bytes` (must be 32 bytes) or `0x…` hex string into 32 bytes."""
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


class KanonAnonCredsStatusRegistry:
    """Thin web3 wrapper around the AnonCredsStatusRegistry contract.

    All write ops require the caller to have supplied an operator key when
    constructing the underlying `web3` instance. Read ops are pure
    eth_call — no key, no gas.
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
            abi=ANONCREDS_STATUS_REGISTRY_ABI,
        )
        self._account = (
            w3.eth.account.from_key(operator_key) if operator_key else None
        )
        self._tx_timeout = tx_timeout
        self._send_lock = asyncio.Lock()

    @property
    def address(self) -> str:
        return self._contract.address

    @property
    def operator_address(self) -> Optional[str]:
        return self._account.address if self._account else None

    # ────────────────────────────────────────────────────────────────
    # Reads
    # ────────────────────────────────────────────────────────────────

    async def get_status(
        self,
        cred_def_id: Bytes32Like,
        cred_id_hash: Bytes32Like,
    ) -> StatusEnum:
        cd = _to_bytes32(cred_def_id, "cred_def_id")
        ch = _to_bytes32(cred_id_hash, "cred_id_hash")

        def _call() -> int:
            return int(self._contract.functions.getStatus(cd, ch).call())

        try:
            raw = await asyncio.to_thread(_call)
        except (ContractLogicError, Web3Exception, ValueError, OSError) as err:
            raise KanonAnonCredsStatusRegistryError(
                f"AnonCredsStatusRegistry.getStatus failed: {err}"
            ) from err
        return StatusEnum(raw)

    async def is_revoked(
        self,
        cred_def_id: Bytes32Like,
        cred_id_hash: Bytes32Like,
    ) -> bool:
        cd = _to_bytes32(cred_def_id, "cred_def_id")
        ch = _to_bytes32(cred_id_hash, "cred_id_hash")

        def _call() -> bool:
            return bool(self._contract.functions.isRevoked(cd, ch).call())

        try:
            return await asyncio.to_thread(_call)
        except (ContractLogicError, Web3Exception, ValueError, OSError) as err:
            raise KanonAnonCredsStatusRegistryError(
                f"AnonCredsStatusRegistry.isRevoked failed: {err}"
            ) from err

    async def is_active(
        self,
        cred_def_id: Bytes32Like,
        cred_id_hash: Bytes32Like,
    ) -> bool:
        cd = _to_bytes32(cred_def_id, "cred_def_id")
        ch = _to_bytes32(cred_id_hash, "cred_id_hash")

        def _call() -> bool:
            return bool(self._contract.functions.isActive(cd, ch).call())

        try:
            return await asyncio.to_thread(_call)
        except (ContractLogicError, Web3Exception, ValueError, OSError) as err:
            raise KanonAnonCredsStatusRegistryError(
                f"AnonCredsStatusRegistry.isActive failed: {err}"
            ) from err

    # ────────────────────────────────────────────────────────────────
    # Writes
    # ────────────────────────────────────────────────────────────────

    async def issue_credential(
        self,
        cred_def_id: Bytes32Like,
        cred_id_hash: Bytes32Like,
    ) -> StatusRegistryTxResult:
        return await self._send(
            "issueCredential",
            _to_bytes32(cred_def_id, "cred_def_id"),
            _to_bytes32(cred_id_hash, "cred_id_hash"),
        )

    async def revoke_credential(
        self,
        cred_def_id: Bytes32Like,
        cred_id_hash: Bytes32Like,
    ) -> StatusRegistryTxResult:
        return await self._send(
            "revokeCredential",
            _to_bytes32(cred_def_id, "cred_def_id"),
            _to_bytes32(cred_id_hash, "cred_id_hash"),
        )

    async def _send(self, fn_name: str, *args) -> StatusRegistryTxResult:
        if self._account is None:
            raise KanonAnonCredsStatusRegistryError(
                f"AnonCredsStatusRegistry.{fn_name}: no operator key configured"
            )

        def _build_send() -> StatusRegistryTxResult:
            fn = self._contract.functions[fn_name](*args)
            tx_fields = {
                "from": self._account.address,
                "nonce": self._w3.eth.get_transaction_count(
                    self._account.address, "pending"
                ),
                "chainId": self._w3.eth.chain_id,
            }
            tx_fields["gas"] = fn.estimate_gas({"from": self._account.address})
            tx_fields.update(self._build_fee_fields())
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
            return StatusRegistryTxResult(
                tx_hash=receipt["transactionHash"].hex(),
                block_number=receipt["blockNumber"],
                status=receipt["status"],
            )

        async with self._send_lock:
            try:
                result = await asyncio.to_thread(_build_send)
            except ContractLogicError as err:
                raise KanonAnonCredsStatusRegistryError(
                    f"AnonCredsStatusRegistry.{fn_name} reverted: {err}"
                ) from err
            except (Web3Exception, ValueError, OSError) as err:
                raise KanonAnonCredsStatusRegistryError(
                    f"AnonCredsStatusRegistry.{fn_name} failed: {err}"
                ) from err

        if result.status != 1:
            raise KanonAnonCredsStatusRegistryError(
                f"AnonCredsStatusRegistry.{fn_name} reverted (tx {result.tx_hash})"
            )
        return result

    def _build_fee_fields(self) -> dict:
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
            return {
                "maxFeePerGas": int(base_fee * 2.0) + int(max_priority),
                "maxPriorityFeePerGas": int(max_priority),
            }
        return {"gasPrice": self._w3.eth.gas_price}
