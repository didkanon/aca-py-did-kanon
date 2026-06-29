"""Shared base for the Kanon registry write/read clients.

Factors the transaction plumbing (nonce lock, gas estimate, EIP-1559 vs
legacy fee detection, sign + wait) out of the per-registry wrappers so each
concrete client is just method shapes + result decoding.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional, Union

from web3 import Web3
from web3.contract import Contract
from web3.exceptions import ContractLogicError, Web3Exception

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
class RegistryTxResult:
    tx_hash: str
    block_number: int
    status: int


class RegistryClientError(Exception):
    """Transport or contract-side failure talking to a registry."""


class RegistryTxClient:
    """Base write+read client.

    Write ops require an operator key (supplied at construction); reads are
    pure `eth_call` and need no key. A per-client lock serialises sends so a
    pending nonce isn't reused across concurrent writes.
    """

    def __init__(
        self,
        w3: Web3,
        address: str,
        abi,
        *,
        operator_key: Optional[str] = None,
        tx_timeout: int = 60,
    ):
        self._w3 = w3
        self._contract: Contract = w3.eth.contract(
            address=Web3.to_checksum_address(address),
            abi=abi,
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

    async def _send(self, fn_name: str, *args) -> RegistryTxResult:
        if self._account is None:
            raise RegistryClientError(
                f"{fn_name}: no operator key configured"
            )

        def _build_send() -> RegistryTxResult:
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
            return RegistryTxResult(
                tx_hash=receipt["transactionHash"].hex(),
                block_number=receipt["blockNumber"],
                status=receipt["status"],
            )

        async with self._send_lock:
            try:
                result = await asyncio.to_thread(_build_send)
            except ContractLogicError as err:
                raise RegistryClientError(
                    f"{fn_name} reverted: {err}"
                ) from err
            except (Web3Exception, ValueError, OSError) as err:
                raise RegistryClientError(
                    f"{fn_name} failed: {err}"
                ) from err

        if result.status != 1:
            raise RegistryClientError(
                f"{fn_name} reverted (tx {result.tx_hash})"
            )
        return result

    async def _read(self, fn_name: str, *args):
        """Run a view fn in a thread; re-raise web3 errors as our error.

        Reverts are surfaced (not swallowed) so callers can decide how to
        interpret a revert (None / False / zero-address).
        """

        def _call():
            return self._contract.functions[fn_name](*args).call()

        try:
            return await asyncio.to_thread(_call)
        except (ContractLogicError, Web3Exception, ValueError, OSError) as err:
            raise RegistryClientError(
                f"{fn_name} read failed: {err}"
            ) from err
