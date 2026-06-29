"""KanonDIDRegistry — on-chain DID document registry client.

Mode-A identity layer: register/update/deactivate DID documents and resolve
them back into plain dicts. The caller is responsible for building the
15-field DIDDocument struct tuple (in ABI order) for writes.
"""

from __future__ import annotations

import logging
from typing import Optional, Union

from web3 import Web3
from web3.exceptions import ContractLogicError

from .abis import DID_REGISTRY_ABI
from ._base import Bytes32Like, RegistryClientError, RegistryTxClient, RegistryTxResult, _to_bytes32

LOGGER = logging.getLogger(__name__)

_ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


class KanonDIDRegistry(RegistryTxClient):
    """Write+read wrapper around the DIDRegistry contract."""

    def __init__(
        self,
        w3: Web3,
        address: str,
        *,
        operator_key: Optional[str] = None,
        tx_timeout: int = 60,
    ):
        super().__init__(
            w3,
            address,
            DID_REGISTRY_ABI,
            operator_key=operator_key,
            tx_timeout=tx_timeout,
        )

    # ────────────────────────────────────────────────────────────────
    # Writes
    # ────────────────────────────────────────────────────────────────

    async def register_did(
        self,
        did: str,
        salt: Bytes32Like,
        doc: Union[tuple, list],
    ) -> RegistryTxResult:
        """Register `did`; `doc` is the pre-built DIDDocument struct tuple."""
        return await self._send("registerDID", did, _to_bytes32(salt, "salt"), doc)

    async def update_did(
        self, did: str, doc: Union[tuple, list]
    ) -> RegistryTxResult:
        return await self._send("updateDID", did, doc)

    async def deactivate_did(self, did: str) -> RegistryTxResult:
        return await self._send("deactivateDID", did)

    # ────────────────────────────────────────────────────────────────
    # Reads
    # ────────────────────────────────────────────────────────────────

    async def resolve_did(self, did: str) -> Optional[dict]:
        """Resolve `did` into a dict; None if not found (call reverts)."""
        try:
            raw = await self._read("resolveDID", did)
        except RegistryClientError as err:
            if isinstance(err.__cause__, ContractLogicError):
                return None
            raise
        return self._decode_doc(raw)

    async def exists(self, did: str) -> bool:
        try:
            return bool(await self._read("exists", did))
        except RegistryClientError as err:
            if isinstance(err.__cause__, ContractLogicError):
                return False
            raise

    async def is_deactivated(self, did: str) -> bool:
        try:
            return bool(await self._read("isDeactivated", did))
        except RegistryClientError as err:
            if isinstance(err.__cause__, ContractLogicError):
                return False
            raise

    async def controller_of(self, did: str) -> str:
        try:
            return str(await self._read("controllerOf", did))
        except RegistryClientError as err:
            if isinstance(err.__cause__, ContractLogicError):
                return _ZERO_ADDRESS
            raise

    @staticmethod
    def _decode_doc(raw) -> dict:
        """Decode the 15-field DIDDocument struct tuple into a dict."""
        (
            controller,
            org_id,
            scope,
            verification_methods,
            authentication,
            assertion_method,
            capability_invocation,
            capability_delegation,
            key_agreement,
            services,
            doc_hash,
            created_at,
            updated_at,
            deactivated,
        ) = raw
        return {
            "controller": controller,
            # orgId is bytes32 — return it as a 0x-prefixed hex string.
            "org_id": "0x" + bytes(org_id).hex(),
            "scope": int(scope),
            "verification_methods": [
                {
                    "id": bytes(vm[0]),
                    "vm_type": int(vm[1]),
                    "public_key": bytes(vm[2]),
                }
                for vm in verification_methods
            ],
            "authentication": [bytes(b) for b in authentication],
            "assertion_method": [bytes(b) for b in assertion_method],
            "capability_invocation": [bytes(b) for b in capability_invocation],
            "capability_delegation": [bytes(b) for b in capability_delegation],
            "key_agreement": [bytes(b) for b in key_agreement],
            "services": [
                {
                    "id": bytes(svc[0]),
                    "service_type": svc[1],
                    "endpoint": svc[2],
                }
                for svc in services
            ],
            "doc_hash": bytes(doc_hash),
            "created_at": int(created_at),
            "updated_at": int(updated_at),
            "deactivated": bool(deactivated),
        }
