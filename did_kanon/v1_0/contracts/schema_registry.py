"""KanonSchemaRegistry — AnonCreds schema registry client.

Register schema metadata (hash + URI) under an org and read it back. A
zero `createdAt` means "never registered", which we map to None.
"""

from __future__ import annotations

import logging
from typing import Optional

from web3 import Web3
from web3.exceptions import ContractLogicError

from .abis import SCHEMA_REGISTRY_ABI
from ._base import Bytes32Like, RegistryClientError, RegistryTxClient, RegistryTxResult, _to_bytes32

LOGGER = logging.getLogger(__name__)


class KanonSchemaRegistry(RegistryTxClient):
    """Write+read wrapper around the SchemaRegistry contract."""

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
            SCHEMA_REGISTRY_ABI,
            operator_key=operator_key,
            tx_timeout=tx_timeout,
        )

    # ────────────────────────────────────────────────────────────────
    # Writes
    # ────────────────────────────────────────────────────────────────

    async def register_schema(
        self,
        org_id: Bytes32Like,
        schema_id: Bytes32Like,
        schema_hash: Bytes32Like,
        uri: str,
    ) -> RegistryTxResult:
        return await self._send(
            "registerSchema",
            _to_bytes32(org_id, "org_id"),
            _to_bytes32(schema_id, "schema_id"),
            _to_bytes32(schema_hash, "schema_hash"),
            uri,
        )

    # ────────────────────────────────────────────────────────────────
    # Reads
    # ────────────────────────────────────────────────────────────────

    async def get_schema(self, schema_id: Bytes32Like) -> Optional[dict]:
        """Schema record as a dict; None if never registered or revert."""
        sid = _to_bytes32(schema_id, "schema_id")
        try:
            raw = await self._read("getSchema", sid)
        except RegistryClientError as err:
            if isinstance(err.__cause__, ContractLogicError):
                return None
            raise
        issuer_org, schema_hash, uri, created_at, deprecated = raw
        if int(created_at) == 0:
            return None
        return {
            "issuer_org": "0x" + bytes(issuer_org).hex(),
            "schema_hash": bytes(schema_hash),
            "uri": uri,
            "created_at": int(created_at),
            "deprecated": bool(deprecated),
        }

    async def is_active(self, schema_id: Bytes32Like) -> bool:
        sid = _to_bytes32(schema_id, "schema_id")
        try:
            return bool(await self._read("isActive", sid))
        except RegistryClientError as err:
            if isinstance(err.__cause__, ContractLogicError):
                return False
            raise

    async def exists(self, schema_id: Bytes32Like) -> bool:
        sid = _to_bytes32(schema_id, "schema_id")
        try:
            return bool(await self._read("exists", sid))
        except RegistryClientError as err:
            if isinstance(err.__cause__, ContractLogicError):
                return False
            raise
