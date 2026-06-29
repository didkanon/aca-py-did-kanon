"""KanonOrgRegistry — organization (issuer) registry client.

Orgs gate who can register schemas/credDefs. Register an org with an admin,
add members, and check membership / admin / approval status.
"""

from __future__ import annotations

import logging
from typing import Optional

from web3 import Web3
from web3.exceptions import ContractLogicError

from .abis import ORGANIZATION_REGISTRY_ABI
from ._base import (
    Bytes32Like,
    RegistryClientError,
    RegistryTxClient,
    RegistryTxResult,
    _to_bytes32,
)

LOGGER = logging.getLogger(__name__)


class KanonOrgRegistry(RegistryTxClient):
    """Write+read wrapper around the OrganizationRegistry contract."""

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
            ORGANIZATION_REGISTRY_ABI,
            operator_key=operator_key,
            tx_timeout=tx_timeout,
        )

    # ────────────────────────────────────────────────────────────────
    # Writes
    # ────────────────────────────────────────────────────────────────

    async def register_org(self, did: str, admin: str) -> RegistryTxResult:
        return await self._send(
            "registerOrg", did, Web3.to_checksum_address(admin)
        )

    async def register_org_and_get_id(self, did: str, admin: str) -> str:
        """Register an org and return its random bytes32 orgId (0x<64 hex>),
        decoded from the OrgRegistered event in the tx receipt."""
        tx = await self.register_org(did, admin)
        receipt = self._w3.eth.get_transaction_receipt(tx.tx_hash)
        for log in self._contract.events.OrgRegistered().process_receipt(receipt):
            return "0x" + bytes(log["args"]["orgId"]).hex()
        raise RegistryClientError("registerOrg: OrgRegistered event not found in receipt")

    async def add_member(self, org_id: Bytes32Like, member: str) -> RegistryTxResult:
        return await self._send(
            "addMember", _to_bytes32(org_id, "orgId"), Web3.to_checksum_address(member)
        )

    async def approve_org(self, org_id: Bytes32Like) -> RegistryTxResult:
        """Governance-only: approve a registered org (requires GOVERNANCE_ROLE)."""
        return await self._send("approveOrg", _to_bytes32(org_id, "orgId"))

    # ────────────────────────────────────────────────────────────────
    # Reads
    # ────────────────────────────────────────────────────────────────

    async def is_member(self, org_id: Bytes32Like, who: str) -> bool:
        try:
            return bool(
                await self._read(
                    "isMember", _to_bytes32(org_id, "orgId"), Web3.to_checksum_address(who)
                )
            )
        except RegistryClientError as err:
            if isinstance(err.__cause__, ContractLogicError):
                return False
            raise

    async def is_admin(self, org_id: Bytes32Like, who: str) -> bool:
        try:
            return bool(
                await self._read(
                    "isAdmin", _to_bytes32(org_id, "orgId"), Web3.to_checksum_address(who)
                )
            )
        except RegistryClientError as err:
            if isinstance(err.__cause__, ContractLogicError):
                return False
            raise

    async def is_approved_and_active(self, org_id: Bytes32Like) -> bool:
        try:
            return bool(
                await self._read(
                    "isApprovedAndActive", _to_bytes32(org_id, "orgId")
                )
            )
        except RegistryClientError as err:
            if isinstance(err.__cause__, ContractLogicError):
                return False
            raise
