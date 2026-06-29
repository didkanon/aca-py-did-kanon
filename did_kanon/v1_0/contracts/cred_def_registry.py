"""KanonCredDefRegistry — credential definition registry client.

Binds a credDef to its schema + issuer public key and a `policyMask` of
supported revocation tiers (bit flags). A zero `createdAt` means "never
registered", which we map to None.
"""

from __future__ import annotations

import logging
from typing import Optional

from web3 import Web3
from web3.exceptions import ContractLogicError

from .abis import CREDENTIAL_DEFINITION_REGISTRY_ABI
from ._base import (
    Bytes32Like,
    RegistryClientError,
    RegistryTxClient,
    RegistryTxResult,
    _to_bytes,
    _to_bytes32,
)

LOGGER = logging.getLogger(__name__)

# policyMask bit flags — which revocation tiers a credDef supports.
TIER_ONE_TIME = 1
TIER_ZK_SNARK = 2
TIER_ALL = 3


class KanonCredDefRegistry(RegistryTxClient):
    """Write+read wrapper around the CredentialDefinitionRegistry contract."""

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
            CREDENTIAL_DEFINITION_REGISTRY_ABI,
            operator_key=operator_key,
            tx_timeout=tx_timeout,
        )

    # ────────────────────────────────────────────────────────────────
    # Writes
    # ────────────────────────────────────────────────────────────────

    async def register_credential_definition(
        self,
        cred_def_id: Bytes32Like,
        schema_id: Bytes32Like,
        issuer_pub_key: bytes,
        policy_mask: int,
        uri: str = "",
        issuer_zk_pub_key_ax: int = 0,
        issuer_zk_pub_key_ay: int = 0,
    ) -> RegistryTxResult:
        """Register a credential definition on-chain.

        The contract takes a single 7-arg call that handles BOTH Mode A
        (Tier 1, status-registry credentials) and Mode B (Tier 2, Groth16
        SNARK credentials) registration. The `issuer_zk_pub_key_ax/ay`
        pair is the BabyJubjub EdDSA public key the Mode B verifier
        binds against.

        For Mode A only (`policy_mask & TIER_ZK_SNARK == 0`) both
        coordinates MUST be `0` — the contract enforces this with
        `UnexpectedIssuerZkPubKey`. For Mode B the key MUST be a
        non-identity BN254 point — the contract enforces this with
        `InvalidIssuerZkPubKey`. Callers issuing Mode B credentials
        provision the key via `KanonZkIssuerKeyService.provision` first
        and pass the resulting `(ax, ay)` here.
        """
        return await self._send(
            "registerCredentialDefinition",
            _to_bytes32(cred_def_id, "cred_def_id"),
            _to_bytes32(schema_id, "schema_id"),
            _to_bytes(issuer_pub_key, "issuer_pub_key"),
            int(policy_mask),
            str(uri),
            int(issuer_zk_pub_key_ax),
            int(issuer_zk_pub_key_ay),
        )

    # ────────────────────────────────────────────────────────────────
    # Reads
    # ────────────────────────────────────────────────────────────────

    async def get_credential_definition(
        self, cred_def_id: Bytes32Like
    ) -> Optional[dict]:
        """CredDef record as a dict; None if never registered or revert."""
        cd = _to_bytes32(cred_def_id, "cred_def_id")
        try:
            raw = await self._read("getCredentialDefinition", cd)
        except RegistryClientError as err:
            if isinstance(err.__cause__, ContractLogicError):
                return None
            raise
        (
            schema_id,
            issuer_org,
            issuer_pub_key,
            policy_mask,
            created_at,
            deprecated,
            uri,
        ) = raw
        if int(created_at) == 0:
            return None
        return {
            "schema_id": bytes(schema_id),
            "issuer_org": "0x" + bytes(issuer_org).hex(),
            "issuer_pub_key": bytes(issuer_pub_key),
            "policy_mask": int(policy_mask),
            "created_at": int(created_at),
            "deprecated": bool(deprecated),
            "uri": str(uri),
        }

    async def exists(self, cred_def_id: Bytes32Like) -> bool:
        cd = _to_bytes32(cred_def_id, "cred_def_id")
        try:
            return bool(await self._read("exists", cd))
        except RegistryClientError as err:
            if isinstance(err.__cause__, ContractLogicError):
                return False
            raise

    async def is_active(self, cred_def_id: Bytes32Like) -> bool:
        cd = _to_bytes32(cred_def_id, "cred_def_id")
        try:
            return bool(await self._read("isActive", cd))
        except RegistryClientError as err:
            if isinstance(err.__cause__, ContractLogicError):
                return False
            raise

    async def supports_tier(self, cred_def_id: Bytes32Like, tier: int) -> bool:
        cd = _to_bytes32(cred_def_id, "cred_def_id")
        try:
            return bool(await self._read("supportsTier", cd, int(tier)))
        except RegistryClientError as err:
            if isinstance(err.__cause__, ContractLogicError):
                return False
            raise

    async def get_issuer_zk_pub_key(
        self, cred_def_id: Bytes32Like
    ) -> Optional[dict]:
        """Return the on-chain BabyJubjub Tier 2 issuer key, or None.

        Returns `{"ax": int, "ay": int, "set": bool}` for Mode B credDefs.
        `set == False` means no Tier 2 key has been published — verifiers
        MUST treat the credDef as Mode A only and reject SNARK proofs.
        Returns `None` for a non-existent credDef.
        """
        cd = _to_bytes32(cred_def_id, "cred_def_id")
        try:
            raw = await self._read("getIssuerZkPubKey", cd)
        except RegistryClientError as err:
            if isinstance(err.__cause__, ContractLogicError):
                return None
            raise
        ax, ay, is_set = raw
        return {"ax": int(ax), "ay": int(ay), "set": bool(is_set)}
