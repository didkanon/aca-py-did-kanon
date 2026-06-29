"""kanonv2 contract ABIs + per-registry web3 clients.

Mirrors the seven-registry kanonv2 architecture (Solidity in
`besi_blockchain/kanonv2/contracts/`): organization, DID, schema,
credential-definition, merkle-state, AnonCreds status, and verifier
registries. `KanonRegistryPool` aggregates one client per registry per
configured network.
"""

from .abis import (
    ANONCREDS_STATUS_REGISTRY_ABI,
    CREDENTIAL_DEFINITION_REGISTRY_ABI,
    DID_REGISTRY_ABI,
    HALO2_VERIFIER_REGISTRY_ABI,
    MERKLE_STATE_REGISTRY_ABI,
    ORGANIZATION_REGISTRY_ABI,
    SCHEMA_REGISTRY_ABI,
)
from ._base import RegistryClientError, RegistryTxResult
from .cred_def_registry import (
    KanonCredDefRegistry,
    TIER_ALL,
    TIER_ONE_TIME,
    TIER_ZK_SNARK,
)
from .did_registry import KanonDIDRegistry
from .merkle_state import KanonMerkleStateRegistry
from .org_registry import KanonOrgRegistry
from .pool import KanonRegistries, KanonRegistryPool
from .schema_registry import KanonSchemaRegistry
from .status_registry import KanonAnonCredsStatusRegistry, StatusEnum

__all__ = [
    "ANONCREDS_STATUS_REGISTRY_ABI",
    "CREDENTIAL_DEFINITION_REGISTRY_ABI",
    "DID_REGISTRY_ABI",
    "HALO2_VERIFIER_REGISTRY_ABI",
    "MERKLE_STATE_REGISTRY_ABI",
    "ORGANIZATION_REGISTRY_ABI",
    "SCHEMA_REGISTRY_ABI",
    "RegistryClientError",
    "RegistryTxResult",
    "KanonCredDefRegistry",
    "TIER_ALL",
    "TIER_ONE_TIME",
    "TIER_ZK_SNARK",
    "KanonDIDRegistry",
    "KanonMerkleStateRegistry",
    "KanonOrgRegistry",
    "KanonRegistries",
    "KanonRegistryPool",
    "KanonSchemaRegistry",
    "KanonAnonCredsStatusRegistry",
    "StatusEnum",
]
