"""Minimal ABIs for the seven kanonv2 contracts.

Only the methods + events the Python plugin needs are included; the full
ABIs live in the Solidity source at
`besi_blockchain/kanonv2/contracts/`.
"""

from __future__ import annotations

from typing import Any, Final

# ─────────────────────────────────────────────────────────────────────
# KanonAddressBook — on-chain directory of the seven registry proxies
# ─────────────────────────────────────────────────────────────────────

KANON_ADDRESS_BOOK_ABI: Final[list[dict[str, Any]]] = [
    {
        "type": "function",
        "name": "registries",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {"name": "organizationRegistry", "type": "address"},
                    {"name": "didRegistry", "type": "address"},
                    {"name": "schemaRegistry", "type": "address"},
                    {"name": "credentialDefinitionRegistry", "type": "address"},
                    {"name": "merkleStateRegistry", "type": "address"},
                    {"name": "anonCredsStatusRegistry", "type": "address"},
                    {"name": "halo2VerifierRegistry", "type": "address"},
                ],
            }
        ],
    },
    {
        "type": "function",
        "name": "organizationRegistry",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "address"}],
    },
    {
        "type": "function",
        "name": "didRegistry",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "address"}],
    },
    {
        "type": "function",
        "name": "schemaRegistry",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "address"}],
    },
    {
        "type": "function",
        "name": "credentialDefinitionRegistry",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "address"}],
    },
    {
        "type": "function",
        "name": "merkleStateRegistry",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "address"}],
    },
    {
        "type": "function",
        "name": "anonCredsStatusRegistry",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "address"}],
    },
    {
        "type": "function",
        "name": "halo2VerifierRegistry",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "address"}],
    },
]

# ─────────────────────────────────────────────────────────────────────
# AnonCredsStatusRegistry — per-credential issuance + revocation
# ─────────────────────────────────────────────────────────────────────

ANONCREDS_STATUS_REGISTRY_ABI: Final[list[dict[str, Any]]] = [
    {
        "type": "function",
        "name": "issueCredential",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "credDefId", "type": "bytes32"},
            {"name": "credIdHash", "type": "bytes32"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "revokeCredential",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "credDefId", "type": "bytes32"},
            {"name": "credIdHash", "type": "bytes32"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "getStatus",
        "stateMutability": "view",
        "inputs": [
            {"name": "credDefId", "type": "bytes32"},
            {"name": "credIdHash", "type": "bytes32"},
        ],
        # 0 Unknown, 1 Issued, 2 Revoked
        "outputs": [{"name": "", "type": "uint8"}],
    },
    {
        "type": "function",
        "name": "isRevoked",
        "stateMutability": "view",
        "inputs": [
            {"name": "credDefId", "type": "bytes32"},
            {"name": "credIdHash", "type": "bytes32"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "isActive",
        "stateMutability": "view",
        "inputs": [
            {"name": "credDefId", "type": "bytes32"},
            {"name": "credIdHash", "type": "bytes32"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "event",
        "name": "CredentialIssued",
        "anonymous": False,
        "inputs": [
            {"name": "credDefId", "type": "bytes32", "indexed": True},
            {"name": "credIdHash", "type": "bytes32", "indexed": True},
            {"name": "issuer", "type": "address", "indexed": True},
            {"name": "issuedAt", "type": "uint64", "indexed": False},
        ],
    },
    {
        "type": "event",
        "name": "CredentialRevoked",
        "anonymous": False,
        "inputs": [
            {"name": "credDefId", "type": "bytes32", "indexed": True},
            {"name": "credIdHash", "type": "bytes32", "indexed": True},
            {"name": "issuer", "type": "address", "indexed": True},
            {"name": "revokedAt", "type": "uint64", "indexed": False},
        ],
    },
]

# ─────────────────────────────────────────────────────────────────────
# MerkleStateRegistry — dual roots, Tier-1 nullifier, Tier-2 ZK
# ─────────────────────────────────────────────────────────────────────

MERKLE_STATE_REGISTRY_ABI: Final[list[dict[str, Any]]] = [
    {
        "type": "function",
        "name": "batchUpdate",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "credDefId", "type": "bytes32"},
            {"name": "addedLeavesKeccak", "type": "bytes32[]"},
            {"name": "addedLeavesPoseidon", "type": "bytes32[]"},
            {"name": "revokedLeavesKeccak", "type": "bytes32[]"},
            {"name": "revokedLeavesPoseidon", "type": "bytes32[]"},
            {"name": "newRootKeccak", "type": "bytes32"},
            {"name": "newRootPoseidon", "type": "bytes32"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "consumeOneTime",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "credDefId", "type": "bytes32"},
            {"name": "credId", "type": "bytes32"},
            {"name": "proof", "type": "bytes32[]"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "verifyZKMembership",
        "stateMutability": "view",
        "inputs": [
            {"name": "credDefId", "type": "bytes32"},
            {"name": "proof", "type": "bytes"},
            {"name": "publicSignals", "type": "bytes32[]"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "initializeCredDefState",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "credDefId", "type": "bytes32"},
            {"name": "initialKeccakRoot", "type": "bytes32"},
            {"name": "initialPoseidonRoot", "type": "bytes32"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "getState",
        "stateMutability": "view",
        "inputs": [{"name": "credDefId", "type": "bytes32"}],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {"name": "rootKeccak", "type": "bytes32"},
                    {"name": "rootPoseidon", "type": "bytes32"},
                    {"name": "epoch", "type": "uint64"},
                    {"name": "lastUpdated", "type": "uint64"},
                    {"name": "issuedCount", "type": "uint256"},
                    {"name": "revokedCount", "type": "uint256"},
                ],
            }
        ],
    },
    {
        "type": "function",
        "name": "isRecentKeccakRoot",
        "stateMutability": "view",
        "inputs": [
            {"name": "credDefId", "type": "bytes32"},
            {"name": "root", "type": "bytes32"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "isRecentPoseidonRoot",
        "stateMutability": "view",
        "inputs": [
            {"name": "credDefId", "type": "bytes32"},
            {"name": "root", "type": "bytes32"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "zkVerifierOf",
        "stateMutability": "view",
        "inputs": [{"name": "credDefId", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "address"}],
    },
    {
        "type": "function",
        "name": "isNullifierUsed",
        "stateMutability": "view",
        "inputs": [
            {"name": "credDefId", "type": "bytes32"},
            {"name": "nullifier", "type": "bytes32"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "event",
        "name": "CredentialAdded",
        "anonymous": False,
        "inputs": [
            {"name": "credDefId", "type": "bytes32", "indexed": True},
            {"name": "leafKeccak", "type": "bytes32", "indexed": False},
            {"name": "leafPoseidon", "type": "bytes32", "indexed": False},
        ],
    },
    {
        "type": "event",
        "name": "CredentialRevoked",
        "anonymous": False,
        "inputs": [
            {"name": "credDefId", "type": "bytes32", "indexed": True},
            {"name": "leafKeccak", "type": "bytes32", "indexed": False},
            {"name": "leafPoseidon", "type": "bytes32", "indexed": False},
        ],
    },
    {
        "type": "event",
        "name": "RootsUpdated",
        "anonymous": False,
        "inputs": [
            {"name": "credDefId", "type": "bytes32", "indexed": True},
            {"name": "epoch", "type": "uint64", "indexed": True},
            {"name": "newRootKeccak", "type": "bytes32", "indexed": False},
            {"name": "newRootPoseidon", "type": "bytes32", "indexed": False},
            {"name": "added", "type": "uint256", "indexed": False},
            {"name": "revoked", "type": "uint256", "indexed": False},
        ],
    },
]

# ─────────────────────────────────────────────────────────────────────
# OrganizationRegistry, DIDRegistry, SchemaRegistry,
# CredentialDefinitionRegistry, Halo2VerifierRegistry — minimal
# ─────────────────────────────────────────────────────────────────────

ORGANIZATION_REGISTRY_ABI: Final[list[dict[str, Any]]] = [
    {
        "type": "function",
        "name": "isApprovedAndActive",
        "stateMutability": "view",
        "inputs": [{"name": "orgId", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "isMember",
        "stateMutability": "view",
        "inputs": [
            {"name": "orgId", "type": "bytes32"},
            {"name": "who", "type": "address"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "isAdmin",
        "stateMutability": "view",
        "inputs": [
            {"name": "orgId", "type": "bytes32"},
            {"name": "who", "type": "address"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "registerOrg",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "did", "type": "string"},
            {"name": "admin", "type": "address"},
        ],
        "outputs": [{"name": "orgId", "type": "bytes32"}],
    },
    {
        "type": "function",
        "name": "addMember",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "orgId", "type": "bytes32"},
            {"name": "member", "type": "address"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "approveOrg",
        "stateMutability": "nonpayable",
        "inputs": [{"name": "orgId", "type": "bytes32"}],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "getOrg",
        "stateMutability": "view",
        "inputs": [{"name": "orgId", "type": "bytes32"}],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {"name": "did", "type": "string"},
                    {"name": "admin", "type": "address"},
                    {"name": "approved", "type": "bool"},
                    {"name": "suspended", "type": "bool"},
                    {"name": "createdAt", "type": "uint64"},
                    {"name": "approvedAt", "type": "uint64"},
                ],
            }
        ],
    },
    {
        "type": "event",
        "name": "OrgRegistered",
        "anonymous": False,
        "inputs": [
            {"name": "orgId", "type": "bytes32", "indexed": True},
            {"name": "did", "type": "string", "indexed": False},
            {"name": "admin", "type": "address", "indexed": True},
        ],
    },
]

# The DIDDocument struct stored on-chain (matches DIDRegistry.DIDDocument).
_DID_DOCUMENT_COMPONENTS: Final[list[dict[str, Any]]] = [
    {"name": "controller", "type": "address"},
    {"name": "orgId", "type": "bytes32"},
    {"name": "scope", "type": "uint8"},
    {
        "name": "verificationMethods",
        "type": "tuple[]",
        "components": [
            {"name": "id", "type": "bytes32"},
            {"name": "vmType", "type": "uint8"},
            {"name": "publicKey", "type": "bytes"},
        ],
    },
    {"name": "authentication", "type": "bytes32[]"},
    {"name": "assertionMethod", "type": "bytes32[]"},
    {"name": "capabilityInvocation", "type": "bytes32[]"},
    {"name": "capabilityDelegation", "type": "bytes32[]"},
    {"name": "keyAgreement", "type": "bytes32[]"},
    {
        "name": "services",
        "type": "tuple[]",
        "components": [
            {"name": "id", "type": "bytes32"},
            {"name": "serviceType", "type": "string"},
            {"name": "endpoint", "type": "string"},
        ],
    },
    {"name": "docHash", "type": "bytes32"},
    {"name": "createdAt", "type": "uint64"},
    {"name": "updatedAt", "type": "uint64"},
    {"name": "deactivated", "type": "bool"},
]

DID_REGISTRY_ABI: Final[list[dict[str, Any]]] = [
    {
        "type": "function",
        "name": "registerDID",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "did", "type": "string"},
            {"name": "salt", "type": "bytes32"},
            {"name": "doc", "type": "tuple", "components": _DID_DOCUMENT_COMPONENTS},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "updateDID",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "did", "type": "string"},
            {"name": "doc", "type": "tuple", "components": _DID_DOCUMENT_COMPONENTS},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "resolveDID",
        "stateMutability": "view",
        "inputs": [{"name": "did", "type": "string"}],
        "outputs": [{"name": "", "type": "tuple", "components": _DID_DOCUMENT_COMPONENTS}],
    },
    {
        "type": "function",
        "name": "deactivateDID",
        "stateMutability": "nonpayable",
        "inputs": [{"name": "did", "type": "string"}],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "exists",
        "stateMutability": "view",
        "inputs": [{"name": "did", "type": "string"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "isDeactivated",
        "stateMutability": "view",
        "inputs": [{"name": "did", "type": "string"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "controllerOf",
        "stateMutability": "view",
        "inputs": [{"name": "did", "type": "string"}],
        "outputs": [{"name": "", "type": "address"}],
    },
]

SCHEMA_REGISTRY_ABI: Final[list[dict[str, Any]]] = [
    {
        "type": "function",
        "name": "registerSchema",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "orgId", "type": "bytes32"},
            {"name": "schemaId", "type": "bytes32"},
            {"name": "schemaHash", "type": "bytes32"},
            {"name": "location", "type": "string"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "getSchema",
        "stateMutability": "view",
        "inputs": [{"name": "schemaId", "type": "bytes32"}],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {"name": "issuerOrg", "type": "bytes32"},
                    {"name": "schemaHash", "type": "bytes32"},
                    {"name": "uri", "type": "string"},
                    {"name": "createdAt", "type": "uint64"},
                    {"name": "deprecated", "type": "bool"},
                ],
            }
        ],
    },
    {
        "type": "function",
        "name": "exists",
        "stateMutability": "view",
        "inputs": [{"name": "schemaId", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "isActive",
        "stateMutability": "view",
        "inputs": [{"name": "schemaId", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
]

CREDENTIAL_DEFINITION_REGISTRY_ABI: Final[list[dict[str, Any]]] = [
    {
        "type": "function",
        "name": "registerCredentialDefinition",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "credDefId", "type": "bytes32"},
            {"name": "schemaId", "type": "bytes32"},
            {"name": "issuerPubKey", "type": "bytes"},
            {"name": "policyMask", "type": "uint8"},
            {"name": "uri", "type": "string"},
            # Tier-2 (Mode B) BabyJubjub EdDSA public key. MUST be (0, 0) when
            # `policyMask & TIER_ZK_SNARK == 0`; MUST be a non-identity BN254
            # point otherwise. The verifier of `non_revocation.circom` checks
            # `publicSignals[3..4] == (ax, ay)` to bind the SNARK to this
            # issuer.
            {"name": "issuerZkPubKeyAx", "type": "uint256"},
            {"name": "issuerZkPubKeyAy", "type": "uint256"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "exists",
        "stateMutability": "view",
        "inputs": [{"name": "credDefId", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "isActive",
        "stateMutability": "view",
        "inputs": [{"name": "credDefId", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "supportsTier",
        "stateMutability": "view",
        "inputs": [
            {"name": "credDefId", "type": "bytes32"},
            {"name": "tier", "type": "uint8"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "getCredentialDefinition",
        "stateMutability": "view",
        "inputs": [{"name": "credDefId", "type": "bytes32"}],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {"name": "schemaId", "type": "bytes32"},
                    {"name": "issuerOrg", "type": "bytes32"},
                    {"name": "issuerPubKey", "type": "bytes"},
                    {"name": "policyMask", "type": "uint8"},
                    {"name": "createdAt", "type": "uint64"},
                    {"name": "deprecated", "type": "bool"},
                    {"name": "uri", "type": "string"},
                ],
            }
        ],
    },
    {
        "type": "function",
        "name": "getIssuerZkPubKey",
        "stateMutability": "view",
        "inputs": [{"name": "credDefId", "type": "bytes32"}],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {"name": "ax", "type": "uint256"},
                    {"name": "ay", "type": "uint256"},
                    {"name": "set", "type": "bool"},
                ],
            }
        ],
    },
    {
        "type": "event",
        "name": "CredentialDefinitionRegistered",
        "anonymous": False,
        "inputs": [
            {"name": "credDefId", "type": "bytes32", "indexed": True},
            {"name": "schemaId", "type": "bytes32", "indexed": True},
            {"name": "issuerOrg", "type": "bytes32", "indexed": True},
            {"name": "policyMask", "type": "uint8", "indexed": False},
        ],
    },
    {
        "type": "event",
        "name": "IssuerZkPubKeySet",
        "anonymous": False,
        "inputs": [
            {"name": "credDefId", "type": "bytes32", "indexed": True},
            {"name": "ax", "type": "uint256", "indexed": False},
            {"name": "ay", "type": "uint256", "indexed": False},
        ],
    },
]

HALO2_VERIFIER_REGISTRY_ABI: Final[list[dict[str, Any]]] = [
    {
        "type": "function",
        "name": "verifierFor",
        "stateMutability": "view",
        "inputs": [{"name": "circuitVersion", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "address"}],
    },
]
