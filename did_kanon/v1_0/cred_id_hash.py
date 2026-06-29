"""Canonical credId hashing — matches @ajna-inc/kanon-sdk/anoncreds.

The Kanon AnonCredsStatusRegistry stores per-credential status keyed by
`bytes32 credIdHash`. Issuer (at issuance), verifier (at lookup), and any
side that derives a status key MUST use this exact function so the 32-byte
hashes line up across the JS SDK, the Solidity contract, and this Python
plugin.
"""

from __future__ import annotations

from web3 import Web3

KANON_CRED_ID_ATTRIBUTE = "kanonCredId"


def kanon_cred_id_hash(cred_id: str) -> bytes:
    """Return the canonical 32-byte keccak256 digest of `utf8(cred_id)`.

    Matches:
      JS:   keccak256(toUtf8Bytes(credId))
      Sol:  keccak256(bytes(credId))   (when called with abi-encoded string)
    """
    if not isinstance(cred_id, str) or len(cred_id) == 0:
        raise ValueError("kanon_cred_id_hash: cred_id must be a non-empty string")
    return Web3.keccak(text=cred_id)


def kanon_cred_id_hash_hex(cred_id: str) -> str:
    """Hex-prefixed variant for callers that want '0x…' strings."""
    return "0x" + kanon_cred_id_hash(cred_id).hex()
