"""OpenZeppelin-style standard Merkle tree (keccak256 + sorted pairs).

Bit-for-bit compatible with OZ MerkleProof.verify on-chain, so a proof
generated here verifies inside Solidity (`MerkleProof.verifyCalldata`)
without further fiddling.

Leaves are hashed twice (Tier-1 spec: `leaf = keccak256(keccak256(credId))`).
The caller passes raw leaves (32 bytes each); the tree itself doesn't
double-hash — callers prepare the leaves to match.
"""

from __future__ import annotations

from typing import List

from web3 import Web3


def _keccak(*chunks: bytes) -> bytes:
    return Web3.keccak(b"".join(chunks))


def _hash_pair(a: bytes, b: bytes) -> bytes:
    """OZ sorted-pair hash — matches `MerkleProof._hashPair`."""
    return _keccak(a + b) if a < b else _keccak(b + a)


class OZStandardMerkleTree:
    """Build a binary Merkle tree over 32-byte leaves; compute root + proofs.

    The tree's leaves and internal nodes are bytes32. A leaf list of size
    N produces a tree of depth ⌈log2 N⌉; the root is `[]` when N == 0
    (caller's responsibility to avoid empty trees in production).
    """

    def __init__(self, leaves: List[bytes]):
        for i, leaf in enumerate(leaves):
            if not isinstance(leaf, (bytes, bytearray)) or len(leaf) != 32:
                raise ValueError(f"leaves[{i}] must be exactly 32 bytes")
        # Stable copy
        self._leaves: List[bytes] = [bytes(leaf) for leaf in leaves]
        self._layers: List[List[bytes]] = self._build_layers(self._leaves)

    @property
    def leaves(self) -> List[bytes]:
        return list(self._leaves)

    @property
    def root(self) -> bytes:
        if not self._layers:
            return b"\x00" * 32
        return self._layers[-1][0]

    def proof_for(self, leaf: bytes) -> List[bytes]:
        """Return the proof path for `leaf` — the sibling-at-each-level list.

        Raises ValueError if the leaf isn't in the tree.
        """
        try:
            idx = self._leaves.index(leaf)
        except ValueError as err:
            raise ValueError("leaf not in tree") from err
        return self.proof_for_index(idx)

    def proof_for_index(self, idx: int) -> List[bytes]:
        proof: List[bytes] = []
        for layer in self._layers[:-1]:
            sibling_idx = idx ^ 1
            if sibling_idx < len(layer):
                proof.append(layer[sibling_idx])
            idx //= 2
        return proof

    @staticmethod
    def verify(leaf: bytes, proof: List[bytes], root: bytes) -> bool:
        """OZ MerkleProof.verify, in Python."""
        if not isinstance(leaf, (bytes, bytearray)) or len(leaf) != 32:
            return False
        if not isinstance(root, (bytes, bytearray)) or len(root) != 32:
            return False
        computed = bytes(leaf)
        for sib in proof:
            if not isinstance(sib, (bytes, bytearray)) or len(sib) != 32:
                return False
            computed = _hash_pair(computed, bytes(sib))
        return computed == bytes(root)

    # ────────────────────────────────────────────────────────────────
    # Internal
    # ────────────────────────────────────────────────────────────────

    @staticmethod
    def _build_layers(leaves: List[bytes]) -> List[List[bytes]]:
        if not leaves:
            return []
        layers: List[List[bytes]] = [leaves]
        while len(layers[-1]) > 1:
            cur = layers[-1]
            nxt: List[bytes] = []
            i = 0
            while i < len(cur):
                if i + 1 < len(cur):
                    nxt.append(_hash_pair(cur[i], cur[i + 1]))
                else:
                    # OZ "odd leaf" handling — promote upward unchanged.
                    nxt.append(cur[i])
                i += 2
            layers.append(nxt)
        return layers
