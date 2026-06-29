"""Fixed-depth Poseidon Merkle tree matching the Kanon non_revocation circuit.

Mirrors `kanonv2/sdk/src/zk/poseidonTree.ts` so a leaf inserted here
yields the same root + proof as the JS side, and the resulting proof
verifies inside the Circom `non_revocation` circuit.

Differences from the standard OZ tree:
  - 3-input Poseidon hash with a `NODE_TAG=2` domain-separation tag —
    matches `non_revocation.circom`'s `MerkleInclusion` template
    (`Poseidon(NODE_TAG, left, right)`).
  - Left / right ordering is preserved (no sorted-pair trick).
  - Fixed depth with a zero-leaf padding value.
  - Proofs carry `(pathElements, pathIndices)` — needed by the circuit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .poseidon import BN254_PRIME, poseidon_hash


# Domain-separation tag — MUST stay in sync with `non_revocation.circom`:
#   var NODE_TAG = 2;   (declared in template MerkleInclusion)
# Tags prevent any internal node value from being structurally
# interpretable as a leaf (`LEAF_TAG=1`) and vice versa. Changing this
# value silently breaks every existing proof.
NODE_TAG: int = 2


def _hash_node(left: int, right: int) -> int:
    """Compute the parent of two Merkle children with the tagged Poseidon
    hash. Equivalent to the circuit's
        `Poseidon(NODE_TAG, left, right)`.
    """
    return poseidon_hash([NODE_TAG, int(left) % BN254_PRIME, int(right) % BN254_PRIME])


@dataclass
class PoseidonProof:
    path_elements: List[int]
    path_indices: List[int]


class PoseidonMerkleTree:
    """Sparse fixed-depth Poseidon tree over BN254 scalars.

    Mirrors `kanonv2/sdk/src/zk/poseidonTree.ts` — empty subtrees are
    represented by precomputed zero hashes per level, so building a
    depth-26 tree over a handful of credentials is O(leaves × depth)
    instead of O(2^depth) ≈ 67M ops the dense layout would require.

    The dense layout that previously lived here was an actual blocker —
    every issuance would hang the listener for minutes (or run out of
    memory) trying to materialise the full padded leaf array. With this
    sparse layout, depth-26 with a single leaf costs 26 hashes.

    Uses the same tagged hash as the circuit's `MerkleInclusion` so a leaf
    inserted here yields the root the SNARK verifier accepts.
    """

    def __init__(self, depth: int, leaves: List[int]):
        if depth < 1:
            raise ValueError("depth must be >= 1")
        max_leaves = 1 << depth
        if len(leaves) > max_leaves:
            raise ValueError(
                f"too many leaves ({len(leaves)}) for depth {depth} (max {max_leaves})"
            )
        self._depth = depth
        self._leaves: List[int] = [int(leaf) % BN254_PRIME for leaf in leaves]
        # Precompute the zero-subtree hash for each level. `zeros[0] = 0`
        # (an empty leaf), `zeros[d] = H(zeros[d-1], zeros[d-1])`. Lets us
        # answer "what's the value of an entirely empty subtree at level d"
        # in O(1) without ever materialising the dense layout.
        self._zeros: List[int] = [0] * (depth + 1)
        for d in range(1, depth + 1):
            self._zeros[d] = _hash_node(self._zeros[d - 1], self._zeros[d - 1])
        # Per-level sparse maps `{index → value}`. Missing indices fall back
        # to `self._zeros[level]`.
        self._nodes: List[Dict[int, int]] = [
            {} for _ in range(depth + 1)
        ]
        for i, leaf in enumerate(self._leaves):
            self._insert(i, leaf)

    @property
    def depth(self) -> int:
        return self._depth

    @property
    def leaves(self) -> List[int]:
        return list(self._leaves)

    @property
    def root(self) -> int:
        return self._node_at(self._depth, 0)

    def proof_for_index(self, idx: int) -> PoseidonProof:
        if idx < 0 or idx >= (1 << self._depth):
            raise ValueError(f"leaf index {idx} out of range for depth {self._depth}")
        path_elements: List[int] = []
        path_indices: List[int] = []
        cur = idx
        for d in range(self._depth):
            is_right = cur & 1
            sib_idx = cur - 1 if is_right else cur + 1
            path_elements.append(self._node_at(d, sib_idx))
            path_indices.append(is_right)
            cur //= 2
        return PoseidonProof(path_elements=path_elements, path_indices=path_indices)

    @staticmethod
    def verify(leaf: int, proof: PoseidonProof, root: int) -> bool:
        if len(proof.path_elements) != len(proof.path_indices):
            return False
        cur = int(leaf) % BN254_PRIME
        for sib, side in zip(proof.path_elements, proof.path_indices):
            sib = int(sib) % BN254_PRIME
            # `side` is the current-node's index bit — 0 = current is the left
            # child (sibling is right), 1 = current is the right child.
            if side == 0:
                cur = _hash_node(cur, sib)
            else:
                cur = _hash_node(sib, cur)
        return cur == int(root) % BN254_PRIME

    # ────────────────────────────────────────────────────────────────
    # Internal
    # ────────────────────────────────────────────────────────────────

    def _node_at(self, level: int, index: int) -> int:
        v = self._nodes[level].get(index)
        return v if v is not None else self._zeros[level]

    def _insert(self, leaf_index: int, value: int) -> None:
        self._nodes[0][leaf_index] = int(value) % BN254_PRIME
        idx = leaf_index
        for level in range(self._depth):
            is_right = idx & 1
            left = (
                self._node_at(level, idx - 1) if is_right else self._node_at(level, idx)
            )
            right = (
                self._node_at(level, idx) if is_right else self._node_at(level, idx + 1)
            )
            idx //= 2
            self._nodes[level + 1][idx] = _hash_node(left, right)
