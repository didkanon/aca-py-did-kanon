"""Tests for the Poseidon Merkle tree."""

import pytest

from did_kanon.v1_0.zk.merkle_poseidon import PoseidonMerkleTree
from did_kanon.v1_0.zk.poseidon import poseidon_hash


def test_known_two_input_poseidon_hash_stable():
    """Sanity — Poseidon over (1, 2) is a known stable value."""
    h = poseidon_hash([1, 2])
    assert isinstance(h, int)
    assert h > 0
    # Re-hash gives the same digest.
    assert poseidon_hash([1, 2]) == h


def test_single_leaf_round_trip():
    tree = PoseidonMerkleTree(depth=3, leaves=[42])
    proof = tree.proof_for_index(0)
    assert PoseidonMerkleTree.verify(42, proof, tree.root)


def test_many_leaves_round_trip():
    leaves = list(range(1, 9))  # 8 leaves at depth 3 — full tree
    tree = PoseidonMerkleTree(depth=3, leaves=leaves)
    for idx, leaf in enumerate(leaves):
        proof = tree.proof_for_index(idx)
        assert PoseidonMerkleTree.verify(leaf, proof, tree.root)


def test_tampered_proof_fails():
    leaves = [11, 22, 33, 44]
    tree = PoseidonMerkleTree(depth=2, leaves=leaves)
    proof = tree.proof_for_index(1)
    proof.path_elements[0] = 9999  # tamper
    assert not PoseidonMerkleTree.verify(22, proof, tree.root)


def test_index_out_of_range():
    tree = PoseidonMerkleTree(depth=2, leaves=[1, 2])
    with pytest.raises(ValueError):
        tree.proof_for_index(5)


def test_too_many_leaves_for_depth():
    with pytest.raises(ValueError):
        PoseidonMerkleTree(depth=2, leaves=list(range(5)))  # max 4 at depth 2


def test_root_changes_with_leaf_change():
    a = PoseidonMerkleTree(depth=2, leaves=[1, 2])
    b = PoseidonMerkleTree(depth=2, leaves=[1, 3])
    assert a.root != b.root
