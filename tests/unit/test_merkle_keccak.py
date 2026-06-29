"""Tests for the OZ-compatible standard Merkle tree."""

import pytest
from web3 import Web3

from did_kanon.v1_0.zk.merkle_keccak import OZStandardMerkleTree


def _leaf(name: str) -> bytes:
    return Web3.keccak(text=name)


def test_single_leaf_root_is_the_leaf():
    leaf = _leaf("only")
    tree = OZStandardMerkleTree([leaf])
    assert tree.root == leaf


def test_round_trip_proof_verifies():
    leaves = [_leaf(f"cred-{i}") for i in range(8)]
    tree = OZStandardMerkleTree(leaves)
    for idx, leaf in enumerate(leaves):
        proof = tree.proof_for_index(idx)
        assert OZStandardMerkleTree.verify(leaf, proof, tree.root)


def test_proof_for_missing_leaf_raises():
    tree = OZStandardMerkleTree([_leaf("a"), _leaf("b")])
    with pytest.raises(ValueError):
        tree.proof_for(_leaf("c"))


def test_tampered_proof_fails():
    leaves = [_leaf(f"x-{i}") for i in range(4)]
    tree = OZStandardMerkleTree(leaves)
    proof = tree.proof_for_index(0)
    proof[0] = b"\x00" * 32  # tamper
    assert not OZStandardMerkleTree.verify(leaves[0], proof, tree.root)


def test_odd_count_handled():
    # 3 leaves — OZ's tree promotes the odd leaf upward unchanged.
    leaves = [_leaf("p"), _leaf("q"), _leaf("r")]
    tree = OZStandardMerkleTree(leaves)
    for idx, leaf in enumerate(leaves):
        proof = tree.proof_for_index(idx)
        assert OZStandardMerkleTree.verify(leaf, proof, tree.root)


def test_rejects_wrong_size_leaf():
    with pytest.raises(ValueError):
        OZStandardMerkleTree([b"\x00" * 20])  # 20 bytes, not 32
