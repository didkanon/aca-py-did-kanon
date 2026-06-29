"""Tests for the pure-Python Groth16 verifier."""

import json
from pathlib import Path

import pytest

from did_kanon.v1_0.zk.groth16_verifier import (
    Groth16OffChainVerifier,
    Groth16VerifyError,
)

VK_PATH = Path(__file__).parent.parent / "data" / "non_revocation_vk.json"


@pytest.mark.skipif(not VK_PATH.exists(), reason="vk fixture missing")
def test_loads_vk_from_file():
    verifier = Groth16OffChainVerifier.from_file(VK_PATH)
    assert verifier is not None


@pytest.mark.skipif(not VK_PATH.exists(), reason="vk fixture missing")
def test_rejects_wrong_protocol():
    with open(VK_PATH, "r", encoding="utf-8") as f:
        vk = json.load(f)
    vk["protocol"] = "plonk"
    with pytest.raises(Groth16VerifyError):
        Groth16OffChainVerifier(vk)


@pytest.mark.skipif(not VK_PATH.exists(), reason="vk fixture missing")
def test_rejects_wrong_curve():
    with open(VK_PATH, "r", encoding="utf-8") as f:
        vk = json.load(f)
    vk["curve"] = "bls12-381"
    with pytest.raises(Groth16VerifyError):
        Groth16OffChainVerifier(vk)


@pytest.mark.skipif(not VK_PATH.exists(), reason="vk fixture missing")
def test_signals_must_match_public_count():
    verifier = Groth16OffChainVerifier.from_file(VK_PATH)
    # A dummy proof — verify will reject before touching the math because
    # the signal count is wrong.
    dummy_proof = {
        "pi_a": ["1", "2", "1"],
        "pi_b": [["1", "0"], ["0", "0"], ["1", "0"]],
        "pi_c": ["1", "2", "1"],
    }
    with pytest.raises(Groth16VerifyError):
        verifier.verify(dummy_proof, [0])  # nPublic is 7
