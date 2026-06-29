"""Tests for the Circom witness calculator (real circuit WASM)."""

from pathlib import Path

import pytest

from did_kanon.v1_0.zk.witness import (
    WitnessCalculator,
    WitnessCalculatorError,
    _fnv_hash,
)

WASM_PATH = Path(__file__).parent.parent / "data" / "non_revocation.wasm"


def test_fnv_hash_known_vector():
    # FNV-1a of "" is the offset basis.
    assert _fnv_hash("") == 0xCBF29CE484222325


def test_fnv_hash_distinct_for_distinct_inputs():
    assert _fnv_hash("root") != _fnv_hash("credDefId")


@pytest.mark.skipif(not WASM_PATH.exists(), reason="non_revocation.wasm not available")
def test_witness_calculator_initializes():
    calc = WitnessCalculator(WASM_PATH)
    # BN254 scalar field prime.
    assert (
        calc.prime
        == 21888242871839275222246405745257275088548364400416034343698204186575808495617
    )
    assert calc.witness_size > 0


@pytest.mark.skipif(not WASM_PATH.exists(), reason="non_revocation.wasm not available")
def test_witness_calculator_missing_signal_raises():
    calc = WitnessCalculator(WASM_PATH)
    # Missing all expected inputs.
    with pytest.raises(WitnessCalculatorError):
        calc.calculate_witness({"notARealSignal": 1})
