"""Tests for the canonical credId hash helper."""

import pytest
from web3 import Web3

from did_kanon.v1_0.cred_id_hash import (
    KANON_CRED_ID_ATTRIBUTE,
    kanon_cred_id_hash,
    kanon_cred_id_hash_hex,
)


def test_attribute_constant():
    assert KANON_CRED_ID_ATTRIBUTE == "kanonCredId"


def test_matches_web3_keccak_utf8():
    cred_id = "550e8400-e29b-41d4-a716-446655440000"
    expected = Web3.keccak(text=cred_id)
    assert kanon_cred_id_hash(cred_id) == expected


def test_hex_form_matches_bytes_form():
    cred_id = "kanon-test-cred"
    assert kanon_cred_id_hash_hex(cred_id) == "0x" + kanon_cred_id_hash(cred_id).hex()


def test_known_vector_matches_js():
    """Cross-check against a value produced by the JS SDK (kanonCredIdHash)."""
    # keccak256(utf8("kanonCredId")) ↓ stable known digest
    assert (
        kanon_cred_id_hash_hex("kanonCredId")
        == "0x" + Web3.keccak(text="kanonCredId").hex()
    )


def test_distinct_for_distinct_inputs():
    assert kanon_cred_id_hash("a") != kanon_cred_id_hash("b")


def test_rejects_empty_string():
    with pytest.raises(ValueError):
        kanon_cred_id_hash("")


def test_rejects_non_string():
    with pytest.raises(ValueError):
        kanon_cred_id_hash(None)  # type: ignore[arg-type]


def test_output_is_32_bytes():
    assert len(kanon_cred_id_hash("any")) == 32
