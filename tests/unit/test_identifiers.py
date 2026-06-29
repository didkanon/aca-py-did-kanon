"""Unit tests for did:kanon URI parsing (kanonv2 org/user DID shapes)."""

import pytest

from did_kanon.v1_0.identifiers import (
    KANON_DID_REGEX,
    KANON_PREFIX_REGEX,
    cred_def_resource_id,
    org_did,
    parse_kanon_did,
    schema_resource_id,
    user_did,
)

_USER = "did:kanon:user:0x" + "ab" * 32
# orgId is a random bytes32 value encoded as 0x<64 hex>.
_ORG_HEX = "0x" + "cd" * 32
_ORG = f"did:kanon:org:{_ORG_HEX}"


def test_org_did():
    parsed = parse_kanon_did(_ORG)
    assert parsed is not None
    assert parsed.did == _ORG
    assert parsed.scope == "org"
    assert parsed.org_id == _ORG_HEX
    assert parsed.user_hex is None
    assert parsed.path is None


def test_user_did():
    parsed = parse_kanon_did(_USER)
    assert parsed is not None
    assert parsed.scope == "user"
    assert parsed.org_id is None
    assert parsed.user_hex == "0x" + "ab" * 32


def test_did_with_resource_path():
    parsed = parse_kanon_did(f"{_ORG}/anoncreds/v0/SCHEMA/Passport/1.0")
    assert parsed is not None
    assert parsed.did == _ORG
    assert parsed.scope == "org"
    assert parsed.path == "/anoncreds/v0/SCHEMA/Passport/1.0"


def test_did_with_fragment():
    parsed = parse_kanon_did(f"{_ORG}#key-1")
    assert parsed is not None
    assert parsed.fragment == "#key-1"


@pytest.mark.parametrize(
    "did",
    [
        "did:web:example.com",
        "did:key:z6Mk",
        "did:sov:abc",
        f"kanon:org:{_ORG_HEX}",
        "did:kanon:sepolia:abc",  # legacy free-form network form no longer valid
        "did:kanon:org:7",  # legacy decimal org id no longer valid
        "did:kanon:user:0xnothex",
    ],
)
def test_non_kanon_or_legacy_dids_dont_match(did):
    assert parse_kanon_did(did) is None


def test_prefix_regex_matches():
    assert KANON_PREFIX_REGEX.match(f"{_ORG}/anoncreds/v0/SCHEMA/x/1.0")
    assert KANON_PREFIX_REGEX.match(f"{_ORG}#frag")
    assert not KANON_PREFIX_REGEX.match("did:web:example")


def test_strict_did_regex_rejects_paths():
    assert KANON_DID_REGEX.match(_ORG)
    assert KANON_DID_REGEX.match(_USER)
    assert not KANON_DID_REGEX.match(f"{_ORG}/anoncreds/v0/SCHEMA/x/1.0")


def test_builders():
    assert org_did(_ORG_HEX) == _ORG
    assert user_did("ab" * 32) == _USER
    assert (
        schema_resource_id(_ORG, "Passport", "1.0")
        == f"{_ORG}/anoncreds/v0/SCHEMA/Passport/1.0"
    )
    assert (
        cred_def_resource_id(_ORG, "Passport", "default")
        == f"{_ORG}/anoncreds/v0/CLAIM_DEF/Passport/default"
    )
