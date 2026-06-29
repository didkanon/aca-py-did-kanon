"""Smoke tests for the new kanonv2 contract ABI definitions."""

from did_kanon.v1_0.contracts.abis import (
    ANONCREDS_STATUS_REGISTRY_ABI,
    CREDENTIAL_DEFINITION_REGISTRY_ABI,
    DID_REGISTRY_ABI,
    HALO2_VERIFIER_REGISTRY_ABI,
    MERKLE_STATE_REGISTRY_ABI,
    ORGANIZATION_REGISTRY_ABI,
    SCHEMA_REGISTRY_ABI,
)


def _fn_names(abi):
    return {fn["name"] for fn in abi if fn.get("type") == "function"}


def _event_names(abi):
    return {ev["name"] for ev in abi if ev.get("type") == "event"}


def test_status_registry_has_required_methods():
    fns = _fn_names(ANONCREDS_STATUS_REGISTRY_ABI)
    assert {
        "issueCredential",
        "revokeCredential",
        "getStatus",
        "isRevoked",
        "isActive",
    } <= fns
    events = _event_names(ANONCREDS_STATUS_REGISTRY_ABI)
    assert {"CredentialIssued", "CredentialRevoked"} <= events


def test_status_registry_uses_bytes32_keys():
    issue = next(
        f
        for f in ANONCREDS_STATUS_REGISTRY_ABI
        if f.get("type") == "function" and f["name"] == "issueCredential"
    )
    assert [a["type"] for a in issue["inputs"]] == ["bytes32", "bytes32"]


def test_merkle_state_registry_has_zk_verify():
    fns = _fn_names(MERKLE_STATE_REGISTRY_ABI)
    assert "verifyZKMembership" in fns
    verify = next(
        f
        for f in MERKLE_STATE_REGISTRY_ABI
        if f.get("type") == "function" and f["name"] == "verifyZKMembership"
    )
    types = [a["type"] for a in verify["inputs"]]
    assert types == ["bytes32", "bytes", "bytes32[]"]
    assert verify["stateMutability"] == "view"  # gas-free RPC call


def test_other_registries_load():
    for abi in (
        CREDENTIAL_DEFINITION_REGISTRY_ABI,
        DID_REGISTRY_ABI,
        HALO2_VERIFIER_REGISTRY_ABI,
        ORGANIZATION_REGISTRY_ABI,
        SCHEMA_REGISTRY_ABI,
    ):
        assert isinstance(abi, list)
        assert len(abi) >= 1
