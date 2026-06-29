"""Unit tests for DidKanonConfig env / settings parsing (multi-registry)."""

import json

import pytest

from did_kanon.v1_0.config import (
    DEFAULT_NETWORK,
    REGISTRY_KEYS,
    DidKanonConfig,
    KanonConfigError,
)


_REQUIRED = [k for k in REGISTRY_KEYS if k != "verifier_registry"]

# Deployment-file shape (mirrors kanonv2/deployments/<chainId>.json).
_DEPLOYMENT = {
    "chainId": 1947,
    "addresses": {
        "OrganizationRegistry": "0x" + "1" * 40,
        "DIDRegistry": "0x" + "2" * 40,
        "SchemaRegistry": "0x" + "3" * 40,
        "CredentialDefinitionRegistry": "0x" + "4" * 40,
        "MerkleStateRegistry": "0x" + "5" * 40,
        "AnonCredsStatusRegistry": "0x" + "6" * 40,
        "Halo2VerifierRegistry": "0x" + "7" * 40,
    },
}

_ALL_ENVS = (
    "KANON_NETWORK",
    "KANON_RPC_URL",
    "KANON_CHAIN_ID",
    "KANON_OPERATOR_KEY",
    "KANON_ORG_ID",
    "KANON_DEPLOYMENT_FILE",
) + tuple(f"KANON_{k.upper()}_ADDRESS" for k in REGISTRY_KEYS)


def _clear(monkeypatch):
    for var in _ALL_ENVS:
        monkeypatch.delenv(var, raising=False)


def _write_deployment(tmp_path):
    path = tmp_path / "1947.json"
    path.write_text(json.dumps(_DEPLOYMENT))
    return str(path)


def test_env_missing_required_raises(monkeypatch):
    _clear(monkeypatch)
    with pytest.raises(KanonConfigError) as exc:
        DidKanonConfig.from_environment()
    msg = str(exc.value)
    assert "rpc_url" in msg
    assert "did_registry address" in msg


def test_env_from_deployment_file(monkeypatch, tmp_path):
    _clear(monkeypatch)
    monkeypatch.setenv("KANON_RPC_URL", "https://besu.essi.studio")
    monkeypatch.setenv("KANON_CHAIN_ID", "1947")
    monkeypatch.setenv("KANON_ORG_ID", "0x" + "3" * 64)
    monkeypatch.setenv("KANON_DEPLOYMENT_FILE", _write_deployment(tmp_path))
    cfg = DidKanonConfig.from_environment()
    assert cfg.default_network == DEFAULT_NETWORK
    net = cfg.network()
    assert net.chain_id == 1947
    assert net.issuer_org_id == "0x" + "3" * 64
    assert net.address("did_registry") == "0x" + "2" * 40
    assert net.address("status_registry") == "0x" + "6" * 40
    for key in _REQUIRED:
        assert net.address(key)


def test_env_per_registry_override(monkeypatch, tmp_path):
    _clear(monkeypatch)
    monkeypatch.setenv("KANON_RPC_URL", "http://besu:8545")
    monkeypatch.setenv("KANON_DEPLOYMENT_FILE", _write_deployment(tmp_path))
    monkeypatch.setenv("KANON_DID_REGISTRY_ADDRESS", "0x" + "a" * 40)
    cfg = DidKanonConfig.from_environment()
    assert cfg.network().address("did_registry") == "0x" + "a" * 40


def test_settings_multinetwork():
    addrs = {k: _DEPLOYMENT["addresses"][name] for k, name in REGISTRY_KEYS.items()}
    settings = {
        "default_network": "besu",
        "networks": {
            "besu": {
                "rpc_url": "http://besu:8545",
                "chain_id": 1947,
                "operator_key": "0xkey",
                "org_id": "0x" + "5" * 64,
                "addresses": addrs,
            },
        },
    }
    cfg = DidKanonConfig.from_settings(settings)
    assert cfg.default_network == "besu"
    net = cfg.network("besu")
    assert net.operator_key == "0xkey"
    assert net.issuer_org_id == "0x" + "5" * 64
    assert net.address("schema_registry") == "0x" + "3" * 40


def test_settings_missing_address_raises():
    settings = {
        "networks": {
            "besu": {"rpc_url": "http://besu:8545", "addresses": {"did_registry": "0xabc"}}
        }
    }
    with pytest.raises(KanonConfigError):
        DidKanonConfig.from_settings(settings)
