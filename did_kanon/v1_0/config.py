from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Optional


LOGGER = logging.getLogger(__name__)


# Network segment name used when KANON_NETWORK is unset. There are
# intentionally no defaults for rpc_url or the registry addresses —
# falling back silently could write to a stranger's contracts.
DEFAULT_NETWORK = "kanon"


# Logical registry key -> the contract name used in a deployment JSON
# (e.g. kanonv2/deployments/<chainId>.json `addresses`). All but the
# verifier registry are required for the plugin to operate.
REGISTRY_KEYS: dict[str, str] = {
    "org_registry": "OrganizationRegistry",
    "did_registry": "DIDRegistry",
    "schema_registry": "SchemaRegistry",
    "cred_def_registry": "CredentialDefinitionRegistry",
    "merkle_state_registry": "MerkleStateRegistry",
    "status_registry": "AnonCredsStatusRegistry",
    "verifier_registry": "Halo2VerifierRegistry",
}
_REQUIRED_KEYS = [k for k in REGISTRY_KEYS if k != "verifier_registry"]


class KanonConfigError(ValueError):
    """Raised when did:kanon configuration is missing or invalid."""


@dataclass
class KanonNetwork:
    """A single kanonv2 deployment the plugin can talk to. Multiple may
    coexist; the registrar/resolver dispatch by the `network` segment in
    the DID."""

    name: str
    rpc_url: str
    addresses: dict[str, str]
    chain_id: Optional[int] = None
    # Plain hex private-key string for the lifetime of the config object.
    # web3.py / eth_account.from_key keep the secret in plain bytes in the
    # Account object too, so wrapping this in a SecretStr would shift the
    # boundary without removing it. Treat the entire KanonNetwork as
    # sensitive: never log the dataclass repr or expose it on tenant
    # routes (see `kanon_list_networks` for the redaction pattern).
    operator_key: Optional[str] = None
    # On-chain KanonAddressBook directory. When set, the seven per-registry
    # addresses are resolved from it and the explicit `addresses` may be empty.
    address_book: Optional[str] = None
    # The organization this agent issues under (org-scoped issuer DID
    # `did:kanon:org:<issuer_org_id>`). The orgId is a bytes32 value encoded
    # as a 0x<64 hex> string. Required only for issuer flows.
    issuer_org_id: Optional[str] = None
    # Default `policyMask` for cred-defs registered against this network when
    # the AnonCreds caller doesn't pass one in `options`. Bit flags:
    #   1 (0b01) = TIER_ONE_TIME    Mode A status registry only
    #   2 (0b10) = TIER_ZK_SNARK    Mode B Merkle root only
    #   3 (0b11) = TIER_ALL         Both modes
    # Defaults to TIER_ONE_TIME so legacy cred-defs and existing CrMS flows
    # keep behaving the same.
    default_policy_mask: int = 1  # TIER_ONE_TIME

    def address(self, key: str) -> str:
        addr = self.addresses.get(key)
        if not addr:
            raise KanonConfigError(
                f"did:kanon: network {self.name!r} has no address for "
                f"{key!r} (set it via deployment file or "
                f"KANON_{key.upper()}_ADDRESS)"
            )
        return addr


def _addresses_from_mapping(src: dict) -> dict[str, str]:
    """Translate a {ContractName: address} mapping (a deployment file's
    `addresses` block) into {registry_key: address}."""
    name_to_key = {name: key for key, name in REGISTRY_KEYS.items()}
    out: dict[str, str] = {}
    for contract_name, addr in src.items():
        key = name_to_key.get(contract_name)
        if key and isinstance(addr, str) and addr.strip():
            out[key] = addr.strip()
    return out


def _load_deployment_file(path: str) -> dict[str, str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as err:
        raise KanonConfigError(
            f"did:kanon: cannot read deployment file {path!r}: {err}"
        ) from err
    block = data.get("addresses") if isinstance(data, dict) else None
    if not isinstance(block, dict):
        # Allow a bare {ContractName: address} mapping too.
        block = data if isinstance(data, dict) else {}
    return _addresses_from_mapping(block)


def _int_or_none(raw: Optional[str], what: str) -> Optional[int]:
    raw = (raw or "").strip() if isinstance(raw, str) else raw
    if raw in (None, ""):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError) as err:
        raise KanonConfigError(f"did:kanon: {what} must be an integer, got {raw!r}") from err


def _org_id_or_none(raw: Optional[str], what: str) -> Optional[str]:
    """An org id is a bytes32 value encoded as a 0x<64 hex> string."""
    raw = str(raw).strip() if raw is not None else None
    if raw in (None, ""):
        return None
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", raw):
        raise KanonConfigError(
            f"did:kanon: {what} must be a bytes32 hex string (0x<64 hex>), got {raw!r}"
        )
    return raw.lower()


# `policyMask` values accepted on chain — see
# `CredentialDefinitionRegistry.registerCredentialDefinition`.
_VALID_POLICY_MASKS = {1, 2, 3}


def _policy_mask_or_default(raw, fallback: int, what: str) -> int:
    """Parse a policyMask value (1 = TIER_ONE_TIME, 2 = TIER_ZK_SNARK,
    3 = TIER_ALL). Accepts int or a string of the above tokens (case-
    insensitive) so YAML can be written either way. Falls back to
    `fallback` (TIER_ONE_TIME) on missing input.
    """
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return fallback
    if isinstance(raw, str):
        token = raw.strip().upper()
        if token in {"1", "TIER_ONE_TIME", "ONE_TIME"}:
            return 1
        if token in {"2", "TIER_ZK_SNARK", "ZK_SNARK", "ZK"}:
            return 2
        if token in {"3", "TIER_ALL", "ALL"}:
            return 3
        raise KanonConfigError(
            f"did:kanon: {what} must be one of "
            "TIER_ONE_TIME (1), TIER_ZK_SNARK (2), TIER_ALL (3); "
            f"got {raw!r}"
        )
    if isinstance(raw, int) and raw in _VALID_POLICY_MASKS:
        return raw
    raise KanonConfigError(
        f"did:kanon: {what} must be one of {sorted(_VALID_POLICY_MASKS)}; got {raw!r}"
    )


@dataclass
class DidKanonConfig:
    """Plugin-wide config. `networks` is the source of truth.

    Each network needs an `rpc_url` and the kanonv2 registry addresses.
    Addresses come from a deployment JSON (`KANON_DEPLOYMENT_FILE` /
    `deployment_file:`) and/or per-registry overrides; the plugin fails
    closed if any required registry address is missing.
    """

    networks: dict[str, KanonNetwork] = field(default_factory=dict)
    default_network: str = ""

    @classmethod
    def from_environment(cls) -> "DidKanonConfig":
        """Build config from `KANON_*` env vars.

        Required:
            KANON_RPC_URL
            registry addresses — from `KANON_DEPLOYMENT_FILE` (a kanonv2
            deployments/<chainId>.json) and/or per-registry overrides
            `KANON_<REGISTRY_KEY>_ADDRESS`
            (e.g. KANON_DID_REGISTRY_ADDRESS).

        Optional:
            KANON_NETWORK       (default "kanon")
            KANON_OPERATOR_KEY  (required for write operations)
            KANON_CHAIN_ID
            KANON_ORG_ID        (issuer org id for did:kanon:org issuers)
        """
        network = os.getenv("KANON_NETWORK", DEFAULT_NETWORK).strip() or DEFAULT_NETWORK
        rpc = os.getenv("KANON_RPC_URL", "").strip()

        address_book = os.getenv("KANON_ADDRESS_BOOK", "").strip() or None

        addresses: dict[str, str] = {}
        dep_file = os.getenv("KANON_DEPLOYMENT_FILE", "").strip()
        if dep_file:
            addresses.update(_load_deployment_file(dep_file))
        for key in REGISTRY_KEYS:
            override = os.getenv(f"KANON_{key.upper()}_ADDRESS", "").strip()
            if override:
                addresses[key] = override

        cls._require(network, rpc, addresses, address_book)

        net = KanonNetwork(
            name=network,
            rpc_url=rpc,
            addresses=addresses,
            chain_id=_int_or_none(os.getenv("KANON_CHAIN_ID"), "KANON_CHAIN_ID"),
            operator_key=os.getenv("KANON_OPERATOR_KEY", "").strip() or None,
            issuer_org_id=_org_id_or_none(os.getenv("KANON_ORG_ID"), "KANON_ORG_ID"),
            address_book=address_book,
            default_policy_mask=_policy_mask_or_default(
                os.getenv("KANON_DEFAULT_POLICY_MASK"), 1, "KANON_DEFAULT_POLICY_MASK"
            ),
        )
        return cls(networks={network: net}, default_network=network)

    @classmethod
    def from_settings(cls, plugin_settings: dict) -> "DidKanonConfig":
        """Build config from `--plugin-config` YAML.

        Schema:
            did_kanon:
              default_network: kanon
              networks:
                kanon:
                  rpc_url: https://besu.essi.studio
                  chain_id: 1947
                  org_id: 1
                  operator_key: "0x..."     # or env KANON_OPERATOR_KEY_{NAME}
                  deployment_file: /path/to/1947.json   # and/or:
                  addresses:
                    did_registry: "0x..."
                    schema_registry: "0x..."
                    ...
        """
        if not plugin_settings:
            return cls.from_environment()

        default_network = plugin_settings.get("default_network", "")
        raw_networks = plugin_settings.get("networks") or {}
        networks: dict[str, KanonNetwork] = {}
        for name, cfg in raw_networks.items():
            rpc = (cfg.get("rpc_url") or "").strip()
            addresses: dict[str, str] = {}
            dep_file = (cfg.get("deployment_file") or "").strip()
            if dep_file:
                addresses.update(_load_deployment_file(dep_file))
            explicit = cfg.get("addresses") or {}
            for key in REGISTRY_KEYS:
                val = (explicit.get(key) or "").strip() if isinstance(explicit.get(key), str) else None
                if val:
                    addresses[key] = val

            address_book = (
                (cfg.get("address_book") or "").strip()
                if isinstance(cfg.get("address_book"), str)
                else None
            ) or None

            cls._require(name, rpc, addresses, address_book)

            operator_key = (
                (cfg.get("operator_key") or "").strip()
                or (os.getenv(f"KANON_OPERATOR_KEY_{name.upper()}") or "").strip()
                or None
            )
            networks[name] = KanonNetwork(
                name=name,
                rpc_url=rpc,
                addresses=addresses,
                chain_id=_int_or_none(cfg.get("chain_id"), f"network {name!r} chain_id"),
                operator_key=operator_key,
                issuer_org_id=_org_id_or_none(cfg.get("org_id"), f"network {name!r} org_id"),
                address_book=address_book,
                default_policy_mask=_policy_mask_or_default(
                    cfg.get("default_policy_mask"), 1, f"network {name!r} default_policy_mask"
                ),
            )

        if not networks:
            return cls.from_environment()
        if default_network not in networks:
            default_network = next(iter(networks))
        return cls(networks=networks, default_network=default_network)

    @staticmethod
    def _require(
        name: str,
        rpc: str,
        addresses: dict[str, str],
        address_book: Optional[str] = None,
    ) -> None:
        missing: list[str] = []
        if not rpc:
            missing.append("rpc_url")
        # An address book resolves all seven registries on-chain, so the
        # explicit per-registry addresses become optional when one is set.
        if not address_book:
            missing += [f"{k} address" for k in _REQUIRED_KEYS if not addresses.get(k)]
        if missing:
            raise KanonConfigError(
                f"did:kanon: network {name!r} missing required configuration: "
                + ", ".join(missing)
            )

    def network(self, name: Optional[str] = None) -> KanonNetwork:
        key = name or self.default_network
        if key not in self.networks:
            raise ValueError(
                f"did:kanon: unknown network {key!r}; configured: {list(self.networks)}"
            )
        return self.networks[key]
