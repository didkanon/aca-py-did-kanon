"""Per-network aggregation of the kanonv2 registry clients.

Replaces the legacy single-contract `KanonClientPool`. One `KanonRegistries`
holds a shared web3 + operator key and a client for each deployed registry
(org, did, schema, credDef, merkle-state, status). `KanonRegistryPool` caches
one per configured network.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from web3 import Web3

from did_kanon.v1_0.config import DidKanonConfig, KanonNetwork
from did_kanon.v1_0.contracts.address_book import KanonAddressBook
from did_kanon.v1_0.contracts.cred_def_registry import KanonCredDefRegistry
from did_kanon.v1_0.contracts.did_registry import KanonDIDRegistry
from did_kanon.v1_0.contracts.merkle_state import KanonMerkleStateRegistry
from did_kanon.v1_0.contracts.org_registry import KanonOrgRegistry
from did_kanon.v1_0.contracts.schema_registry import KanonSchemaRegistry
from did_kanon.v1_0.contracts.status_registry import KanonAnonCredsStatusRegistry

LOGGER = logging.getLogger(__name__)


class KanonRegistriesError(Exception):
    """Construction-time failure (unreachable RPC, wrong chain, no code)."""


class KanonRegistries:
    """All kanonv2 registry clients for one network."""

    def __init__(self, net: KanonNetwork, *, verify_chain: bool = True):
        self._net = net
        self._w3 = Web3(Web3.HTTPProvider(net.rpc_url))
        key = net.operator_key

        # If only an address book is configured, resolve the seven registry
        # addresses from it on-chain; otherwise use the explicit addresses.
        if net.address_book and not net.addresses:
            resolved = KanonAddressBook(self._w3, net.address_book).resolve_sync()

            def _addr(k: str) -> str:
                return resolved[k]
        else:

            def _addr(k: str) -> str:
                return net.address(k)

        self.org = KanonOrgRegistry(self._w3, _addr("org_registry"), operator_key=key)
        self.did = KanonDIDRegistry(self._w3, _addr("did_registry"), operator_key=key)
        self.schema = KanonSchemaRegistry(self._w3, _addr("schema_registry"), operator_key=key)
        self.cred_def = KanonCredDefRegistry(
            self._w3, _addr("cred_def_registry"), operator_key=key
        )
        # Merkle-state is read-mostly for the holder/verifier paths.
        # Merkle-state needs the operator key for Mode B issuer writes
        # (batchUpdate). Reads work without one.
        self.merkle = KanonMerkleStateRegistry(
            self._w3, _addr("merkle_state_registry"), operator_key=key
        )
        self.status = KanonAnonCredsStatusRegistry(
            self._w3, _addr("status_registry"), operator_key=key
        )
        if verify_chain:
            self._verify_chain()

    @property
    def network(self) -> KanonNetwork:
        return self._net

    @property
    def network_name(self) -> str:
        return self._net.name

    @property
    def w3(self) -> Web3:
        return self._w3

    @property
    def operator_address(self) -> Optional[str]:
        return self.did.operator_address

    @property
    def issuer_org_id(self) -> Optional[int]:
        return self._net.issuer_org_id

    def _verify_chain(self) -> None:
        """Fail closed: reachable RPC, expected chain, and code at the DID
        registry — so a misconfig can't silently write to a stranger's chain."""
        try:
            code = self._w3.eth.get_code(self.did.address)
        except Exception as err:
            raise KanonRegistriesError(
                f"did:kanon: failed to reach RPC for network {self._net.name!r}"
            ) from err
        if not code or code in (b"", b"\x00"):
            raise KanonRegistriesError(
                f"did:kanon: no DIDRegistry bytecode at {self.did.address} on "
                f"network {self._net.name!r} — check the deployment addresses"
            )
        if self._net.chain_id is not None:
            try:
                on_chain = self._w3.eth.chain_id
            except Exception as err:
                raise KanonRegistriesError(
                    f"did:kanon: failed to read chain_id for {self._net.name!r}"
                ) from err
            if on_chain != self._net.chain_id:
                raise KanonRegistriesError(
                    f"did:kanon: chain_id mismatch on {self._net.name!r}: "
                    f"configured {self._net.chain_id}, RPC reports {on_chain}"
                )


class KanonRegistryPool:
    """Holds one `KanonRegistries` per configured network, keyed by name."""

    def __init__(self, config: DidKanonConfig):
        self._config = config
        self._cache: dict[str, KanonRegistries] = {}
        self._lock = asyncio.Lock()

    def for_network(self, name: Optional[str] = None) -> KanonRegistries:
        # Sync fast path. Two concurrent callers racing through this can
        # each construct a KanonRegistries (each opening a Web3 HTTPProvider
        # connection); `setdefault` then picks one winner and the loser is
        # GC'd, wasting that connection. Not a correctness bug — the
        # caller still gets a valid registry — and the rare double-build
        # only matters on the first call per network. Callers that need
        # the leak-free guarantee should use `for_network_async`, which
        # serialises construction through `self._lock`.
        net = self._config.network(name)
        reg = self._cache.get(net.name)
        if reg is None:
            reg = KanonRegistries(net)
            self._cache.setdefault(net.name, reg)
            reg = self._cache[net.name]
        return reg

    async def for_network_async(self, name: Optional[str] = None) -> KanonRegistries:
        net = self._config.network(name)
        reg = self._cache.get(net.name)
        if reg is not None:
            return reg
        async with self._lock:
            reg = self._cache.get(net.name)
            if reg is None:
                reg = KanonRegistries(net)
                self._cache[net.name] = reg
            return reg

    def for_did(self, did: str) -> KanonRegistries:
        """kanonv2 DIDs carry no network segment, so resolution dispatches to
        the configured default network."""
        return self.for_network(self._config.default_network)

    def network_config(self, name: Optional[str] = None) -> KanonNetwork:
        return self._config.network(name)
