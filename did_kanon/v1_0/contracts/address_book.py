"""KanonAddressBook — on-chain directory of the seven registry proxies.

A single contract returns all seven registry addresses, restoring the
single-address ergonomics: configure one `address_book` and resolve the rest
from it. Read-only; no operator key required.
"""

from __future__ import annotations

import logging

from web3 import Web3

from .abis import KANON_ADDRESS_BOOK_ABI
from ._base import RegistryTxClient

LOGGER = logging.getLogger(__name__)


# Order of the seven addresses in the book's `registries()` tuple, mapped to
# the plugin's logical registry keys.
_REGISTRIES_ORDER: tuple[str, ...] = (
    "org_registry",
    "did_registry",
    "schema_registry",
    "cred_def_registry",
    "merkle_state_registry",
    "status_registry",
    "verifier_registry",
)


class KanonAddressBook(RegistryTxClient):
    """Read wrapper around the KanonAddressBook directory contract."""

    def __init__(
        self,
        w3: Web3,
        address: str,
        *,
        tx_timeout: int = 60,
    ):
        super().__init__(
            w3,
            address,
            KANON_ADDRESS_BOOK_ABI,
            operator_key=None,
            tx_timeout=tx_timeout,
        )

    async def resolve(self) -> dict[str, str]:
        """Return the seven registry addresses keyed by the plugin's registry
        keys (org_registry, did_registry, schema_registry, cred_def_registry,
        merkle_state_registry, status_registry, verifier_registry)."""
        raw = await self._read("registries")
        return {
            key: Web3.to_checksum_address(raw[i])
            for i, key in enumerate(_REGISTRIES_ORDER)
        }

    def resolve_sync(self) -> dict[str, str]:
        """Synchronous variant of :meth:`resolve` for use in constructors."""
        raw = self._contract.functions["registries"]().call()
        return {
            key: Web3.to_checksum_address(raw[i])
            for i, key in enumerate(_REGISTRIES_ORDER)
        }
