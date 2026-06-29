from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Optional

from acapy_agent.core.profile import Profile
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.key_type import ED25519
from acapy_agent.wallet.util import b58_to_bytes
from web3 import Web3

from did_kanon.v1_0.config import DidKanonConfig
from did_kanon.v1_0.contracts.pool import KanonRegistryPool
from did_kanon.v1_0.contracts._base import RegistryTxResult
from did_kanon.v1_0.did.did_method import KANON
from did_kanon.v1_0.identifiers import org_did, user_did

LOGGER = logging.getLogger(__name__)

# DIDScope enum (IDIDRegistry): User = 0, Org = 1.
_SCOPE_USER = 0
_SCOPE_ORG = 1
# VerificationMethodType.Ed25519VerificationKey2020 = 0.
_VM_ED25519 = 0
_ZERO32 = b"\x00" * 32

_MAX_SERVICES = 8
_MAX_SERVICES_BYTES = 4096


@dataclass
class RegisterDidResult:
    did: str
    verkey: str
    did_document: dict
    tx_hash: Optional[str]
    network: str


@dataclass
class ImportDidResult:
    """Wallet-store result for an existing on-chain DID.

    No tx_hash — import is wallet-only. The DID must already exist on
    chain or import raises ValueError. Caller is responsible for
    persisting `did` as the tenant's public DID.
    """

    did: str
    verkey: str
    network: str


def _validate_services(services: list) -> None:
    if not isinstance(services, list):
        raise ValueError("did:kanon: services must be a list")
    if len(services) > _MAX_SERVICES:
        raise ValueError(f"did:kanon: too many services (max {_MAX_SERVICES})")
    for idx, svc in enumerate(services):
        if not isinstance(svc, dict):
            raise ValueError(f"did:kanon: services[{idx}] must be an object")
        for field_name in ("id", "type", "serviceEndpoint"):
            value = svc.get(field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"did:kanon: services[{idx}].{field_name} must be a non-empty string"
                )
    if len(json.dumps(services)) > _MAX_SERVICES_BYTES:
        raise ValueError("did:kanon: services blob too large")


class KanonDIDRegistrar:
    """Mints + on-chain registers did:kanon DIDs against the kanonv2
    `DIDRegistry`. Issuer DIDs are org-scoped (`did:kanon:org:<orgId>`);
    holder DIDs are user-scoped (`did:kanon:user:0x<hash>`)."""

    def __init__(self, config: DidKanonConfig, pool: KanonRegistryPool):
        self._config = config
        self._pool = pool

    async def register(
        self,
        profile: Profile,
        *,
        network: Optional[str] = None,
        seed: Optional[str] = None,
        services: Optional[list[dict]] = None,
        scope: str = "org",
        org_id: Optional[str] = None,
    ) -> RegisterDidResult:
        net_cfg = self._config.network(network)
        registries = self._pool.for_network(network)
        controller = registries.operator_address
        if controller is None:
            raise ValueError(
                "did:kanon: no operator key configured; cannot register a DID"
            )
        if services is not None:
            _validate_services(services)

        if scope == "org":
            oid = org_id if org_id is not None else net_cfg.issuer_org_id
            if oid is None:
                raise ValueError(
                    "did:kanon: org-scoped DID needs an org id (set KANON_ORG_ID "
                    "or pass org_id)"
                )
            did = org_did(oid)
            # orgId is a bytes32 value encoded as a 0x<64 hex> string; web3
            # accepts the hex string directly for the bytes32 doc field.
            scope_enum, struct_org_id, salt = _SCOPE_ORG, oid, _ZERO32
        elif scope == "user":
            salt = os.urandom(32)
            handle = Web3.solidity_keccak(
                ["string", "address", "bytes32"],
                ["did:kanon:user:", Web3.to_checksum_address(controller), salt],
            )
            did = user_did("0x" + handle.hex())
            scope_enum, struct_org_id = _SCOPE_USER, _ZERO32
        else:
            raise ValueError(f"did:kanon: unknown scope {scope!r} (use 'org' or 'user')")

        async with profile.session() as session:
            wallet = session.inject(BaseWallet)
            key_info = await wallet.create_key(ED25519, seed=seed)
            verkey_b58 = key_info.verkey

        kid = did + "#key-1"
        vm_id = Web3.keccak(text=kid)
        public_key = b58_to_bytes(verkey_b58)

        did_document = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": did,
            "controller": did,
            "verificationMethod": [
                {
                    "id": kid,
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyBase58": verkey_b58,
                }
            ],
            "authentication": [kid],
            "assertionMethod": [kid],
        }
        if services:
            did_document["service"] = services

        doc_hash = Web3.keccak(
            text=json.dumps(did_document, sort_keys=True, separators=(",", ":"))
        )
        service_structs = [
            (Web3.keccak(text=svc["id"]), svc["type"], svc["serviceEndpoint"])
            for svc in (services or [])
        ]
        doc_struct = (
            Web3.to_checksum_address(controller),  # controller
            struct_org_id,                         # orgId
            scope_enum,                            # scope
            [(vm_id, _VM_ED25519, public_key)],    # verificationMethods
            [vm_id],                               # authentication
            [vm_id],                               # assertionMethod
            [],                                    # capabilityInvocation
            [],                                    # capabilityDelegation
            [],                                    # keyAgreement
            service_structs,                       # services
            doc_hash,                              # docHash
            0,                                     # createdAt (contract stamps)
            0,                                     # updatedAt
            False,                                 # deactivated
        )

        # Fail loudly: always attempt the on-chain registration and let any
        # contract revert (e.g. a duplicate DID) propagate so `create` fails
        # rather than masquerading a pre-existing DID as a fresh success.
        tx_hash: Optional[str] = None
        try:
            tx: RegistryTxResult = await registries.did.register_did(did, salt, doc_struct)
            tx_hash = tx.tx_hash
        except Exception:
            await self._attempt_orphan_key_cleanup(profile, verkey_b58, did)
            raise

        async with profile.session() as session:
            wallet = session.inject(BaseWallet)
            try:
                await wallet.assign_kid_to_key(verkey_b58, kid)
            except (AttributeError, NotImplementedError):
                LOGGER.debug("did:kanon: assign_kid_to_key not supported, skipping")
            except Exception:
                LOGGER.warning("did:kanon: assign_kid_to_key failed for %s", did, exc_info=True)
                raise

        await self._store_local_did(profile, did, net_cfg.name, verkey_b58, tx_hash)

        return RegisterDidResult(
            did=did,
            verkey=verkey_b58,
            did_document=did_document,
            tx_hash=tx_hash,
            network=net_cfg.name,
        )

    async def import_did(
        self,
        profile: Profile,
        *,
        seed: str,
        network: Optional[str] = None,
        scope: str = "org",
        org_id: Optional[str] = None,
    ) -> ImportDidResult:
        """Recover wallet ownership of an existing on-chain did:kanon.

        Derives the keypair from `seed`, looks up the DID on chain, and
        only stores the keypair in the wallet if the on-chain verkey
        matches. This guards against typos / wrong seeds silently
        installing a non-working keypair.

        Restricted to scope='org' for v1 — user-scoped DIDs need the
        random salt that was used at registration, which can't be
        recovered from the seed.
        """
        if not seed:
            raise ValueError("did:kanon: seed is required for import")
        if scope != "org":
            raise ValueError(
                "did:kanon: import only supports scope='org' "
                "(user-scoped DIDs need the original salt)"
            )

        net_cfg = self._config.network(network)
        registries = self._pool.for_network(network)

        oid = org_id if org_id is not None else net_cfg.issuer_org_id
        if oid is None:
            raise ValueError(
                "did:kanon: org-scoped DID needs an org id (set KANON_ORG_ID "
                "or pass org_id)"
            )
        did = org_did(oid)

        on_chain = await registries.did.resolve_did(did)
        if on_chain is None:
            raise ValueError(
                f"did:kanon: {did} is not registered on chain — "
                "use register instead of import"
            )

        async with profile.session() as session:
            wallet = session.inject(BaseWallet)
            key_info = await wallet.create_key(ED25519, seed=seed)
            verkey_b58 = key_info.verkey

        derived_pubkey = b58_to_bytes(verkey_b58)
        chain_pubkeys = {vm["public_key"] for vm in on_chain.get("verification_methods", [])}
        if derived_pubkey not in chain_pubkeys:
            # Wrong seed for this DID — refuse to install a keypair that
            # can't sign for the on-chain identity. Clean up the orphan key.
            await self._attempt_orphan_key_cleanup(profile, verkey_b58, did)
            raise ValueError(
                f"did:kanon: derived verkey does not match the on-chain "
                f"verkey for {did} (wrong seed?)"
            )

        kid = did + "#key-1"
        async with profile.session() as session:
            wallet = session.inject(BaseWallet)
            try:
                await wallet.assign_kid_to_key(verkey_b58, kid)
            except (AttributeError, NotImplementedError):
                LOGGER.debug("did:kanon: assign_kid_to_key not supported, skipping")
            except Exception:
                LOGGER.warning("did:kanon: assign_kid_to_key failed for %s", did, exc_info=True)
                raise

        # tx_hash is None — import doesn't write to chain.
        await self._store_local_did(profile, did, net_cfg.name, verkey_b58, None)

        return ImportDidResult(did=did, verkey=verkey_b58, network=net_cfg.name)

    async def _store_local_did(
        self, profile: Profile, did: str, network: str, verkey: str, tx_hash: Optional[str]
    ) -> None:
        from acapy_agent.wallet.error import WalletError

        try:
            from acapy_agent.wallet.error import WalletDuplicateError
        except ImportError:  # pragma: no cover
            WalletDuplicateError = None

        try:
            async with profile.session() as session:
                wallet = session.inject(BaseWallet)
                await wallet.create_local_did(
                    method=KANON,
                    key_type=ED25519,
                    seed=None,
                    did=did,
                    metadata={"network": network, "verkey": verkey, "tx_hash": tx_hash},
                )
        except Exception as err:
            if WalletDuplicateError is not None and isinstance(err, WalletDuplicateError):
                LOGGER.warning("did:kanon: local DID record already exists for %s", did)
            elif isinstance(err, WalletError) and "exist" in str(err).lower():
                LOGGER.warning("did:kanon: local DID record already exists for %s", did)
            else:
                raise

    async def _attempt_orphan_key_cleanup(
        self, profile: Profile, verkey: str, did: str
    ) -> None:
        try:
            async with profile.session() as session:
                wallet = session.inject(BaseWallet)
                remover = getattr(wallet, "remove_key", None) or getattr(wallet, "delete_key", None)
                if remover is None:
                    return
                await remover(verkey)
        except Exception:
            LOGGER.warning(
                "did:kanon: failed to clean up orphan key after registerDID failure for %s",
                did, exc_info=True,
            )
