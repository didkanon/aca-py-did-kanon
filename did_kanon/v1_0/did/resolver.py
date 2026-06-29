from __future__ import annotations

import logging
from re import Pattern
from typing import Optional, Sequence

from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.profile import Profile
from acapy_agent.resolver.base import (
    BaseDIDResolver,
    DIDNotFound,
    ResolverError,
    ResolverType,
)
from acapy_agent.wallet.util import bytes_to_b58

from did_kanon.v1_0.contracts._base import RegistryClientError
from did_kanon.v1_0.contracts.pool import KanonRegistryPool
from did_kanon.v1_0.identifiers import KANON_PREFIX_REGEX, parse_kanon_did

LOGGER = logging.getLogger(__name__)

# VerificationMethodType -> W3C type string (index = on-chain enum value).
_VM_TYPES = [
    "Ed25519VerificationKey2020",
    "EcdsaSecp256k1VerificationKey2019",
    "Bls12381G2Key2020",
    "JsonWebKey2020",
]

# on-chain relationship key -> W3C camelCase name.
_REL_KEYS = {
    "authentication": "authentication",
    "assertion_method": "assertionMethod",
    "capability_invocation": "capabilityInvocation",
    "capability_delegation": "capabilityDelegation",
    "key_agreement": "keyAgreement",
}


class KanonDIDResolver(BaseDIDResolver):
    """Resolve did:kanon DIDs from the kanonv2 DIDRegistry, rebuilding the
    W3C document from the on-chain struct."""

    def __init__(self, pool: KanonRegistryPool):
        super().__init__(ResolverType.NATIVE)
        self._pool = pool

    @property
    def supported_did_regex(self) -> Pattern:
        return KANON_PREFIX_REGEX

    async def setup(self, context: InjectionContext) -> None:  # noqa: D401
        """No-op — pool is constructed at plugin setup time."""

    async def _resolve(
        self,
        profile: Profile,
        did: str,
        service_accept: Optional[Sequence[str]] = None,
    ) -> dict:
        parsed = parse_kanon_did(did)
        if parsed is None:
            raise DIDNotFound(f"did:kanon: not a did:kanon DID: {did}")
        base_did = parsed.did

        try:
            registries = self._pool.for_did(base_did)
            doc = await registries.did.resolve_did(base_did)
        except RegistryClientError as err:
            LOGGER.exception("did:kanon: chain read failed for %s", base_did)
            raise ResolverError(f"failed to resolve {base_did}") from err
        except ValueError as err:
            raise DIDNotFound(str(err)) from err

        if doc is None:
            raise DIDNotFound(f"did:kanon: no DID document on chain for {base_did}")
        if doc.get("deactivated"):
            raise DIDNotFound(f"did:kanon: DID is deactivated: {base_did}")

        return self._to_w3c(base_did, doc)

    @staticmethod
    def _to_w3c(did: str, doc: dict) -> dict:
        vms = doc.get("verification_methods") or []
        # On-chain VM/service ids are keccak hashes (not reversible), so we
        # synthesize stable fragment ids by position and map relationship
        # references (bytes32) back to them.
        id_to_fragment: dict[bytes, str] = {}
        verification_method = []
        for i, vm in enumerate(vms):
            frag = f"{did}#key-{i + 1}"
            id_to_fragment[bytes(vm["id"])] = frag
            vm_type = _VM_TYPES[vm["vm_type"]] if vm["vm_type"] < len(_VM_TYPES) else "JsonWebKey2020"
            entry = {"id": frag, "type": vm_type, "controller": did}
            pk = bytes(vm["public_key"])
            if vm["vm_type"] == 0:  # Ed25519
                entry["publicKeyBase58"] = bytes_to_b58(pk)
            else:
                entry["publicKeyHex"] = pk.hex()
            verification_method.append(entry)

        def refs(key: str) -> list[str]:
            return [
                id_to_fragment[bytes(r)]
                for r in (doc.get(key) or [])
                if bytes(r) in id_to_fragment
            ]

        w3c: dict = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": did,
            "controller": did,
            "verificationMethod": verification_method,
        }
        for chain_key, w3c_key in _REL_KEYS.items():
            mapped = refs(chain_key)
            if mapped:
                w3c[w3c_key] = mapped

        services = doc.get("services") or []
        if services:
            w3c["service"] = [
                {
                    "id": f"{did}#service-{i + 1}",
                    "type": svc["service_type"],
                    "serviceEndpoint": svc["endpoint"],
                }
                for i, svc in enumerate(services)
            ]
        return w3c
