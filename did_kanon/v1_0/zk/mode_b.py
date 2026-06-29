"""Mode B credential preparation — issuer-side leaf + BJJ signature injection.

Mirrors `KanonZkApi.prepareModeBCredential` in the credo-ts v6 plugin. The
caller (CrMS UI, an admin route, or any orchestrator on top of ACA-Py)
hands in `{credDefId, domainAttributes}` and gets back the FULL attribute
set the AnonCreds issuance flow should sign, plus the generated kanon
identifiers.

  Input:
    credDefId           bytes32 of the on-chain credDef
    domainAttributes    arbitrary {name: value} the credential carries
                        (e.g. {studentId: "S12345", name: "Alice"}).
                        MUST NOT include reserved names.

  Output:
    attributes          dict suitable as the AnonCreds preview value set —
                        domain attrs first, then `kanonCredId` and
                        `kanonZkSig`. The schema's attrNames MUST list
                        the reserved names in that exact order, last.
    kanon_cred_id       the freshly-minted 32-byte (hex) bookkeeping id;
                        the issuer publishes its keccak leaf for Mode A
                        and its Poseidon leaf for Mode B.
    kanon_zk_sig        BJJ-EdDSA signature over the Mode B leaf, base64.

The CL signature on the credential then covers `kanonZkSig` as a regular
attribute — the AnonCreds-signs-over-everything property gives integrity.

Cryptographic shape (must match `non_revocation.circom` and the SDK):

  credDefFelt = uint256(credDefId) mod p
  credIdFelt  = uint256(keccak256(utf8(kanonCredId))) mod p
  attrFelts   = padToCircuit(canonicalEncode(domainAttributes))
  leaf        = Poseidon(LEAF_TAG=1, credDefFelt, credIdFelt, Poseidon(attrFelts))
  sig         = BabyJub-EdDSA-Poseidon(privateKey, leaf)
"""

from __future__ import annotations

import secrets
from typing import Dict, NamedTuple, Mapping

from web3 import Web3

from did_kanon.v1_0.zk import eddsa
from did_kanon.v1_0.zk.attributes import (
    KANON_CRED_ID_ATTRIBUTE,
    KANON_ZK_PROOF_ATTRIBUTE,
    KANON_ZK_RESERVED_ATTRIBUTE_NAMES,
    KANON_ZK_SIG_ATTRIBUTE,
    encode_attributes_canonical,
    pad_attrs_to_circuit,
)
from did_kanon.v1_0.zk.zk_issuer import compute_zk_leaf
from did_kanon.v1_0.zk.zk_issuer_key import KanonZkIssuerKeyService


class KanonZkCredentialPrep(NamedTuple):
    """Result of `prepare_mode_b_credential`."""

    attributes: Dict[str, str]
    kanon_cred_id: str
    kanon_zk_sig: str


async def prepare_mode_b_credential(
    issuer_key_service: KanonZkIssuerKeyService,
    cred_def_id: str,
    domain_attributes: Mapping[str, str],
) -> KanonZkCredentialPrep:
    """Build a Mode B credential's full attribute set.

    Generates a fresh 32-byte bookkeeping id (`kanonCredId`), felt-encodes
    the domain attrs, computes the tagged Poseidon leaf, signs it with the
    issuer's BabyJubjub key, and returns the merged attribute set the
    AnonCreds preview should carry. Idempotent w.r.t. issuer-key
    provisioning — re-runs on the same credDefId reuse the persisted key.

    Raises if the domain attrs include any reserved name: the caller has
    a bug and we'd rather fail loud than overwrite their value with the
    SDK's generated one.
    """
    # Reject reserved names — the SDK injects them, the caller MUST NOT.
    reserved_present = [
        n for n in (KANON_CRED_ID_ATTRIBUTE, KANON_ZK_SIG_ATTRIBUTE, KANON_ZK_PROOF_ATTRIBUTE)
        if n in domain_attributes
    ]
    if reserved_present:
        raise ValueError(
            f"kanon-zk: domain attributes must not include reserved names "
            f"{reserved_present!r}; the issuer injects them."
        )

    # Fresh 32-byte credId, hex-encoded. Same shape Mode A uses (the
    # status-registry path also takes a 0x<64hex> string).
    kanon_cred_id = "0x" + secrets.token_hex(32)

    # Canonical (alphabetical-name) encoding of the domain values, padded to
    # the circuit's 16-attribute width. The holder, the issuer, and the
    # leaf-tracking service all reproduce this same vector — that's why we
    # don't take attribute order from the caller.
    domain_felts = encode_attributes_canonical(
        dict(domain_attributes), exclude_names=KANON_ZK_RESERVED_ATTRIBUTE_NAMES
    )
    padded = pad_attrs_to_circuit(domain_felts)

    # Tagged leaf the circuit recomputes from its inputs. The cred-id felt
    # MUST be `uint256(keccak256(utf8(kanonCredId))) mod p` to match the
    # holder/verifier side (`kanonCredIdHash` in the SDK). We hand
    # compute_zk_leaf the 32-byte keccak digest directly so its internal
    # `big-endian mod p` reduction lands on the same felt.
    cred_id_keccak = Web3.keccak(text=kanon_cred_id)
    leaf = compute_zk_leaf(cred_def_id, cred_id_keccak, padded)

    # Sign the leaf with the issuer's BJJ key, scoped tightly via
    # `with_private_key` so the privkey hex doesn't outlive the signing op.
    async def _do_sign(key: eddsa.KanonZkIssuerKey) -> eddsa.KanonZkSignature:
        return eddsa.sign_poseidon(key.private_key_hex, leaf)

    sig = await issuer_key_service.with_private_key(cred_def_id, _do_sign)
    kanon_zk_sig = eddsa.encode_zk_signature(sig)

    # Final attribute set: domain attrs in caller's order + reserved at the
    # end. The Mode B schema's attrNames MUST list the reserved attributes
    # in this exact order at the tail.
    attributes: Dict[str, str] = dict(domain_attributes)
    attributes[KANON_CRED_ID_ATTRIBUTE] = kanon_cred_id
    attributes[KANON_ZK_SIG_ATTRIBUTE] = kanon_zk_sig

    return KanonZkCredentialPrep(
        attributes=attributes,
        kanon_cred_id=kanon_cred_id,
        kanon_zk_sig=kanon_zk_sig,
    )


__all__ = ["KanonZkCredentialPrep", "prepare_mode_b_credential"]
