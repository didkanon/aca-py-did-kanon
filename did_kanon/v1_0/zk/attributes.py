"""Mode B attribute encoding — matches @ajna-inc/kanon-sdk/anoncreds.

Mode B rides on standard AnonCreds. The Kanon SDK reserves a handful of
attribute names and a canonical felt-encoding scheme; issuer, holder and
verifier all have to agree on them bit-for-bit. This module is the Python
mirror of `kanonv2/sdk/src/anoncreds/zkAttributes.ts`. Both produce
identical outputs for identical inputs — confirmed by cross-tests against
the SDK's `attrValueToFelt` and `encodeAttributesCanonical`.

The three reserved attribute names:

  kanonCredId       — Mode A's per-credential identifier. Always revealed
                      in Mode A proofs; verifiers hash it for the status
                      lookup.
  kanonZkSig        — Mode B's BabyJubjub signature over the leaf. Stored
                      as a regular credential attribute so the AnonCreds
                      CL signature covers it. Holders MUST NOT disclose
                      it; the kanon-aware verifier wrapper rejects any
                      proof request that asks for it.
  kanonZkProof      — Self-attested attribute carrying the holder's
                      Groth16 proof + public signals (base64).

The canonical attribute encoding for Mode B:

  felt = uint256(keccak256(utf8(value))) mod BN254_SCALAR_FIELD

Attribute arrays fed into the SNARK are constructed by sorting the
attribute NAMES lexicographically (byte order), filtering out the
SDK-reserved names, then felt-encoding each value. Same encoder runs at
issuance (`prepareModeBCredential`), at publish time (the issuance
tracker) and at presentation time (the holder wrapper) — so the three
sides agree on the leaf without depending on JS object iteration order
or AnonCreds' attribute-list serialisation.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Sequence

from web3 import Web3

from .poseidon import BN254_PRIME

# ─── Reserved attribute names ────────────────────────────────────────────

KANON_CRED_ID_ATTRIBUTE: str = "kanonCredId"
KANON_ZK_SIG_ATTRIBUTE: str = "kanonZkSig"
KANON_ZK_PROOF_ATTRIBUTE: str = "kanonZkProof"

KANON_ZK_RESERVED_ATTRIBUTE_NAMES: Sequence[str] = (
    KANON_CRED_ID_ATTRIBUTE,
    KANON_ZK_SIG_ATTRIBUTE,
    KANON_ZK_PROOF_ATTRIBUTE,
)


# ─── Felt encoding ───────────────────────────────────────────────────────


def attr_value_to_felt(value: str) -> int:
    """Canonical felt encoding of an AnonCreds attribute value.

    `felt = uint256(keccak256(utf8(value))) mod BN254_SCALAR_FIELD`.

    This is collision-resistant (keccak gives 256 bits, reduction loses
    ~2 bits) but lossy — you can't recover the original value from the
    felt. That's fine for Mode B's purpose (non-revocation + selective
    disclosure of WHICH attribute, not RANGE queries on attribute values).

    Range proofs on numeric attributes would need a typed encoding;
    that's a separate primitive.
    """
    if not isinstance(value, str):
        raise TypeError(
            f"attr_value_to_felt: value must be str, got {type(value).__name__}"
        )
    digest = Web3.keccak(text=value)
    return int.from_bytes(digest, "big") % BN254_PRIME


def encode_attributes_canonical(
    values: Dict[str, str],
    exclude_names: Iterable[str] = KANON_ZK_RESERVED_ATTRIBUTE_NAMES,
) -> List[int]:
    """Felt-encode `values` in canonical (lexicographic-name) order.

    `exclude_names` defaults to the SDK-reserved names so the leaf
    doesn't double-bind values the circuit already binds elsewhere
    (`kanonCredId` is a separate circuit input; `kanonZkSig` IS the
    signature over the leaf — including it as a leaf input would be
    circular).

    The output is a list of BN254 felts of length
    `len(values) - len(<reserved names found>)`. The leaf builder pads
    this with zeros to the circuit's 16-felt width via
    `pad_attrs_to_circuit`.
    """
    exclude = set(exclude_names)
    sorted_names = sorted(n for n in values.keys() if n not in exclude)
    return [attr_value_to_felt(values[n]) for n in sorted_names]


# ─── Circuit-width padding ───────────────────────────────────────────────

KANON_ZK_CIRCUIT_ATTRS: int = 16


def pad_attrs_to_circuit(attrs: Sequence[int]) -> List[int]:
    """Pad or reject a felt list to the circuit's 16-felt attribute width.

    The compiled `non_revocation.circom` consumes EXACTLY 16 attribute
    felts. Real schemas have fewer, so we right-pad with `0`. Schemas
    with more than 16 attrs are NOT silently truncated — they don't fit
    this circuit and the caller has to either trim or recompile with a
    higher `nAttr`.
    """
    if len(attrs) > KANON_ZK_CIRCUIT_ATTRS:
        raise ValueError(
            f"pad_attrs_to_circuit: {len(attrs)} attributes exceed the circuit's "
            f"{KANON_ZK_CIRCUIT_ATTRS}-felt limit"
        )
    out = [int(a) % BN254_PRIME for a in attrs]
    while len(out) < KANON_ZK_CIRCUIT_ATTRS:
        out.append(0)
    return out


__all__ = [
    "KANON_CRED_ID_ATTRIBUTE",
    "KANON_ZK_SIG_ATTRIBUTE",
    "KANON_ZK_PROOF_ATTRIBUTE",
    "KANON_ZK_RESERVED_ATTRIBUTE_NAMES",
    "KANON_ZK_CIRCUIT_ATTRS",
    "attr_value_to_felt",
    "encode_attributes_canonical",
    "pad_attrs_to_circuit",
]
