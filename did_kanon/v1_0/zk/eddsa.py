"""BabyJubjub EdDSA-Poseidon — pure-Python port of circomlibjs's `signPoseidon`.

The Mode B circuit (`non_revocation.circom`) verifies an issuer's BabyJubjub
signature over a Poseidon-hashed leaf. The issuer and verifier MUST agree
byte-for-byte on the signature scheme. The reference implementation is
circomlibjs (Node-only), so for the Python plugin to issue Mode B credentials
we mirror it here. All test vectors cross-check against
`@ajna-inc/kanon-sdk`'s `signZkLeaf` / `restoreZkIssuerKey`.

Scheme (circomlibjs convention):

  prv2pub(prv):
    h = BLAKE-512(prv)                          # 64 bytes
    s_buf = prune(h[0:32])                      # clamp lo/hi bits
    s = uint(s_buf, little-endian)              # secret scalar
    A = (s >> 3) · BASE8                        # public point

  signPoseidon(prv, msg):
    (s_buf, s, A) as above
    r_buf = BLAKE-512(h[32:64] || msg_LE_32)    # 64 bytes
    r = uint(r_buf, little-endian) mod SUB_ORDER
    R8 = r · BASE8
    c  = Poseidon(R8x, R8y, Ax, Ay, msg)        # field-element challenge
    S  = (r + c · s) mod SUB_ORDER
    return (R8, S)

  verifyPoseidon(msg, sig, A):
    c  = Poseidon(R8x, R8y, Ax, Ay, msg)
    Pleft  = S · BASE8
    Pright = R8 + (c · 8) · A
    return Pleft == Pright

The `prune` step is identical to Ed25519's: clear the low 3 bits and the top
bit, set bit 254. This keeps the scalar in the right range and avoids small
subgroup leaks — same constraint the circuit enforces.
"""

from __future__ import annotations

import secrets
from typing import NamedTuple, Tuple

from did_kanon.v1_0.zk import _babyjub as babyjub
from did_kanon.v1_0.zk._blake1 import blake512
from did_kanon.v1_0.zk.poseidon import poseidon_hash


# ─── Types ───────────────────────────────────────────────────────────────


class KanonZkSignature(NamedTuple):
    """BabyJubjub-EdDSA signature over a Poseidon-hashed leaf.

    Wire form: `(R8x, R8y, S)` — three BN254 felts. Encoders pack these into
    96 bytes big-endian (matches the SDK's `encodeZkSignature`).
    """

    R8x: int
    R8y: int
    S: int


class KanonZkIssuerKey(NamedTuple):
    """Persisted issuer keypair.

    Only `private_key_hex` needs to be kept secret. `Ax`, `Ay` are the
    on-chain `IssuerZkPubKey` coordinates the credDef registry stores.
    """

    private_key_hex: str
    Ax: int
    Ay: int


# ─── Helpers ─────────────────────────────────────────────────────────────


def _prune(buf32: bytes) -> bytes:
    """Ed25519-style buffer clamping. Mirrors `Eddsa.pruneBuffer`."""
    if len(buf32) != 32:
        raise ValueError("prune expects 32 bytes")
    b = bytearray(buf32)
    b[0] &= 0xF8
    b[31] &= 0x7F
    b[31] |= 0x40
    return bytes(b)


def _le_to_int(buf: bytes) -> int:
    return int.from_bytes(buf, "little")


def _felt_to_le32(value: int) -> bytes:
    """Serialise a felt as 32 little-endian bytes for the message-hash
    composition. Matches `F.toRprLE(out, off, value)` in circomlibjs."""
    return (value % babyjub.P).to_bytes(32, "little")


# ─── Public API ──────────────────────────────────────────────────────────

KANON_ZK_LEAF_TAG: int = 1


def generate_issuer_key() -> KanonZkIssuerKey:
    """Mint a fresh BabyJubjub-EdDSA keypair from 32 random bytes."""
    sk = secrets.token_bytes(32)
    return restore_issuer_key("0x" + sk.hex())


def restore_issuer_key(private_key_hex: str) -> KanonZkIssuerKey:
    """Recover the public coords `(Ax, Ay)` from a persisted private key."""
    sk_bytes = bytes.fromhex(
        private_key_hex[2:] if private_key_hex.lower().startswith("0x") else private_key_hex
    )
    if len(sk_bytes) != 32:
        raise ValueError("private key must be 32 bytes")
    h = blake512(sk_bytes)
    pruned = _prune(h[:32])
    s = _le_to_int(pruned)
    ax, ay = babyjub.mul(babyjub.BASE8, s >> 3)
    return KanonZkIssuerKey(
        private_key_hex=private_key_hex
        if private_key_hex.lower().startswith("0x")
        else "0x" + private_key_hex,
        Ax=ax,
        Ay=ay,
    )


def sign_poseidon(private_key_hex: str, leaf: int) -> KanonZkSignature:
    """Sign a leaf with the issuer's BJJ key.

    Matches `eddsa.signPoseidon(prv, msg)` in circomlibjs byte-for-byte.
    Returns `(R8x, R8y, S)`.
    """
    sk_bytes = bytes.fromhex(
        private_key_hex[2:] if private_key_hex.lower().startswith("0x") else private_key_hex
    )
    if len(sk_bytes) != 32:
        raise ValueError("private key must be 32 bytes")

    h = blake512(sk_bytes)
    pruned = _prune(h[:32])
    s = _le_to_int(pruned)
    A_point = babyjub.mul(babyjub.BASE8, s >> 3)

    # Nonce derivation: r = BLAKE-512(h[32:64] || msg_LE_32) mod SUB_ORDER.
    compose = bytearray(h[32:64])
    compose.extend(_felt_to_le32(leaf))
    r_buf = blake512(bytes(compose))
    r = _le_to_int(r_buf) % babyjub.SUB_ORDER

    R8 = babyjub.mul(babyjub.BASE8, r)

    # Challenge: Poseidon(R8x, R8y, Ax, Ay, leaf) — circuit's
    # `EdDSAPoseidonVerifier()` recomputes this on the wire.
    c = poseidon_hash([R8[0], R8[1], A_point[0], A_point[1], leaf % babyjub.P])

    S = (r + c * s) % babyjub.SUB_ORDER
    return KanonZkSignature(R8x=R8[0], R8y=R8[1], S=S)


def verify_poseidon(
    public_key: Tuple[int, int],
    leaf: int,
    signature: KanonZkSignature,
) -> bool:
    """Verify a Mode B signature. Mirrors `eddsa.verifyPoseidon`.

    Equation: `S · BASE8 == R8 + (c · 8) · A` where
              `c = Poseidon(R8x, R8y, Ax, Ay, leaf)`. The factor of 8
    is the cofactor — same constraint the circuit applies.
    """
    if signature.S >= babyjub.SUB_ORDER:
        return False
    if signature.S == 0:
        # BIP-62 style lower bound. With S=0 the LHS collapses to the
        # identity point (0, 1) and the equation degenerates; rejecting
        # avoids a (theoretical) forgery surface where an attacker picks
        # R8 to satisfy the equation without knowing the secret.
        return False
    if (signature.R8x, signature.R8y) == (0, 1):
        # R8 must not be the identity point.
        return False
    if public_key == (0, 1):
        # Public key must not be the identity point.
        return False
    if not babyjub.in_curve((signature.R8x, signature.R8y)):
        return False
    if not babyjub.in_curve(public_key):
        return False

    c = poseidon_hash(
        [signature.R8x, signature.R8y, public_key[0], public_key[1], leaf % babyjub.P]
    )

    p_left = babyjub.mul(babyjub.BASE8, signature.S)
    p_right_term = babyjub.mul(public_key, (c * 8) % babyjub.ORDER)
    p_right = babyjub.add((signature.R8x, signature.R8y), p_right_term)
    return p_left == p_right


def encode_zk_signature(sig: KanonZkSignature) -> str:
    """Pack `(R8x, R8y, S)` as 96 BE bytes, then base64. Matches the SDK."""
    import base64

    buf = b"".join(
        v.to_bytes(32, "big") for v in (sig.R8x, sig.R8y, sig.S)
    )
    return base64.b64encode(buf).decode("ascii")


def decode_zk_signature(value: str) -> KanonZkSignature:
    """Inverse of `encode_zk_signature`."""
    import base64

    buf = base64.b64decode(value)
    if len(buf) != 96:
        raise ValueError(f"expected 96 bytes, got {len(buf)}")
    R8x = int.from_bytes(buf[0:32], "big")
    R8y = int.from_bytes(buf[32:64], "big")
    S = int.from_bytes(buf[64:96], "big")
    return KanonZkSignature(R8x=R8x, R8y=R8y, S=S)


__all__ = [
    "KANON_ZK_LEAF_TAG",
    "KanonZkSignature",
    "KanonZkIssuerKey",
    "generate_issuer_key",
    "restore_issuer_key",
    "sign_poseidon",
    "verify_poseidon",
    "encode_zk_signature",
    "decode_zk_signature",
]
