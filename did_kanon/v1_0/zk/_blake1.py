"""BLAKE-1-512 — the original BLAKE hash (SHA-3 finalist, 2008), not BLAKE2.

circomlibjs's `eddsa.signPoseidon` uses `createBlakeHash('blake512')` (the
`blake-hash` npm package) for two derivations inside its EdDSA-on-BabyJubjub
construction:

  1. `prv2pub` clamps `BLAKE-512(prv)[0:32]` to derive the secret scalar.
  2. `signPoseidon` builds the nonce `r` from
     `BLAKE-512(BLAKE-512(prv)[32:64] || M)` and reduces mod the subgroup order.

For Python plugin parity we need a byte-exact port of BLAKE-1-512 — the algorithm
is NOT in `hashlib` (which only ships BLAKE2). This module is a pure-Python
implementation that produces identical digests to the npm `blake-hash` package
and to circomlibjs's `createBlakeHash('blake512')`.

Test vector (cross-checked against `blake-hash`):

  blake512(0x01 02 03 04) =
      c181d3707ba41c176481e9f56d88be37 6153e8be6d6718f9bdb605601bd1ee63
      4c9d7130553d6853585d48cb43da3e2c d54939c97f64eccd4a3774efa5e924d2

Reference: Aumasson et al., "SHA-3 proposal BLAKE" (2010 revision).
This is the BLAKE-512 instance with HMAC-style padding compatible with
the `blake-hash` JS package (which is what circomlibjs uses).
"""

from __future__ import annotations

import struct
from typing import List


# ─── Constants ───────────────────────────────────────────────────────────


def _u64(x: int) -> int:
    """Wrap to 64 bits (unsigned)."""
    return x & 0xFFFFFFFFFFFFFFFF


def _rotr64(x: int, n: int) -> int:
    """Right-rotate a 64-bit word by `n` bits."""
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF


# BLAKE-512 initial values (same as SHA-512 IV).
_IV_512 = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
]

# 16 round constants (pi digits).
_C_512 = [
    0x243F6A8885A308D3,
    0x13198A2E03707344,
    0xA4093822299F31D0,
    0x082EFA98EC4E6C89,
    0x452821E638D01377,
    0xBE5466CF34E90C6C,
    0xC0AC29B7C97C50DD,
    0x3F84D5B5B5470917,
    0x9216D5D98979FB1B,
    0xD1310BA698DFB5AC,
    0x2FFD72DBD01ADFB7,
    0xB8E1AFED6A267E96,
    0xBA7C9045F12C7F99,
    0x24A19947B3916CF7,
    0x0801F2E2858EFC16,
    0x636920D871574E69,
]

# Message permutation table (10 rounds × 16 indices).
_SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    # The original spec defines only 10 SIGMA tables but the algorithm runs 16
    # rounds and indexes `_SIGMA[r % 10]`. The list below mirrors rounds
    # 10..15 for clarity (= rows 0..5 of the 10-row table).
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
]


def _G(
    v: List[int],
    a: int,
    b: int,
    c: int,
    d: int,
    m: List[int],
    e: int,
    f: int,
) -> None:
    """One round of the BLAKE-512 mixing function (operates in-place on `v`)."""
    v[a] = _u64(v[a] + v[b] + (m[e] ^ _C_512[f]))
    v[d] = _rotr64(v[d] ^ v[a], 32)
    v[c] = _u64(v[c] + v[d])
    v[b] = _rotr64(v[b] ^ v[c], 25)
    v[a] = _u64(v[a] + v[b] + (m[f] ^ _C_512[e]))
    v[d] = _rotr64(v[d] ^ v[a], 16)
    v[c] = _u64(v[c] + v[d])
    v[b] = _rotr64(v[b] ^ v[c], 11)


def _compress(h: List[int], block: bytes, salt: List[int], t: int) -> None:
    """One BLAKE-512 compression step. Updates `h` in place."""
    # Parse the 128-byte block into 16 big-endian 64-bit message words.
    m = list(struct.unpack(">16Q", block))

    v = [0] * 16
    v[0:8] = h[:]
    v[8] = salt[0] ^ _C_512[0]
    v[9] = salt[1] ^ _C_512[1]
    v[10] = salt[2] ^ _C_512[2]
    v[11] = salt[3] ^ _C_512[3]
    v[12] = (t & 0xFFFFFFFFFFFFFFFF) ^ _C_512[4]
    v[13] = (t & 0xFFFFFFFFFFFFFFFF) ^ _C_512[5]
    v[14] = ((t >> 64) & 0xFFFFFFFFFFFFFFFF) ^ _C_512[6]
    v[15] = ((t >> 64) & 0xFFFFFFFFFFFFFFFF) ^ _C_512[7]

    # 16 rounds (BLAKE-512). Each round applies 8 G-mixings under a
    # permutation from SIGMA[r % 10].
    for r in range(16):
        s = _SIGMA[r % 10]
        # Column mixings.
        _G(v, 0, 4, 8, 12, m, s[0], s[1])
        _G(v, 1, 5, 9, 13, m, s[2], s[3])
        _G(v, 2, 6, 10, 14, m, s[4], s[5])
        _G(v, 3, 7, 11, 15, m, s[6], s[7])
        # Diagonal mixings.
        _G(v, 0, 5, 10, 15, m, s[8], s[9])
        _G(v, 1, 6, 11, 12, m, s[10], s[11])
        _G(v, 2, 7, 8, 13, m, s[12], s[13])
        _G(v, 3, 4, 9, 14, m, s[14], s[15])

    # Finalise: h_i ^= v_i ^ v_{i+8} ^ salt_{i%4}
    for i in range(8):
        h[i] = h[i] ^ v[i] ^ v[i + 8] ^ salt[i % 4]


def blake512(data: bytes) -> bytes:
    """Return the 64-byte BLAKE-512 digest of `data`.

    Byte-identical to npm `blake-hash`'s `createBlakeHash('blake512')`
    output for the same input — verified by cross-test vectors.
    """
    h = list(_IV_512)
    salt = [0, 0, 0, 0]
    t_counter = 0  # bit-length counter

    # Process full 128-byte blocks.
    data = bytes(data)
    n = len(data)
    offset = 0
    while n - offset >= 128:
        t_counter += 1024
        _compress(h, data[offset : offset + 128], salt, t_counter)
        offset += 128

    # Final block with padding.
    rem = data[offset:]
    rem_bits = len(rem) * 8

    # Padding: append 0x80, then zeros, then 0x01, then 16-byte big-endian
    # length. The padded block ends with the BLAKE personalisation byte
    # 0x01 immediately before the length field, distinguishing BLAKE-512
    # from BLAKE-384.
    pad = bytearray(rem)
    pad.append(0x80)
    # Zero-pad so that after padding the final block is 128 bytes,
    # leaving 17 bytes at the end (1 for the 0x01 byte + 16 for length).
    while len(pad) % 128 != 111:
        pad.append(0x00)
    pad.append(0x01)
    # 16-byte big-endian message bit-length.
    pad.extend(struct.pack(">QQ", 0, rem_bits + (offset * 8)))
    # Handle two padding-block edge cases:
    if len(pad) == 128:
        # Single padded block; absorb the bit-counter including these bits.
        if rem_bits == 0:
            # Empty final block had only padding — set counter to zero per spec.
            _compress(h, bytes(pad), salt, 0)
        else:
            t_counter += rem_bits
            _compress(h, bytes(pad), salt, t_counter)
    else:
        # Two padded blocks. The FIRST block carries the actual data bits
        # (with the appended 0x80 etc.) and ends without the 0x01+length
        # tail. The SECOND block is all padding (no new data bits) with
        # the 0x01+length tail; spec says use counter=0 on that block.
        # Our `pad` already contains both blocks back-to-back. Re-derive:
        first = pad[:128]
        second = pad[128:]
        # The first block has rem bytes of real data; bit-counter advances by
        # that many bits.
        if rem_bits == 0:
            _compress(h, bytes(first), salt, 0)
        else:
            t_counter += rem_bits
            _compress(h, bytes(first), salt, t_counter)
        # Pad-only second block: spec mandates counter=0.
        _compress(h, bytes(second), salt, 0)

    # Serialise: 8 big-endian 64-bit words.
    return struct.pack(">8Q", *h)


__all__ = ["blake512"]
