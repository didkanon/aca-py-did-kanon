"""BabyJubjub curve arithmetic — twisted Edwards over the BN254 scalar field.

Mirrors `kanonv2/sdk/node_modules/circomlibjs/src/babyjub.js` exactly:

  - Base field:  Fp where p = BN254 scalar prime
                    21888242871839275222246405745257275088548364400416034343698204186575808495617
  - Curve:       a·x² + y² = 1 + d·x²·y²   (twisted Edwards)
                 with  a = 168700,  d = 168696
  - Group order: 21888242871839275222246405745257275088614511777268538073601725287587578984328
  - Subgroup:    order / 8

This module exposes:

  * `BabyJubjub` — bundled curve params + arithmetic
  * `add(P, Q)` / `double(P)` / `mul(P, k)`
  * `BASE8` — `8 · Generator` (the scalar-mul base circomlibjs uses)
  * `SUB_ORDER` — `order >> 3` (subgroup order on Base8)

All point operations return `(x, y)` tuples of `int` in `[0, p)`. The `mul`
routine is the textbook double-and-add — variable-time but fine here because
the secret scalar is hashed and clamped before it ever reaches this module
(circomlibjs's prv2pub does the same).
"""

from __future__ import annotations

from typing import Tuple


# ─── Field + curve constants ─────────────────────────────────────────────

# BN254 scalar field prime.
P: int = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# Twisted-Edwards parameters.
A: int = 168700
D: int = 168696

# Full group order (8 × subgroup order).
ORDER: int = 21888242871839275222246405745257275088614511777268538073601725287587578984328

# Subgroup order — secret scalars in EdDSA live mod this.
SUB_ORDER: int = ORDER >> 3

# Generator (cofactor-8 point) used in circomlibjs's `babyJub.Generator`.
GENERATOR: Tuple[int, int] = (
    995203441582195749578291179787384436505546430278305826713579947235728471134,
    5472060717959818805561601436314318772137091100104008585924551046643952123905,
)

# `Base8 = 8 · Generator` — the point circomlibjs's prv2pub / signPoseidon
# scalar-multiply from. Equivalent to "generator of the prime-order subgroup".
BASE8: Tuple[int, int] = (
    5299619240641551281634865583518297030282874472190772894086521144482721001553,
    16950150798460657717958625567821834550301663161624707787222815936182638968203,
)

Point = Tuple[int, int]


# ─── Field helpers ───────────────────────────────────────────────────────


def _modinv(a: int, m: int = P) -> int:
    """Modular inverse via the extended Euclidean algorithm."""
    # CPython ≥ 3.8 implements pow(a, -1, m).
    return pow(a, -1, m)


# ─── Point arithmetic ────────────────────────────────────────────────────


def add(p: Point, q: Point) -> Point:
    """Twisted-Edwards point addition. Mirrors `BabyJub.addPoint`.

    For twisted-Edwards a·x² + y² = 1 + d·x²·y² the addition formula is:

      x₃ = (x₁·y₂ + x₂·y₁) / (1 + d·x₁·x₂·y₁·y₂)
      y₃ = (y₁·y₂ − a·x₁·x₂) / (1 − d·x₁·x₂·y₁·y₂)

    circomlibjs uses an equivalent but rearranged form; we reproduce its
    intermediate expressions to keep the arithmetic byte-identical to the
    reference (relevant only for tracing — the final result is the same).
    """
    x1, y1 = p
    x2, y2 = q

    beta = (x1 * y2) % P
    gamma = (y1 * x2) % P
    delta = ((y1 - A * x1) % P * (x2 + y2) % P) % P
    tau = (beta * gamma) % P
    dtau = (D * tau) % P

    inv_pos = _modinv((1 + dtau) % P)
    inv_neg = _modinv((1 - dtau) % P)

    x3 = ((beta + gamma) * inv_pos) % P
    y3 = ((delta + A * beta - gamma) * inv_neg) % P
    return (x3, y3)


def double(p: Point) -> Point:
    """Point doubling. Same formula as `add(p, p)` — no efficiency gain in
    pure Python so we just delegate."""
    return add(p, p)


def mul(base: Point, k: int) -> Point:
    """Scalar multiplication via textbook double-and-add.

    Matches `BabyJub.mulPointEscalar`: starts with the neutral element
    `(0, 1)` and walks `k`'s bits LSB first. Variable-time (fine here —
    callers either hash/clamp the scalar or it's a public value).
    """
    if k < 0:
        raise ValueError("scalar must be non-negative")
    res: Point = (0, 1)  # neutral on twisted-Edwards
    exp: Point = base
    while k:
        if k & 1:
            res = add(res, exp)
        exp = add(exp, exp)
        k >>= 1
    return res


def in_curve(p: Point) -> bool:
    """Curve membership test: `a·x² + y² ≡ 1 + d·x²·y² (mod P)`."""
    x, y = p
    x2 = (x * x) % P
    y2 = (y * y) % P
    lhs = (A * x2 + y2) % P
    rhs = (1 + D * x2 * y2) % P
    return lhs == rhs


__all__ = [
    "P",
    "A",
    "D",
    "ORDER",
    "SUB_ORDER",
    "GENERATOR",
    "BASE8",
    "Point",
    "add",
    "double",
    "mul",
    "in_curve",
]
