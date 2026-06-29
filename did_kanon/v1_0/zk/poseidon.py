"""Poseidon hash over BN254 scalar field — circomlib-compatible.

This is a pure-Python port of `circomlibjs/src/poseidon_reference.js`. It uses
the same parameter set (constants + MDS matrix) that the `non_revocation.circom`
circuit's `Poseidon(t)` templates compile against, so a Merkle leaf or root
computed here matches what the circuit (and the credo-ts SDK) compute over the
same inputs.

Why we ship our own port instead of using a pypi Poseidon:
    `poseidon-py` (and most other pypi Poseidons) implement Starkware's
    Poseidon, which uses the same BN254 field but a *different* round-constant
    + MDS-matrix set than circomlib. The hashes don't match. We verified
    empirically:

        circomlibjs.poseidon([1, 2]) = 7853200120776062878684798364095072458815029376092732009249414926327459813530
        poseidon-py poseidon([1, 2]) = 1557996165160500454210437319447297236715335099509187222888255133199463084263

    Any leaf or root the Python plugin previously published through poseidon-py
    would have been rejected by the on-chain SNARK verifier.

Implementation:
    - State width `t = nInputs + 1` (input 0 is the initial `0` capacity).
    - 8 full rounds (4 at the start, 4 at the end). Partial-round count varies
      with `t`; the table comes straight from circomlibjs.
    - S-box is `x^5`; full rounds apply it to every state element, partial
      rounds only to state[0].
    - Round constants `C[t-2]` and MDS matrix `M[t-2]` come from the vendored
      `poseidon_constants.json` (copied verbatim from circomlibjs).

Sanity test (also enforced in tests/test_poseidon.py):
    poseidon_hash([1, 2]) == 7853200120776062878684798364095072458815029376092732009249414926327459813530

The file `poseidon_constants.json` is ~870 KB and is loaded once at module
import. The hash itself is field-arithmetic-heavy but acceptable at Python
speeds for the off-hot-path uses we have (issuance / revocation Merkle root
recompute).
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Iterable, Sequence

# BN254 scalar field modulus — same field the circuit runs over.
BN254_PRIME = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)

# Full-round count (fixed across t in circomlib's parameter selection).
_N_ROUNDS_F = 8

# Partial-round count by `t - 2`. From circomlibjs/src/poseidon_reference.js.
_N_ROUNDS_P = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68]

_CONSTANTS_PATH = os.path.join(os.path.dirname(__file__), "poseidon_constants.json")


def _parse_field(x: str) -> int:
    """Decode a circomlibjs JSON felt — decimal or `0x…` hex — as a Python int."""
    if isinstance(x, int):
        return x % BN254_PRIME
    s = str(x)
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16) % BN254_PRIME
    return int(s) % BN254_PRIME


@lru_cache(maxsize=1)
def _constants() -> tuple[list[list[int]], list[list[list[int]]]]:
    """Load `(C, M)` from the vendored circomlib JSON.

    `C[t-2]` is a flat list of round constants, length `(R_F + R_P) * t`.
    `M[t-2]` is a `t x t` MDS matrix.
    """
    with open(_CONSTANTS_PATH, "r") as fh:
        raw = json.load(fh)

    C: list[list[int]] = []
    for row in raw["C"]:
        C.append([_parse_field(v) for v in row])

    M: list[list[list[int]]] = []
    for matrix in raw["M"]:
        M.append([[_parse_field(v) for v in r] for r in matrix])

    return C, M


def _pow5(x: int) -> int:
    """`x^5 mod p`, the Poseidon S-box. Two squarings + a multiply is one less
    modmul than `pow(x, 5, p)`; in practice this matters at hot-path scale."""
    x2 = (x * x) % BN254_PRIME
    x4 = (x2 * x2) % BN254_PRIME
    return (x4 * x) % BN254_PRIME


def poseidon_hash(inputs: Iterable[int], init_state: int = 0) -> int:
    """Circomlib-compatible Poseidon hash of `inputs`.

    Args:
        inputs: sequence of `n` field elements (Python ints). `n` must be in
            `[1, 16]` — the same arity range circomlibjs's constant table
            supports.
        init_state: optional override for the capacity element. Defaults to
            `0`, which is what `circomlibjs.poseidon(inputs)` uses and what the
            circuit's `Poseidon(n)` template uses.

    Returns:
        a single field element (int in `[0, p)`).
    """
    inputs_list: Sequence[int] = list(inputs)
    n = len(inputs_list)
    if n == 0:
        raise ValueError("poseidon_hash requires at least one input")
    if n > len(_N_ROUNDS_P):
        raise ValueError(
            f"poseidon_hash arity {n} exceeds supported range "
            f"[1, {len(_N_ROUNDS_P)}]"
        )

    t = n + 1
    n_rf = _N_ROUNDS_F
    n_rp = _N_ROUNDS_P[t - 2]

    C, M = _constants()
    Ct = C[t - 2]
    Mt = M[t - 2]

    state: list[int] = [init_state % BN254_PRIME]
    state.extend(int(a) % BN254_PRIME for a in inputs_list)

    p = BN254_PRIME
    for r in range(n_rf + n_rp):
        # Add round constants.
        base = r * t
        for i in range(t):
            state[i] = (state[i] + Ct[base + i]) % p

        # S-box: full rounds apply x^5 to all; partial rounds only to state[0].
        if r < n_rf // 2 or r >= n_rf // 2 + n_rp:
            for i in range(t):
                state[i] = _pow5(state[i])
        else:
            state[0] = _pow5(state[0])

        # MDS multiply: new_state[i] = Σ_j M[i][j] * state[j].
        new_state = [0] * t
        for i in range(t):
            row = Mt[i]
            acc = 0
            for j in range(t):
                acc = (acc + row[j] * state[j]) % p
            new_state[i] = acc
        state = new_state

    return state[0]
