"""Off-chain Groth16 verifier over BN254 — `py_ecc`-backed.

Useful when the verifier wants to check a proof without an RPC round-trip
(e.g. air-gapped tests, batch jobs). For most cases the on-chain
`MerkleStateRegistry.verifyZKMembership` view call is cheaper.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence, Union

from py_ecc.optimized_bn128 import (
    FQ12,
    add,
    final_exponentiate,
    multiply,
    neg,
    pairing,
    G1,  # noqa: F401  — imported for parity with the spec
    G2,  # noqa: F401
    curve_order,
)

# A Groth16 proof in snarkjs JSON shape:
#   { pi_a: [x, y, "1"], pi_b: [[x0, x1], [y0, y1], ["1", "0"]], pi_c: [...], protocol, curve }
# Verifying key in snarkjs JSON shape:
#   { vk_alpha_1, vk_beta_2, vk_gamma_2, vk_delta_2, IC: [[x, y, 1], ...] }


class Groth16VerifyError(Exception):
    pass


def _to_int(x: Union[str, int]) -> int:
    if isinstance(x, str):
        return int(x)
    return int(x)


def _g1(point) -> tuple:
    """snarkjs G1 point — affine [x, y, '1'] → optimized_bn128 jacobian (X, Y, Z)."""
    from py_ecc.optimized_bn128 import FQ

    x = FQ(_to_int(point[0]))
    y = FQ(_to_int(point[1]))
    z = FQ(_to_int(point[2]))
    return (x, y, z)


def _g2(point) -> tuple:
    """snarkjs G2 point — affine [[x0,x1], [y0,y1], [z0,z1]] → jacobian."""
    from py_ecc.optimized_bn128 import FQ2

    x = FQ2([_to_int(point[0][0]), _to_int(point[0][1])])
    y = FQ2([_to_int(point[1][0]), _to_int(point[1][1])])
    z = FQ2([_to_int(point[2][0]), _to_int(point[2][1])])
    return (x, y, z)


class Groth16OffChainVerifier:
    """Pure-Python Groth16 verifier for circuits compiled by Circom + snarkjs.

    Load the verification key once and verify many proofs.
    """

    def __init__(self, verification_key: dict):
        if verification_key.get("protocol") not in ("groth16", "Groth16"):
            raise Groth16VerifyError(
                f"unsupported protocol: {verification_key.get('protocol')!r}"
            )
        if verification_key.get("curve") not in ("bn128", "BN254"):
            raise Groth16VerifyError(
                f"unsupported curve: {verification_key.get('curve')!r}"
            )
        self._n_public = int(verification_key["nPublic"])
        self._alpha_1 = _g1(verification_key["vk_alpha_1"])
        self._beta_2 = _g2(verification_key["vk_beta_2"])
        self._gamma_2 = _g2(verification_key["vk_gamma_2"])
        self._delta_2 = _g2(verification_key["vk_delta_2"])
        self._ic = [_g1(p) for p in verification_key["IC"]]
        if len(self._ic) != self._n_public + 1:
            raise Groth16VerifyError(
                f"IC length {len(self._ic)} != nPublic+1 ({self._n_public + 1})"
            )

    @classmethod
    def from_file(cls, vk_path: Union[str, Path]) -> "Groth16OffChainVerifier":
        with open(vk_path, "r", encoding="utf-8") as f:
            return cls(json.load(f))

    def verify(self, proof: dict, public_signals: Sequence[Union[str, int]]) -> bool:
        if len(public_signals) != self._n_public:
            raise Groth16VerifyError(
                f"expected {self._n_public} public signals, got {len(public_signals)}"
            )
        # Reduce signals into the scalar field.
        signals = [_to_int(s) % curve_order for s in public_signals]
        pi_a = _g1(proof["pi_a"])
        pi_b = _g2(proof["pi_b"])
        pi_c = _g1(proof["pi_c"])

        # vk_x = IC[0] + sum(IC[i+1] * signal[i])
        vk_x = self._ic[0]
        for i, s in enumerate(signals):
            term = multiply(self._ic[i + 1], s)
            vk_x = add(vk_x, term)

        # e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1
        e_ab = pairing(pi_b, neg(pi_a))
        e_alpha_beta = pairing(self._beta_2, self._alpha_1)
        e_vkx_gamma = pairing(self._gamma_2, vk_x)
        e_c_delta = pairing(self._delta_2, pi_c)
        product = e_ab * e_alpha_beta * e_vkx_gamma * e_c_delta
        return final_exponentiate(product) == FQ12.one()
