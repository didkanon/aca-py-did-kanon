"""Groth16 prover — wraps `snarkjs prove` as a subprocess.

We don't ship a pure-Python prover (Groth16 over BN254 with full MSMs is
slow in Python and snarkjs is the canonical reference). The Python side
generates the witness via `WitnessCalculator`, then hands it to snarkjs
for the elliptic-curve heavy-lifting.

Requirements:
  - `node` and the `snarkjs` package on PATH (`npm i -g snarkjs` or
    `npx snarkjs ...`).
  - A `.zkey` file produced by the Phase-2 ceremony (or for dev: by
    `snarkjs groth16 setup`).

The subprocess hand-off makes the prover Node-dependent at runtime; for
pure-Python deployments swap this out for a future Rust→WASM prover or
the `py_ecc` fallback.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple, Union

from .witness import WitnessCalculator

LOGGER = logging.getLogger(__name__)


class SnarkjsProverError(Exception):
    pass


class SnarkjsProver:
    """Witness gen in Python (via `wasmtime`) + Groth16 prove via snarkjs CLI."""

    def __init__(
        self,
        wasm_path: Union[str, Path],
        zkey_path: Union[str, Path],
        *,
        snarkjs_binary: str = "snarkjs",
    ):
        self._wasm_path = Path(wasm_path)
        self._zkey_path = Path(zkey_path)
        if not self._wasm_path.exists():
            raise FileNotFoundError(f"witness WASM not found at {self._wasm_path}")
        if not self._zkey_path.exists():
            raise FileNotFoundError(f"zkey not found at {self._zkey_path}")
        self._snarkjs = snarkjs_binary
        self._calculator: WitnessCalculator | None = None

    def _get_calculator(self) -> WitnessCalculator:
        if self._calculator is None:
            self._calculator = WitnessCalculator(self._wasm_path)
        return self._calculator

    def prove(self, inputs: Dict) -> Tuple[dict, List[int]]:
        """Return `(proof, public_signals_as_ints)` for the given inputs.

        `proof` is snarkjs JSON shape; `public_signals` is the public-input
        vector in the order declared by the circuit.
        """
        calc = self._get_calculator()
        witness = calc.calculate_witness(inputs)
        return self._snarkjs_prove(witness, calc.witness_size, calc.prime)

    def _snarkjs_prove(self, witness: List[int], witness_size: int, prime: int) -> Tuple[dict, List[int]]:
        # Build a WTNS binary file in Circom v2 format so snarkjs can read it
        # without re-running the witness calculator.
        with tempfile.TemporaryDirectory() as tmp:
            wtns_path = Path(tmp) / "witness.wtns"
            self._write_wtns(witness, witness_size, prime, wtns_path)
            proof_path = Path(tmp) / "proof.json"
            public_path = Path(tmp) / "public.json"
            cmd = [
                self._snarkjs,
                "groth16",
                "prove",
                str(self._zkey_path),
                str(wtns_path),
                str(proof_path),
                str(public_path),
            ]
            try:
                subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except FileNotFoundError as err:
                raise SnarkjsProverError(
                    f"snarkjs binary not found ({self._snarkjs!r}); install via "
                    "'npm i -g snarkjs' or pass `snarkjs_binary=` explicitly"
                ) from err
            except subprocess.CalledProcessError as err:
                raise SnarkjsProverError(
                    f"snarkjs prove failed: {err.stderr or err.stdout}"
                ) from err
            with open(proof_path, "r", encoding="utf-8") as f:
                proof = json.load(f)
            with open(public_path, "r", encoding="utf-8") as f:
                public = json.load(f)
            return proof, [int(x) for x in public]

    @staticmethod
    def _write_wtns(witness: List[int], witness_size: int, prime: int, path: Path) -> None:
        """Write a WTNS v2 binary file — matches `calculateWTNSBin` in
        snarkjs / witness_calculator.js so `snarkjs groth16 prove` reads it."""
        # Field element size: 32 bytes for BN254 (256 bits = 8×u32).
        n8 = 32

        def field_to_bytes_le(x: int) -> bytes:
            return (x % prime).to_bytes(n8, "little")

        from io import BytesIO
        import struct

        buf = BytesIO()
        # Magic "wtns" + version (2) + nSections (2).
        buf.write(b"wtns")
        buf.write(struct.pack("<I", 2))
        buf.write(struct.pack("<I", 2))
        # Section 1: header.
        buf.write(struct.pack("<I", 1))
        header_size = 4 + n8 + 4  # n8 + prime + witnessSize ... actually:
        #   n8 (4), prime (n8), nWitness (4) — total 4 + n8 + 4 bytes.
        # Length is u64.
        buf.write(struct.pack("<Q", header_size))
        buf.write(struct.pack("<I", n8))
        buf.write(field_to_bytes_le(prime))
        buf.write(struct.pack("<I", witness_size))
        # Section 2: witness values.
        buf.write(struct.pack("<I", 2))
        section_size = witness_size * n8
        buf.write(struct.pack("<Q", section_size))
        for w in witness:
            buf.write(field_to_bytes_le(w))
        path.write_bytes(buf.getvalue())
