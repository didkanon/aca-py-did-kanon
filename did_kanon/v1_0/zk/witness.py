"""Circom witness calculator — port of `witness_calculator.js` to Python.

Runs a Circom-compiled WASM circuit under `wasmtime` to produce a witness
vector. Matches the snarkjs / circom v2 ABI used by `non_revocation.wasm`.

The witness produced here can be handed to a Groth16 prover (snarkjs CLI
or pure-Python) to generate a SNARK proof.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Union

from wasmtime import Engine, Instance, Linker, Module, Store

LOGGER = logging.getLogger(__name__)


class WitnessCalculatorError(Exception):
    """Raised when the circuit aborts or input is malformed."""


def _flatten(value: Any) -> List[int]:
    """Recursively flatten nested arrays/tuples/lists to a list of ints."""
    if isinstance(value, (list, tuple)):
        out: List[int] = []
        for v in value:
            out.extend(_flatten(v))
        return out
    return [int(value)]


def _qualify_input(prefix: str, value: Any, out: Dict[str, List[int]]) -> None:
    """Flatten `{a: {b: 5, c: [1,2]}}` → `{"a.b": [5], "a.c": [1,2]}`.

    Mirrors `qualify_input` in `witness_calculator.js`.
    """
    if isinstance(value, dict):
        for k, v in value.items():
            new_prefix = k if not prefix else f"{prefix}.{k}"
            _qualify_input(new_prefix, v, out)
    else:
        out[prefix] = _flatten(value)


def _fnv_hash(s: str) -> int:
    """FNV-1a 64-bit hash on bytes(s) — matches Circom's symbol hash."""
    h = 0xCBF29CE484222325
    mask = (1 << 64) - 1
    for b in s.encode("ascii"):
        h ^= b
        h *= 0x100000001B3
        h &= mask
    return h


def _to_array32(rem: int, size: int) -> List[int]:
    """BigInt → big-endian uint32[size]. Matches `toArray32` in witness_calculator.js."""
    radix = 1 << 32
    arr: List[int] = []
    while rem:
        arr.insert(0, int(rem % radix))
        rem //= radix
    while len(arr) < size:
        arr.insert(0, 0)
    return arr


def _from_array32(arr: Iterable[int]) -> int:
    """Big-endian uint32[] → int. Words are masked to unsigned 32-bit because
    wasmtime returns signed i32 where snarkjs' JS code stores into a
    Uint32Array (which auto-coerces to unsigned)."""
    res = 0
    radix = 1 << 32
    for n in arr:
        res = res * radix + (int(n) & 0xFFFFFFFF)
    return res


class WitnessCalculator:
    """Loads a Circom v2 WASM circuit and produces witness vectors.

    Single-threaded: do not share an instance across asyncio tasks; each
    `calculate_witness` mutates the WASM shared memory.
    """

    def __init__(self, wasm_path: Union[str, Path]):
        path = Path(wasm_path)
        if not path.exists():
            raise FileNotFoundError(f"witness WASM not found at {path}")
        engine = Engine()
        with open(path, "rb") as f:
            module = Module(engine, f.read())
        store = Store(engine)
        linker = Linker(engine)
        self._error_buf: List[str] = []
        self._message_buf: List[str] = []
        # Circom v2 expects the host to provide a `runtime` namespace.
        # The functions here mirror what `witness_calculator.js` plugs in.
        self._instance = self._instantiate(linker, store, module)
        self._store = store
        # Cache function handles for speed.
        ex = self._instance.exports(store)
        self._exports = ex
        self._n32 = ex["getFieldNumLen32"](store)
        ex["getRawPrime"](store)
        prime_words = [ex["readSharedRWMemory"](store, i) for i in range(self._n32)]
        prime_words.reverse()
        self._prime = _from_array32(prime_words)
        self._witness_size = ex["getWitnessSize"](store)
        self._input_size = ex["getInputSize"](store)

    # ────────────────────────────────────────────────────────────────
    # Public API
    # ────────────────────────────────────────────────────────────────

    @property
    def prime(self) -> int:
        return self._prime

    @property
    def witness_size(self) -> int:
        return self._witness_size

    def calculate_witness(self, inputs: Dict[str, Any], sanity_check: bool = False) -> List[int]:
        ex = self._exports
        store = self._store
        ex["init"](store, 1 if sanity_check else 0)

        qualified: Dict[str, List[int]] = {}
        _qualify_input("", inputs, qualified)

        input_counter = 0
        for k, flat in qualified.items():
            h = _fnv_hash(k)
            h_msb = (h >> 32) & 0xFFFFFFFF
            h_lsb = h & 0xFFFFFFFF
            signal_size = ex["getInputSignalSize"](store, h_msb, h_lsb)
            if signal_size < 0:
                raise WitnessCalculatorError(f"Signal {k!r} not found in circuit")
            if len(flat) < signal_size:
                raise WitnessCalculatorError(
                    f"Not enough values for input signal {k!r}: "
                    f"got {len(flat)}, expected {signal_size}"
                )
            if len(flat) > signal_size:
                raise WitnessCalculatorError(
                    f"Too many values for input signal {k!r}: "
                    f"got {len(flat)}, expected {signal_size}"
                )
            for i, raw in enumerate(flat):
                normalized = raw % self._prime
                if normalized < 0:
                    normalized += self._prime
                words = _to_array32(normalized, self._n32)
                # Big-endian; circom stores little-endian limbs in RWMemory
                # (writing index j ← word at position n32-1-j).
                # Sign-mask the high bit so wasmtime accepts as i32.
                for j in range(self._n32):
                    w = words[self._n32 - 1 - j]
                    if w >= 0x80000000:
                        w -= 0x100000000
                    ex["writeSharedRWMemory"](store, j, w)
                ex["setInputSignal"](store, h_msb, h_lsb, i)
                input_counter += 1

        if input_counter < self._input_size:
            raise WitnessCalculatorError(
                f"Not all inputs set ({input_counter}/{self._input_size})"
            )

        witness: List[int] = []
        for i in range(self._witness_size):
            ex["getWitness"](store, i)
            words = [ex["readSharedRWMemory"](store, j) for j in range(self._n32)]
            words.reverse()
            witness.append(_from_array32(words))
        return witness

    # ────────────────────────────────────────────────────────────────
    # Internal
    # ────────────────────────────────────────────────────────────────

    def _instantiate(self, linker: Linker, store: Store, module: Module) -> Instance:
        from wasmtime import FuncType, ValType

        def exception_handler(code: int) -> None:
            msgs = {
                1: "Signal not found.",
                2: "Too many signals set.",
                3: "Signal already set.",
                4: "Assert Failed.",
                5: "Not enough memory.",
                6: "Input signal array access exceeds the size.",
            }
            err = msgs.get(code, f"Unknown error (code {code}).")
            err = err + " " + " ".join(self._error_buf) if self._error_buf else err
            raise WitnessCalculatorError(err)

        def print_error_message() -> None:
            self._error_buf.append("<error>")

        def write_buffer_message() -> None:
            self._message_buf.append("<msg>")

        def show_shared_rw_memory() -> None:
            # Used by sanity-check builds for printing intermediate signals.
            pass

        ty_void_i = FuncType([ValType.i32()], [])
        ty_void = FuncType([], [])

        linker.define_func(
            "runtime", "exceptionHandler", ty_void_i, exception_handler
        )
        linker.define_func(
            "runtime", "printErrorMessage", ty_void, print_error_message
        )
        linker.define_func(
            "runtime", "writeBufferMessage", ty_void, write_buffer_message
        )
        linker.define_func(
            "runtime", "showSharedRWMemory", ty_void, show_shared_rw_memory
        )

        return linker.instantiate(store, module)
