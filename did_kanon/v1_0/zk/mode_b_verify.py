"""Verifier-side Mode B helper — checks a `kanonZkProof` attribute end-to-end.

Mirrors `KanonWrappedAnonCredsVerifierService` in the v6 credo plugin
without depending on credo. Useful for two cases:

  * The Python ACA-Py verifier wants to confirm a Mode B presentation
    after the standard CL verification passes.
  * A test / admin route wants to verify a `kanonZkProof` blob directly
    given a credDefId.

The verification has three independent layers — ALL must pass:

  1. **SNARK validity** — the Groth16 proof is valid under the
     non-revocation circuit's verification key.
  2. **Issuer binding** — `publicSignals[3..4]` equals
     `getIssuerZkPubKey(credDefId).{ax, ay}` on chain. The issuer can't
     forge a proof under someone else's BJJ key.
  3. **Root recency** — the Poseidon root in `publicSignals[0]` is among
     the credDef's recent published roots. Stale roots are rejected.

We delegate (1) + (3) to the on-chain
`MerkleStateRegistry.verifyZKMembership(credDefId, proofBytes,
publicSignals)` view — the chain already has the verifier deployed and
maintains the sliding-window of recent roots. Layer (2) is checked
independently against `CredentialDefinitionRegistry.getIssuerZkPubKey`.

publicSignals layout (matches SDK / circuit):

  [0] Poseidon root
  [1] credDef felt              (uint256(credDefId) mod p)
  [2] verifier challenge
  [3] issuer Ax
  [4] issuer Ay
  [5] disclosed slot index
  [6] disclosed slot felt
"""

from __future__ import annotations

import base64
import logging
from typing import Dict, List, Tuple

from eth_abi import decode as abi_decode

from did_kanon.v1_0.zk.poseidon import BN254_PRIME


LOGGER = logging.getLogger(__name__)


def _decode_kanon_zk_proof_attr(value: str) -> Tuple[bytes, List[bytes]]:
    """Inverse of the SDK's `encodeKanonZkProofAttr` — recover
    `(proofBytes, publicSignals)` from the base64 wire form.
    """
    try:
        raw = base64.b64decode(value)
    except Exception as err:
        raise ValueError(f"kanonZkProof is not valid base64: {err}") from err

    try:
        # ABI: (bytes proofBytes, bytes32[] publicSignals).
        proof_bytes, public_signals = abi_decode(["bytes", "bytes32[]"], raw)
    except Exception as err:
        raise ValueError(
            f"kanonZkProof abi-decode failed: {err}"
        ) from err

    if not isinstance(proof_bytes, (bytes, bytearray)) or len(proof_bytes) == 0:
        raise ValueError("kanonZkProof: proofBytes is empty")
    if not isinstance(public_signals, (list, tuple)) or len(public_signals) != 7:
        raise ValueError(
            f"kanonZkProof: expected 7 publicSignals, got {len(public_signals)}"
        )
    # Each entry is a `bytes32` — keep as 32-byte values.
    public_signals_list: List[bytes] = [bytes(p) for p in public_signals]
    for sig in public_signals_list:
        if len(sig) != 32:
            raise ValueError(
                f"kanonZkProof: publicSignals entry length {len(sig)} (expected 32)"
            )
    return bytes(proof_bytes), public_signals_list


def _to_bytes32_credef_id(cred_def_id_hex: str) -> bytes:
    s = (
        cred_def_id_hex[2:]
        if cred_def_id_hex.lower().startswith("0x")
        else cred_def_id_hex
    )
    if len(s) != 64:
        raise ValueError(
            f"cred_def_id hex must be 64 chars (32 bytes); got {len(s)}"
        )
    return bytes.fromhex(s)


async def verify_mode_b_proof(
    pool,
    cred_def_id_hex: str,
    kanon_zk_proof_b64: str,
) -> Dict:
    """Verify a Mode B presentation's `kanonZkProof` attribute.

    Returns a dict suitable for direct JSON response:

      {
        "verified": bool,
        "reason":   str | None,
        "checks":   {
          "credDefBinding":  bool,
          "issuerKeyOnChain": bool,
          "issuerKeyBinding": bool,
          "rootAndProof":     bool,
        }
      }

    `pool` is a `KanonRegistryPool` (or anything with `.cred_def` and
    `.merkle` attributes exposing the cred-def + merkle state registries).
    """
    cd_bytes = _to_bytes32_credef_id(cred_def_id_hex)
    proof_bytes, public_signals = _decode_kanon_zk_proof_attr(kanon_zk_proof_b64)

    checks = {
        "credDefBinding": False,
        "issuerKeyOnChain": False,
        "issuerKeyBinding": False,
        "rootAndProof": False,
    }

    # ── (a) credDef binding ────────────────────────────────────────────
    cred_def_felt = int.from_bytes(cd_bytes, "big") % BN254_PRIME
    sig_cred_def_felt = int.from_bytes(public_signals[1], "big")
    if sig_cred_def_felt != cred_def_felt:
        return {
            "verified": False,
            "reason": (
                f"credDef binding failed: publicSignals[1] {hex(sig_cred_def_felt)} "
                f"!= credDef felt {hex(cred_def_felt)}"
            ),
            "checks": checks,
        }
    checks["credDefBinding"] = True

    # ── (b) issuer key on chain ───────────────────────────────────────
    registries = pool.for_network()
    issuer_key = await registries.cred_def.get_issuer_zk_pub_key(cd_bytes)
    if issuer_key is None or not issuer_key.get("set"):
        return {
            "verified": False,
            "reason": "credDef has no issuer zk public key set (Mode B not enabled?)",
            "checks": checks,
        }
    checks["issuerKeyOnChain"] = True

    # ── (c) issuer key binding ────────────────────────────────────────
    sig_ax = int.from_bytes(public_signals[3], "big")
    sig_ay = int.from_bytes(public_signals[4], "big")
    if sig_ax != issuer_key["ax"] or sig_ay != issuer_key["ay"]:
        return {
            "verified": False,
            "reason": (
                "issuer key binding failed: "
                f"publicSignals[3..4]=({hex(sig_ax)}, {hex(sig_ay)}) "
                f"!= on-chain (ax, ay)=({hex(issuer_key['ax'])}, {hex(issuer_key['ay'])})"
            ),
            "checks": checks,
        }
    checks["issuerKeyBinding"] = True

    # ── (d) on-chain SNARK + root-recency check ──────────────────────
    # The contract's verifyZKMembership view runs the deployed Halo2/Groth16
    # verifier AND checks the Poseidon root in publicSignals[0] is among the
    # credDef's recent roots. Pass through unchanged.
    try:
        chain_ok = await registries.merkle.verify_zk_membership(
            cd_bytes,
            proof_bytes,
            public_signals,
        )
    except Exception as err:  # noqa: BLE001
        return {
            "verified": False,
            "reason": f"on-chain verifyZKMembership failed: {err}",
            "checks": checks,
        }
    checks["rootAndProof"] = bool(chain_ok)
    if not chain_ok:
        return {
            "verified": False,
            "reason": "on-chain verifyZKMembership returned false",
            "checks": checks,
        }

    return {"verified": True, "reason": None, "checks": checks}


__all__ = ["verify_mode_b_proof"]
