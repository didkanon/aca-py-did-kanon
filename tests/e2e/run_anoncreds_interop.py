"""Drive the REAL plugin AnonCreds registry against the live chain and verify
the schema-hash convention matches what the JS SDK verifier checks
(`schemaHash == keccak256(canonical JSON)`), proving Python<->JS interop.

Reuses org 1 (approved in the prior e2e) as issuer did:kanon:org:1.
"""

import asyncio
import base64
import json
import time

from acapy_agent.anoncreds.models.schema import AnonCredsSchema
from web3 import Web3

from did_kanon.v1_0.anoncreds.registry import KanonAnonCredsRegistry
from did_kanon.v1_0.config import DidKanonConfig
from did_kanon.v1_0.contracts.pool import KanonRegistryPool


def ok(label: str) -> None:
    print(f"  \033[32mPASS\033[0m {label}")


async def main() -> None:
    cfg = DidKanonConfig.from_environment()
    pool = KanonRegistryPool(cfg)
    registry = KanonAnonCredsRegistry(pool)
    reg = pool.for_network()
    print(f"chain={reg.w3.eth.chain_id} operator={reg.operator_address}")

    ts = int(time.time())
    issuer = "did:kanon:org:1"
    schema = AnonCredsSchema(
        issuer_id=issuer,
        attr_names=["given_name", "family_name", "dob"],
        name=f"Passport{ts}",
        version="1.0",
    )

    # 1. register via the actual plugin registrar
    res = await registry.register_schema(None, schema, {})
    schema_id = res.schema_state.schema_id
    ok(f"plugin register_schema -> {schema_id} (tx {res.registration_metadata['tx_hash'][:12]}…)")

    # 2. resolve via the actual plugin resolver (data: URI decode)
    got = await registry.get_schema(None, schema_id)
    assert got.schema.attr_names == ["given_name", "family_name", "dob"]
    assert got.schema.name == schema.name
    ok("plugin get_schema round-trips name + attrNames from inline data: URI")

    # 3. confirm the on-chain schemaHash == keccak256(canonical JSON) — the
    #    exact formula the SDK's VerifierService.validateSchemaJson uses.
    schema_id_32 = Web3.keccak(text=schema_id)
    on_chain = await reg.schema.get_schema(schema_id_32)
    canonical = base64.b64decode(on_chain["uri"].split(",", 1)[1])
    expected = Web3.keccak(canonical)
    assert on_chain["schema_hash"] == expected, (
        f"schemaHash mismatch: on-chain {on_chain['schema_hash'].hex()} "
        f"!= keccak(canonical) {expected.hex()}"
    )
    # And the canonical body is exactly the schema fields.
    body = json.loads(canonical)
    assert body["attrNames"] == ["given_name", "family_name", "dob"]
    ok("on-chain schemaHash == keccak256(canonical JSON)  → SDK verifier will validate")

    print(f"\nschemaId(str) = {schema_id}")
    print(f"schemaId(b32) = 0x{schema_id_32.hex()}")
    print("\n\033[32mANONCREDS INTEROP CHECKS PASSED\033[0m")


if __name__ == "__main__":
    asyncio.run(main())
