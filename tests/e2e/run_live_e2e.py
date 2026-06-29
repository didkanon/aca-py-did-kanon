"""Live end-to-end check against the kanonv2 deployment on besu-ajna.

Exercises the real contracts through the plugin's wrapper clients: org
onboarding -> DID register/resolve -> schema register/get (inline data: URI)
-> credDef register/get -> per-credential status issue/revoke.

Run (operator key supplied via env, never hardcoded):

    KANON_RPC_URL=https://besu.essi.studio \
    KANON_CHAIN_ID=1947 \
    KANON_DEPLOYMENT_FILE=/path/to/kanonv2/deployments/1947.json \
    KANON_OPERATOR_KEY=0x... \
    python tests/e2e/run_live_e2e.py
"""

import asyncio
import base64
import json
import time

from web3 import Web3

from did_kanon.v1_0.config import DidKanonConfig
from did_kanon.v1_0.contracts.cred_def_registry import TIER_ONE_TIME
from did_kanon.v1_0.contracts.pool import KanonRegistries
from did_kanon.v1_0.identifiers import (
    cred_def_resource_id,
    org_did,
    schema_resource_id,
)

# DIDScope.Org = 1, VerificationMethodType.Ed25519 = 0.
_SCOPE_ORG = 1
_VM_ED25519 = 0
_ZERO32 = b"\x00" * 32


def b32(text: str) -> bytes:
    return Web3.keccak(text=text)


def ok(label: str) -> None:
    print(f"  \033[32mPASS\033[0m {label}")


async def main() -> None:
    cfg = DidKanonConfig.from_environment()
    net = cfg.network()
    reg = KanonRegistries(net)  # verifies chainId + code on construction
    operator = reg.operator_address
    assert operator, "no operator key configured (set KANON_OPERATOR_KEY)"
    ts = int(time.time())
    print(f"chain={reg.w3.eth.chain_id} operator={operator}")

    # ── 1. Org onboarding ────────────────────────────────────────────────
    print("\n[1] org onboarding")
    org_id = await reg.org.register_org_and_get_id(f"e2e-org-{ts}", operator)
    assert await reg.org.is_admin(org_id, operator), "operator should be org admin"
    assert await reg.org.is_member(org_id, operator), "admin is implicitly a member"
    await reg.org.approve_org(org_id)
    assert await reg.org.is_approved_and_active(org_id), "org must be approved+active"
    ok(f"org {org_id} registered, approved, operator is member")

    issuer = org_did(org_id)

    # ── 2. DID register + resolve ────────────────────────────────────────
    print("\n[2] DID register + resolve")
    kid = issuer + "#key-1"
    vm_id = Web3.keccak(text=kid)
    pubkey = Web3.keccak(text=f"pk-{ts}")  # 32-byte stand-in Ed25519 key
    doc_hash = Web3.keccak(text=f"doc-{ts}")
    doc = (
        Web3.to_checksum_address(operator),       # controller
        org_id,                                    # orgId
        _SCOPE_ORG,                                # scope
        [(vm_id, _VM_ED25519, pubkey)],            # verificationMethods
        [vm_id],                                   # authentication
        [vm_id],                                   # assertionMethod
        [], [], [],                                # capability*/keyAgreement
        [],                                        # services
        doc_hash,                                  # docHash
        0, 0, False,                               # createdAt/updatedAt/deactivated
    )
    await reg.did.register_did(issuer, _ZERO32, doc)
    assert await reg.did.exists(issuer), "DID should exist after register"
    resolved = await reg.did.resolve_did(issuer)
    assert resolved is not None, "resolveDID returned None"
    assert resolved["scope"] == _SCOPE_ORG
    assert resolved["org_id"].lower() == org_id.lower()
    assert resolved["verification_methods"][0]["id"] == vm_id
    ok(f"DID {issuer} registered + resolved (1 VM, scope=org)")

    # ── 3. Schema (inline data: URI) ─────────────────────────────────────
    print("\n[3] schema register + get")
    name, version = f"Passport{ts}", "1.0"
    schema_id = schema_resource_id(issuer, name, version)
    body = {"name": name, "version": version, "attrNames": ["given", "family"], "issuerId": issuer}
    uri = "data:application/json;base64," + base64.b64encode(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    await reg.schema.register_schema(org_id, b32(schema_id), b32(uri), uri)
    assert await reg.schema.is_active(b32(schema_id)), "schema should be active"
    got = await reg.schema.get_schema(b32(schema_id))
    assert got is not None and got["uri"] == uri, "schema uri round-trip"
    decoded = json.loads(base64.b64decode(got["uri"].split(",", 1)[1]))
    assert decoded["attrNames"] == ["given", "family"], "inline attrNames round-trip"
    ok(f"schema {schema_id} registered + body round-tripped via data: URI")

    # ── 4. CredDef ───────────────────────────────────────────────────────
    print("\n[4] credDef register + get")
    cred_def_id = cred_def_resource_id(issuer, name, "default")
    issuer_pub = b32(f"cl-body-{ts}")  # 32-byte anchor for the off-chain CL body
    await reg.cred_def.register_credential_definition(
        b32(cred_def_id), b32(schema_id), issuer_pub, TIER_ONE_TIME
    )
    assert await reg.cred_def.exists(b32(cred_def_id)), "credDef should exist"
    assert await reg.cred_def.supports_tier(b32(cred_def_id), TIER_ONE_TIME)
    cd = await reg.cred_def.get_credential_definition(b32(cred_def_id))
    assert cd is not None and cd["policy_mask"] == TIER_ONE_TIME
    assert cd["schema_id"] == b32(schema_id)
    ok(f"credDef {cred_def_id} registered + resolved (tier 1)")

    # ── 5. Per-credential status ─────────────────────────────────────────
    print("\n[5] status issue + revoke")
    cred_id_hash = Web3.keccak(text=f"cred-{ts}")
    await reg.status.issue_credential(b32(cred_def_id), cred_id_hash)
    assert await reg.status.is_active(b32(cred_def_id), cred_id_hash), "issued => active"
    assert not await reg.status.is_revoked(b32(cred_def_id), cred_id_hash)
    await reg.status.revoke_credential(b32(cred_def_id), cred_id_hash)
    assert await reg.status.is_revoked(b32(cred_def_id), cred_id_hash), "revoked"
    assert not await reg.status.is_active(b32(cred_def_id), cred_id_hash)
    ok("credential issued (active) then revoked (revoked)")

    print("\n\033[32mALL E2E CHECKS PASSED\033[0m")


if __name__ == "__main__":
    asyncio.run(main())
