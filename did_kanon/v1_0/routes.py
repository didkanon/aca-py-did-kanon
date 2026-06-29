from __future__ import annotations

import json
import logging
import re
from typing import Optional
from urllib.parse import urlparse, urlunparse

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from marshmallow import fields

from did_kanon.v1_0.config import DidKanonConfig
from did_kanon.v1_0.did.registrar import KanonDIDRegistrar

LOGGER = logging.getLogger(__name__)


class KanonRegisterDidRequestSchema(OpenAPISchema):
    network = fields.Str(required=False, allow_none=True)
    seed = fields.Str(required=False, allow_none=True)
    # Issuer DIDs are org-scoped (did:kanon:org:<orgId>); holder DIDs are
    # user-scoped. Default to "org" so the innkeeper register-did flow mints
    # the issuer's org DID from KANON_ORG_ID without extra arguments.
    scope = fields.Str(required=False, allow_none=True)
    org_id = fields.Int(required=False, allow_none=True)
    services = fields.List(fields.Dict(), required=False, allow_none=True)


class KanonRegisterDidResponseSchema(OpenAPISchema):
    did = fields.Str()
    verkey = fields.Str()
    did_document = fields.Dict()
    tx_hash = fields.Str()
    network = fields.Str()


class KanonImportDidRequestSchema(OpenAPISchema):
    # seed is required — without it there's nothing to derive a keypair
    # from and the whole point of import is wallet-storage of a
    # known-existing on-chain DID.
    seed = fields.Str(required=True)
    network = fields.Str(required=False, allow_none=True)
    scope = fields.Str(required=False, allow_none=True)
    org_id = fields.Int(required=False, allow_none=True)


class KanonImportDidResponseSchema(OpenAPISchema):
    did = fields.Str()
    verkey = fields.Str()
    network = fields.Str()


def _redact_rpc_url(rpc_url: str) -> str:
    """Strip query string and userinfo from an RPC URL.

    Provider URLs often embed API keys in the query string
    (Alchemy/Infura) or as Basic-auth userinfo. Returning the raw URL
    to any authenticated tenant is a credential leak.
    """
    try:
        parsed = urlparse(rpc_url)
    except Exception:
        return ""
    netloc = parsed.hostname or ""
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunparse((parsed.scheme, netloc, parsed.path, "", "", ""))


@docs(tags=["did-kanon"], summary="Mint a new did:kanon DID and register it on chain")
@request_schema(KanonRegisterDidRequestSchema())
@response_schema(KanonRegisterDidResponseSchema(), 201)
@tenant_authentication
async def kanon_register_did(request: web.BaseRequest):
    context: AdminRequestContext = request["context"]
    registrar: KanonDIDRegistrar = context.inject(KanonDIDRegistrar)
    body = await request.json() if request.body_exists else {}
    network: Optional[str] = body.get("network")
    seed: Optional[str] = body.get("seed")
    scope: str = body.get("scope") or "org"
    org_id: Optional[int] = body.get("org_id")
    services = body.get("services")

    try:
        result = await registrar.register(
            context.profile,
            network=network,
            seed=seed,
            scope=scope,
            org_id=org_id,
            services=services,
        )
    except ValueError as err:
        raise web.HTTPBadRequest(
            reason="Bad Request",
            text=json.dumps({"error": str(err)}),
            content_type="application/json",
        ) from err
    except Exception as err:
        # NEVER echo str(err) here — web3 exceptions can carry the
        # RPC URL, raw transaction payload, or key material.
        LOGGER.exception("did:kanon: register failed")
        raise web.HTTPInternalServerError(
            reason="Internal Server Error",
            text=json.dumps({"error": "internal error registering DID"}),
            content_type="application/json",
        ) from err

    return web.json_response(
        {
            "did": result.did,
            "verkey": result.verkey,
            "did_document": result.did_document,
            "tx_hash": result.tx_hash,
            "network": result.network,
        },
        status=201,
    )


@docs(tags=["did-kanon"], summary="List configured Kanon networks")
@tenant_authentication
async def kanon_list_networks(request: web.BaseRequest):
    context: AdminRequestContext = request["context"]
    config: DidKanonConfig = context.inject(DidKanonConfig)
    # Deliberately omit `rpc_url` and `contract_address` from the
    # tenant-visible response — RPC URLs frequently embed API keys in
    # query strings, and the contract address is operational config
    # that shouldn't be enumerated by every authenticated tenant.
    return web.json_response(
        {
            "default_network": config.default_network,
            "networks": [
                {
                    "name": net.name,
                    "chain_id": net.chain_id,
                    "operator_configured": bool(net.operator_key),
                }
                for net in config.networks.values()
            ],
        }
    )


# policyMask bit flags — kept in sync with kanonv2 contracts +
# `did_kanon.v1_0.contracts.cred_def_registry`.
TIER_ONE_TIME = 1
TIER_ZK_SNARK = 2


def _cred_id_hash(cred_id: str) -> bytes:
    """Mirror of `kanonCredIdHash` in the SDK / credo-ts plugin."""
    from web3 import Web3

    return Web3.keccak(text=cred_id)


@docs(
    tags=["did-kanon"],
    summary="Revoke a credential across whichever revocation tiers the credDef supports",
)
@tenant_authentication
async def kanon_revoke(request: web.BaseRequest):
    """Body: `{ "cred_ids": [...], "network": "<optional>" }`.

    Reads the credDef's on-chain `policyMask`:
      - if `TIER_ONE_TIME`, writes `revokeCredential` to AnonCredsStatusRegistry
      - if `TIER_ZK_SNARK`, calls the ZK issuer's `revoke` (which rotates the
        Merkle root via `batchUpdate`)
      - both writes happen for a `TIER_ALL` credDef

    Returns a dict with each surface that was touched.
    """
    cred_def_id = request.match_info["cred_def_id"]
    body = await request.json()
    cred_ids = body.get("cred_ids") or []
    cred_ex_ids = body.get("cred_ex_ids") or []
    if not isinstance(cred_ids, list) or any(not isinstance(c, str) for c in cred_ids):
        raise web.HTTPBadRequest(text=json.dumps({"error": "cred_ids must be string[]"}))
    if not isinstance(cred_ex_ids, list) or any(
        not isinstance(c, str) for c in cred_ex_ids
    ):
        raise web.HTTPBadRequest(
            text=json.dumps({"error": "cred_ex_ids must be string[]"})
        )

    context: AdminRequestContext = request["context"]
    config = context.inject(DidKanonConfig)

    # Resolve cred_ex_ids to kanonCredIds via the binding the issuance
    # listener wrote at issue time. Lets callers revoke by the visible
    # ACA-Py `cred_ex_id` for schema-clean Mode A credentials (no
    # `kanonCredId` attribute on the schema).
    if cred_ex_ids:
        from did_kanon.v1_0.anoncreds.revreg_state import lookup_cred_id_by_credex

        resolved: list[str] = []
        missing: list[str] = []
        for cex in cred_ex_ids:
            rec = await lookup_cred_id_by_credex(context.profile, cex)
            if rec and rec.get("kanon_cred_id"):
                resolved.append(rec["kanon_cred_id"])
            else:
                missing.append(cex)
        if missing:
            raise web.HTTPNotFound(
                text=json.dumps(
                    {
                        "error": "no kanonCredId binding for cred_ex_id(s)",
                        "missing": missing,
                    }
                )
            )
        cred_ids = list(cred_ids) + resolved

    if not cred_ids:
        return web.json_response({"mode_a": 0, "mode_b": 0})

    from did_kanon.v1_0.contracts.pool import KanonRegistryPool
    from web3 import Web3

    network = body.get("network") or config.default_network
    pool = context.inject(KanonRegistryPool)
    registries = pool.for_network(network)
    cred_def_bytes = Web3.keccak(text=cred_def_id)

    cred_def_record = await registries.cred_def.get_credential_definition(cred_def_bytes)
    if cred_def_record is None:
        raise web.HTTPNotFound(
            text=json.dumps({"error": f"credDef not found: {cred_def_id}"})
        )
    policy_mask = int(cred_def_record["policy_mask"])

    result = {"mode_a": 0, "mode_b": 0, "policy_mask": policy_mask}

    try:
        # ── Mode A ──
        if policy_mask & TIER_ONE_TIME:
            for cid in cred_ids:
                await registries.status.revoke_credential(
                    cred_def_bytes, _cred_id_hash(cid)
                )
            result["mode_a"] = len(cred_ids)

        # ── Mode B ──
        if policy_mask & TIER_ZK_SNARK:
            from did_kanon.v1_0.zk.zk_issuer import KanonZkIssuer

            issuer = KanonZkIssuer(registries.merkle, context.profile)
            # `KanonZkIssuer.revoke` expects a 32-byte cred_def_id (raw
            # bytes or hex), not the DID URL — same convention as
            # `add_issued`. Hash it the way the chain side does so the
            # leaf state lookup keys match.
            receipt = await issuer.revoke(cred_def_bytes, cred_ids)
            result["mode_b"] = len(cred_ids)
            if receipt is not None:
                result["mode_b_receipt"] = receipt

        return web.json_response(result)
    except Exception as err:
        # NEVER echo str(err) here — RegistryTxClient errors can carry the
        # RPC URL (with embedded API keys), raw revert payloads, or other
        # operator-internal state. Same convention as register/import.
        LOGGER.exception("did:kanon: revoke failed for %s", cred_def_id)
        raise web.HTTPInternalServerError(
            reason="Internal Server Error",
            text=json.dumps({"error": "internal error revoking credential", "partial": result}),
            content_type="application/json",
        ) from err


class KanonPrepareModeBRequestSchema(OpenAPISchema):
    cred_def_id = fields.Str(required=True)
    domain_attributes = fields.Dict(
        keys=fields.Str(), values=fields.Str(), required=True
    )


class KanonPrepareModeBResponseSchema(OpenAPISchema):
    attributes = fields.Dict(keys=fields.Str(), values=fields.Str())
    kanon_cred_id = fields.Str()
    kanon_zk_sig = fields.Str()


@docs(
    tags=["did-kanon"],
    summary="Prepare a Mode B credential attribute set "
    "(injects kanonCredId + kanonZkSig).",
)
@request_schema(KanonPrepareModeBRequestSchema())
@response_schema(KanonPrepareModeBResponseSchema(), 200)
@tenant_authentication
async def kanon_prepare_mode_b(request: web.BaseRequest):
    """Build the AnonCreds preview attribute set for a Mode B credential.

    Caller hands in the domain attributes (the credential's actual data
    fields); we mint a fresh kanonCredId, sign the canonical leaf with
    the credDef's BabyJubjub issuer key, and return the merged attribute
    set the AnonCreds /issue-credential flow should use.

    No chain writes. Idempotent w.r.t. the per-credDef BJJ key (re-uses
    persisted one). The credDef MUST already be registered with a
    non-zero `(ax, ay)` on chain — register it via the AnonCreds
    `/anoncreds/credential-definition` endpoint with a policy mask that
    includes TIER_ZK_SNARK first.
    """
    context: AdminRequestContext = request["context"]
    body = await request.json() if request.body_exists else {}
    cred_def_id = body.get("cred_def_id")
    domain_attributes = body.get("domain_attributes") or {}

    if not isinstance(cred_def_id, str) or not re.fullmatch(
        r"0x[0-9a-fA-F]{64}", cred_def_id
    ):
        raise web.HTTPBadRequest(
            text=json.dumps({"error": "cred_def_id must be a 0x-prefixed 32-byte hex string"})
        )
    if not isinstance(domain_attributes, dict) or not all(
        isinstance(k, str) and isinstance(v, str)
        for k, v in domain_attributes.items()
    ):
        raise web.HTTPBadRequest(
            text=json.dumps({"error": "domain_attributes must be a {str: str} map"})
        )

    from did_kanon.v1_0.zk.mode_b import prepare_mode_b_credential
    from did_kanon.v1_0.zk.zk_issuer_key import KanonZkIssuerKeyService

    try:
        issuer_key_service = KanonZkIssuerKeyService(context.profile)
        prep = await prepare_mode_b_credential(
            issuer_key_service,
            cred_def_id,
            domain_attributes,
        )
    except ValueError as err:
        raise web.HTTPBadRequest(text=json.dumps({"error": str(err)}))
    except Exception:  # noqa: BLE001
        LOGGER.exception(
            "did:kanon: prepare-mode-b failed for credDef %s", cred_def_id
        )
        raise web.HTTPInternalServerError(
            text=json.dumps({"error": "internal error preparing Mode B credential"})
        )

    return web.json_response(
        {
            "attributes": prep.attributes,
            "kanon_cred_id": prep.kanon_cred_id,
            "kanon_zk_sig": prep.kanon_zk_sig,
        }
    )


class KanonVerifyModeBRequestSchema(OpenAPISchema):
    cred_def_id = fields.Str(required=True)
    kanon_zk_proof = fields.Str(required=True)


class KanonVerifyModeBResponseSchema(OpenAPISchema):
    verified = fields.Bool()
    reason = fields.Str(required=False, allow_none=True)
    checks = fields.Dict(required=False, allow_none=True)


@docs(
    tags=["did-kanon"],
    summary="Verify a Mode B kanonZkProof self-attested attribute",
)
@request_schema(KanonVerifyModeBRequestSchema())
@response_schema(KanonVerifyModeBResponseSchema(), 200)
@tenant_authentication
async def kanon_verify_mode_b(request: web.BaseRequest):
    """Verify a `kanonZkProof` attribute against a credDef.

    The caller hands in the base64-encoded `kanonZkProof` attribute value
    (the same string the holder put into the AnonCreds presentation's
    self-attested attributes). We:

      1. Base64-decode and abi-decode the wire form into
         `(proofBytes, publicSignals)`.
      2. Check `publicSignals[1]` matches `credDefId` (mod BN254 scalar).
      3. Check `publicSignals[3..4]` matches the on-chain
         `getIssuerZkPubKey(credDefId)` — binds the proof to THIS issuer.
      4. Call `MerkleStateRegistry.verifyZKMembership(credDefId,
         proofBytes, publicSignals)` for the on-chain SNARK + Merkle
         root recency check (the chain stores recent roots in a sliding
         window — root recency is part of the contract).

    Returns `{verified: bool, reason?: str, checks: {…}}`.
    """
    context: AdminRequestContext = request["context"]
    body = await request.json() if request.body_exists else {}
    cred_def_id = body.get("cred_def_id")
    kanon_zk_proof = body.get("kanon_zk_proof")

    if not isinstance(cred_def_id, str) or not re.fullmatch(
        r"0x[0-9a-fA-F]{64}", cred_def_id
    ):
        raise web.HTTPBadRequest(
            text=json.dumps({"error": "cred_def_id must be a 0x-prefixed 32-byte hex string"})
        )
    if not isinstance(kanon_zk_proof, str) or not kanon_zk_proof:
        raise web.HTTPBadRequest(
            text=json.dumps({"error": "kanon_zk_proof must be a non-empty base64 string"})
        )

    from did_kanon.v1_0.contracts.pool import KanonRegistryPool
    from did_kanon.v1_0.zk.mode_b_verify import verify_mode_b_proof

    config = context.inject(DidKanonConfig)
    pool = context.inject(KanonRegistryPool)

    try:
        result = await verify_mode_b_proof(pool, cred_def_id, kanon_zk_proof)
    except ValueError as err:
        # ValueError is raised for caller-controlled input shape problems
        # (bad base64, malformed proofBytes, etc.) — surfacing the message
        # is OK because it never originates from the on-chain client and
        # is shaped by us. Internal exceptions take the generic path below.
        raise web.HTTPBadRequest(text=json.dumps({"error": str(err)}))
    except Exception:  # noqa: BLE001
        # NEVER echo str(err) — the verify path drops into the on-chain
        # client (verifyZKMembership) whose exceptions can carry the RPC
        # URL with embedded API keys or raw revert payloads. Same
        # convention as register/import/revoke.
        LOGGER.exception(
            "did:kanon: verify-mode-b failed for credDef %s", cred_def_id
        )
        return web.json_response({"verified": False, "reason": "verification failed"})

    return web.json_response(result)


@docs(tags=["did-kanon"], summary="Inspect the Mode B active leaf set for a cred-def")
@tenant_authentication
async def kanon_zk_checkpoint(request: web.BaseRequest):
    cred_def_id = request.match_info["cred_def_id"]
    context: AdminRequestContext = request["context"]
    config = context.inject(DidKanonConfig)
    network = request.query.get("network") or config.default_network
    from did_kanon.v1_0.contracts.pool import KanonRegistryPool
    pool = context.inject(KanonRegistryPool)
    registries = pool.for_network(network)

    from did_kanon.v1_0.zk.zk_issuer import KanonZkIssuer

    issuer = KanonZkIssuer(registries.merkle, context.profile)
    cp = await issuer.get_checkpoint(cred_def_id)
    return web.json_response(cp)


@docs(
    tags=["did-kanon"],
    summary="Recover wallet ownership of an already-registered did:kanon",
)
@request_schema(KanonImportDidRequestSchema())
@response_schema(KanonImportDidResponseSchema(), 200)
@tenant_authentication
async def kanon_import_did(request: web.BaseRequest):
    context: AdminRequestContext = request["context"]
    registrar: KanonDIDRegistrar = context.inject(KanonDIDRegistrar)
    body = await request.json() if request.body_exists else {}
    seed: Optional[str] = body.get("seed")
    network: Optional[str] = body.get("network")
    scope: str = body.get("scope") or "org"
    org_id: Optional[int] = body.get("org_id")

    if not seed:
        raise web.HTTPBadRequest(
            reason="Bad Request",
            text=json.dumps({"error": "seed is required"}),
            content_type="application/json",
        )

    try:
        result = await registrar.import_did(
            context.profile,
            seed=seed,
            network=network,
            scope=scope,
            org_id=org_id,
        )
    except ValueError as err:
        raise web.HTTPBadRequest(
            reason="Bad Request",
            text=json.dumps({"error": str(err)}),
            content_type="application/json",
        ) from err
    except Exception:
        # Never echo str(err) here — same redaction rationale as register.
        LOGGER.exception("did:kanon: import failed")
        raise web.HTTPInternalServerError(
            reason="Internal Server Error",
            text=json.dumps({"error": "internal error importing DID"}),
            content_type="application/json",
        )

    return web.json_response(
        {
            "did": result.did,
            "verkey": result.verkey,
            "network": result.network,
        }
    )


async def register(app: web.Application):
    app.add_routes([
        web.post("/did/kanon/register", kanon_register_did),
        web.post("/did/kanon/import", kanon_import_did),
        web.get("/did/kanon/networks", kanon_list_networks),
        # `revoke` reads the credDef's policyMask and dispatches to whichever
        # tier(s) it opted in to (Mode A status registry, Mode B Merkle root,
        # or both). This is the canonical revoke entry point.
        web.post("/did/kanon/revoke/{cred_def_id}", kanon_revoke),
        # Read-only inspection of the Mode B active-leaf set.
        web.get("/did/kanon/zk/checkpoint/{cred_def_id}", kanon_zk_checkpoint),
        # Issuer-side helper: produce a Mode B credential's full attribute set
        # (domain attrs + injected kanonCredId/kanonZkSig).
        web.post("/did/kanon/zk/prepare-mode-b", kanon_prepare_mode_b),
        # Verifier-side helper: verify a kanonZkProof attribute against the
        # credDef's on-chain (ax, ay) + Merkle root.
        web.post("/did/kanon/zk/verify-mode-b", kanon_verify_mode_b),
    ])


def post_process_routes(app: web.Application):
    """Add Swagger tag for the plugin's endpoints.

    aiohttp_apispec's `@docs(tags=[...])` already registers tags
    lazily on the spec, so this helper is intentionally minimal —
    it only injects the human-readable description when missing.
    """
    swagger_dict = app._state.get("swagger_dict")
    if not isinstance(swagger_dict, dict):
        return
    tags = swagger_dict.setdefault("tags", [])
    if any(t.get("name") == "did-kanon" for t in tags if isinstance(t, dict)):
        return
    tags.append(
        {
            "name": "did-kanon",
            "description": "did:kanon DID method + Ethereum-backed AnonCreds registry",
        }
    )
