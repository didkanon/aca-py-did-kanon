"""did:kanon identifier parsing for the kanonv2 registries.

kanonv2 binds the DID identifier to its subject, so there are exactly two
shapes (no free-form network segment like the legacy method had):

  * org-scoped  : ``did:kanon:org:0x<64 hex>``  (the bytes32 orgId)
  * user-scoped : ``did:kanon:user:0x<64 hex>``  (bound to controller+salt)

AnonCreds resource IDs are DID URLs under the issuer DID, e.g.
``did:kanon:org:0x<64 hex>/anoncreds/v0/SCHEMA/<name>/<version>``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


_ORG_ID = r"(?P<org_id>0x[0-9a-fA-F]{64})"
_USER_HEX = r"(?P<user_hex>0x[0-9a-fA-F]{64})"
_SUBJECT = rf"(?:org:{_ORG_ID}|user:{_USER_HEX})"
_PATH = r"(?P<path>/[^#?]*)?"
_QUERY = r"(?P<query>\?[^#]*)?"
_FRAGMENT = r"(?P<fragment>#.*)?"

KANON_DID_REGEX = re.compile(rf"^did:kanon:{_SUBJECT}$")
KANON_DID_URL_REGEX = re.compile(rf"^did:kanon:{_SUBJECT}{_PATH}{_QUERY}{_FRAGMENT}$")
# Matches anything starting with did:kanon — used as the resolver's
# `supported_did_regex` and the AnonCreds registry's
# `supported_identifiers_regex` (schema/credDef IDs are DID URLs).
KANON_PREFIX_REGEX = re.compile(r"^did:kanon:.+$")

# AnonCreds resource path prefix under an issuer DID.
_ANONCREDS_PREFIX = "/anoncreds/v0"


@dataclass
class ParsedKanonDid:
    """Decomposed did:kanon URI."""

    did: str
    scope: str  # "org" | "user"
    org_id: Optional[str] = None  # bytes32 orgId as 0x<64 hex>
    user_hex: Optional[str] = None
    path: Optional[str] = None
    query: Optional[str] = None
    fragment: Optional[str] = None


def org_did(org_id: str) -> str:
    return f"did:kanon:org:{org_id}"


def user_did(hex_handle: str) -> str:
    h = hex_handle if hex_handle.startswith("0x") else "0x" + hex_handle
    return f"did:kanon:user:{h}"


def parse_kanon_did(did_url: str) -> Optional[ParsedKanonDid]:
    """Return the decomposed DID URL or None if it doesn't match."""
    if not did_url:
        return None
    match = KANON_DID_URL_REGEX.match(did_url)
    if not match:
        return None
    org_raw = match.group("org_id")
    if org_raw is not None:
        scope, org_id, user_hex = "org", org_raw, None
        base = org_did(org_id)
    else:
        scope, org_id, user_hex = "user", None, match.group("user_hex")
        base = user_did(user_hex)
    return ParsedKanonDid(
        did=base,
        scope=scope,
        org_id=org_id,
        user_hex=user_hex,
        path=match.group("path"),
        query=match.group("query"),
        fragment=match.group("fragment"),
    )


def issuer_did_of(resource_id: str) -> Optional[str]:
    """The issuer DID prefix of an AnonCreds resource id (the part before
    the first `/`), or None if the id is not a did:kanon URL."""
    parsed = parse_kanon_did(resource_id)
    return parsed.did if parsed else None


def schema_resource_id(issuer_did: str, name: str, version: str) -> str:
    return f"{issuer_did}{_ANONCREDS_PREFIX}/SCHEMA/{name}/{version}"


def cred_def_resource_id(issuer_did: str, schema_tag: str, tag: str) -> str:
    return f"{issuer_did}{_ANONCREDS_PREFIX}/CLAIM_DEF/{schema_tag}/{tag}"
