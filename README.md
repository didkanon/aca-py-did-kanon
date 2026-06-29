# aca-py-did-kanon

ACA-Py plugin for the **kanon AnonCreds VDR** — adds `did:kanon` DID-method support and an AnonCreds registry backed by the kanon contracts on any EVM chain (Hyperledger Besu, Ethereum, L2s, private rollups).

Pairs with the credo-ts side ([`@ajna-inc/kanon`](https://www.npmjs.com/package/@ajna-inc/kanon)) so an ACA-Py issuer and a Credo holder can issue, present, and verify against the same on-chain VDR.

## What ships

| Module | Role |
|---|---|
| `did_kanon.v1_0.did` | `KanonDIDRegistrar`, `KanonDIDResolver` for `did:kanon:org:0x<32>` and `did:kanon:user:0x<32>` |
| `did_kanon.v1_0.anoncreds.registry` | `KanonAnonCredsRegistry` — registers + resolves schemas, cred-defs, and per-credential status against the kanon contracts |
| `did_kanon.v1_0.contracts` | typed handles for the seven kanon registries + a shared connection pool keyed on RPC URL |
| `did_kanon.v1_0.zk` | Tier-2 prover (Groth16 + Poseidon Merkle tree + witness) |
| `did_kanon.v1_0.cred_id_hash` | canonical `kanonCredId` attribute hash — interoperable with the credo-ts plugin |
| `did_kanon.v1_0.identifiers` | DID + AnonCreds resource-id parsing / building |
| `did_kanon.v1_0.routes` | admin HTTP routes (org register/approve, did mint, status set/get) |

## Install

```bash
pip install -e /path/to/aca-py-did-kanon
```

## Configure

Add the plugin to the ACA-Py startup args:

```yaml
plugin:
  - did_kanon
```

And a `plugin-config.yml` entry:

```yaml
did_kanon:
  rpc_url: https://besu.example.com
  # Either: single on-chain directory (resolves all 7 registries internally) ─
  address_book: "0x…"
  # Or: an inline deployment block of registry addresses + chainId.
  # deployment:
  #   chainId: 1947
  #   addresses:
  #     OrganizationRegistry: "0x…"
  #     DIDRegistry: "0x…"
  #     SchemaRegistry: "0x…"
  #     CredentialDefinitionRegistry: "0x…"
  #     MerkleStateRegistry: "0x…"
  #     Halo2VerifierRegistry: "0x…"
  #     AnonCredsStatusRegistry: "0x…"
  # Issuer org id (bytes32 as 0x<64 hex>) — only required for issuer agents.
  org_id: "0x…"
  # The operator's private key — fund this address with native gas before startup.
  operator_key: "${BESU_AJNA_DEPLOYER_KEY}"
  # auto_issuer=true tracks credential issuance on-chain when issuance finalises.
  auto_issuer: true
```

## Tests

```bash
pip install -e ".[dev]"
pytest
```

## Resource id format

Schemas and cred-defs are stored as DID URLs under the issuer DID — the standard AnonCreds v0/v1 resource-path shape, so the on-chain bytes32 key matches what `did:indy` and `did:cheqd` would produce structurally:

```
did:kanon:org:0x<64 hex>/anoncreds/v0/SCHEMA/<name>/<version>
did:kanon:org:0x<64 hex>/anoncreds/v0/CLAIM_DEF/<schemaTag>/<tag>
```

The on-chain key is `keccak256(utf8(resource_id))`. Both the credo-ts plugin and this plugin compute the same value, so each one resolves objects the other writes.

## Related repos

- Contracts: [`contracts`](https://github.com/didkanon/contracts)
- TypeScript SDK: [`sdk`](https://github.com/didkanon/sdk) — published as `@ajna-inc/kanon-sdk`
- Credo-ts plugin: [`credo-ts-kanon`](https://github.com/didkanon/credo-ts-kanon) — published as `@ajna-inc/kanon`

## License

Apache-2.0. See `LICENSE`.
