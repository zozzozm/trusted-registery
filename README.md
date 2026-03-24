# MPC Node Registry

A signed JSON registry for MPC custody node admission. Uses EIP-712 v2 typed data signatures with role-based governance -- each role (SYSTEM_ADMIN, POLICY_COMPLIANCE, TREASURY_OPS, AUDIT_OBSERVER) has its own quorum requirement. No blockchain required.

## How it works

1. **Governance roles** (Ethereum addresses) are embedded in the registry document -- SYSTEM_ADMIN requires 3 addresses with 2-of-3 quorum, other roles define their own quorum
2. **Registry documents** are nested JSON files signed by all roles meeting their quorum via MetaMask/Ledger (EIP-712 v2)
3. **Chain-of-trust**: signatures on a new version are verified against the PREVIOUS version's role addresses
4. **Every node** independently verifies the document before any ceremony
5. **GitHub** stores the signed documents as immutable commit history
6. **CI verification** walks the full chain of trust from genesis to HEAD

## Document Structure (v2)

```jsonc
{
  "registry_metadata": {
    "registry_id": "dev-custody-v1",
    "version": 3,
    "issued_at": 1710000000,
    "expires_at": 1712592000,
    "updated_at": "2026-03-12T10:30:00.000Z",
    "document_hash": "sha256-hex...",
    "merkle_root": "sha256-hex...",
    "prev_document_hash": "sha256-hex... | null",
    "endpoints": { "primary": "https://...", "mirrors": [] }
  },
  "governance": {
    "roles": [
      { "role": "SYSTEM_ADMIN", "display_name": "System Administrator", "addresses": ["0x..."], "quorum": 2, "features": {} }
    ]
  },
  "ceremony_config": { "global_threshold_t": 2, "max_participants_n": 3, "allowed_protocols": ["cmp"], "allowed_curves": ["Secp256k1"] },
  "trusted_infrastructure": { "backoffice_pubkey": null, "market_oracle_pubkey": null, "trusted_binary_hashes": [] },
  "nodes": [{ "node_id": "...", "ik_pub": "...", "ek_pub": "...", "role": "PROVIDER_COSIGNER", "status": "ACTIVE", "enrolled_at": 1710000000 }],
  "immutable_policies": { "max_withdrawal_usd_24h": 1000000, "require_oracle_price": true, "enforce_whitelist": true },
  "signatures": [{ "role": "SYSTEM_ADMIN", "signer": "0x...", "signature": "0x..." }]
}
```

## Quick start

```bash
npm install

# Set admin wallet addresses in .env (no private keys needed)
# ADMIN_ADDRESS_0=0x...
# ADMIN_ADDRESS_1=0x...
# ADMIN_ADDRESS_2=0x...
#
# Optional additional governance roles:
# POLICY_COMPLIANCE_ADDRESS_0=0x...
# TREASURY_OPS_ADDRESS_0=0x...
# AUDIT_OBSERVER_ADDRESS_0=0x...

npm run setup        # create unsigned genesis document from .env addresses
npm run start:dev    # start the server

# Open http://localhost:3000/sign.html
# Connect MetaMask with admin wallets, sign genesis, then publish
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/registry/health | Server status and governance info |
| GET | /api/registry/current | Active signed document |
| GET | /api/registry/pending | Unsigned draft for next version |
| GET | /api/registry/pending/message | EIP-712 v2 typed data payload for signing |
| GET | /api/registry/nodes | List nodes (filter: `?role=`) |
| GET | /api/registry/nodes/:id | Single node record |
| GET | /api/registry/audit | Event audit log |
| GET | /api/registry/versions | List all published versions |
| GET | /api/registry/versions/:v | Get specific version document |
| POST | /api/registry/pending | Create new pending draft |
| POST | /api/registry/pending/sign | Submit role-based signature `{role, signer, signature, document_hash}` |
| DELETE | /api/registry/pending | Discard pending draft |
| POST | /api/registry/verify | Verify any document -- 12-step pipeline |
| POST | /api/registry/nodes/enroll | Propose enrolling a node |
| POST | /api/registry/nodes/revoke | Propose revoking a node |
| POST | /api/registry/nodes/rotate-ik | Rotate node identity key |
| POST | /api/registry/nodes/maintenance | Set node to maintenance mode |
| POST | /api/registry/nodes/reactivate | Reactivate a maintenance node |
| POST | /api/registry/governance/role | Propose governance role changes |
| POST | /api/registry/ceremony-config/propose | Propose ceremony configuration |
| POST | /api/registry/infrastructure/propose | Propose trusted infrastructure changes |
| POST | /api/registry/endpoints/propose | Propose registry endpoints |
| POST | /api/registry/immutable-policies/propose | Propose immutable policies |
| POST | /api/registry/publish | Publish a fully signed document |

## Governance Roles

| Role | Required | Min Addresses | Description |
|------|----------|---------------|-------------|
| `SYSTEM_ADMIN` | Yes | 3 (quorum >= 2) | Full administrative control |
| `POLICY_COMPLIANCE` | No | - | Compliance and policy team |
| `TREASURY_OPS` | No | - | Treasury operations |
| `AUDIT_OBSERVER` | No | - | Audit observation |

## Verification Pipeline (12 steps)

1. Structure -- required sections present
2. Registry ID -- matches config
3. Expiry -- not expired
4. Document hash -- SHA-256 integrity
5. Merkle root -- node list integrity
6. Hash chain -- prev_document_hash links correctly
7. SYSTEM_ADMIN -- >= 3 addresses, quorum >= 2
8. Per-role quorum -- ALL roles meet their quorum
9. Ceremony config -- global_threshold_t >= 2, etc.
10. Endpoints -- URL validation
11. Immutable policies -- valid
12. Trusted infrastructure -- hex format validation

## Read the testing guide

```bash
cat TESTING.md
```

## Run tests

```bash
npm test    # 33 tests
```
