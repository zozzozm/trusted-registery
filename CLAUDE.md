# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MPC Custody Node Registry -- a NestJS server that manages a cryptographically signed registry of MPC custody nodes. Registry documents are versioned, hash-chained, Merkle-rooted, and use role-based governance with per-role quorum EIP-712 (v2) multi-signature approval before publishing.

## Commands

- `npm run start:dev` -- run dev server (ts-node-dev, auto-restarts on changes)
- `npm run build` -- compile TypeScript to `dist/`
- `npm run test` -- run all tests (`jest --runInBand`, 33 tests)
- `npm run setup` -- create unsigned genesis (v1) document from `ADMIN_ADDRESS_*` (and optional role addresses) in `.env`

## Initial Dev Setup

1. `npm install`
2. Set `ADMIN_ADDRESS_0`, `ADMIN_ADDRESS_1`, `ADMIN_ADDRESS_2` in `.env` (required for SYSTEM_ADMIN)
3. Optionally set `POLICY_COMPLIANCE_ADDRESS_0`, `TREASURY_OPS_ADDRESS_0`, `AUDIT_OBSERVER_ADDRESS_0`, etc.
4. `npm run setup` (creates unsigned genesis doc)
5. `npm run start:dev`
6. Open `http://localhost:3000/sign.html` -- sign genesis with MetaMask, then publish

## Architecture

**NestJS app with a single module** (`RegistryModule`). All API routes are under the `/api/registry` prefix.

### Core Flow

1. **Create pending draft** -- `POST /pending` creates a new staged draft from the current document
2. **Propose changes** -- `POST /nodes/enroll`, `/nodes/revoke`, `/nodes/rotate-ik`, `/nodes/maintenance`, `/nodes/reactivate` modify nodes in the staged draft
3. **Configure document** -- `POST /governance/role`, `/infrastructure/propose`, `/ceremony-config/propose`, `/endpoints/propose`, `/immutable-policies/propose` modify draft metadata
4. **Sign draft** -- `POST /pending/sign` adds a role-based signature (via MetaMask/Ledger in the web UI). Body: `{role, signer, signature, document_hash}`
5. **Publish** -- `POST /publish` validates the fully-signed document through 12 verification steps and persists it
6. **Discard draft** -- `DELETE /pending` clears the staged draft

### Key Files

- `src/common/crypto.ts` -- EIP-712 v2 typed data signing/verification (ethers.js), SHA-256 hashing with deterministic JSON serialization (sorted keys), Merkle tree construction, Ed25519 rotation proof verification
- `src/common/types.ts` -- Core types: `RegistryDocument`, `NodeRecord`, `GovernanceRole`, `GovernanceRoleName`, `CeremonyConfig`, `TrustedInfrastructure`, `ImmutablePolicies`, `RegistryEndpoints`, `RegistryMetadata`, `RoleSignature`, `IkRotationEntry`
- `src/common/config.ts` -- Config from env vars; genesis role addresses are the trust root, with `GENESIS_ROLE_PREFIXES` mapping role names to env var prefixes
- `src/registry/registry.service.ts` -- All business logic: in-memory state (currentDoc, stagedDraft, auditLog), 12-step verification pipeline, disk persistence
- `src/registry/registry.controller.ts` -- REST endpoints mapping to service methods
- `src/registry/dto.ts` -- Request DTOs for all endpoints

### Registry Document Structure (v2 -- Nested, Role-Based Governance)

The document is organized into top-level sections:

- **`registry_metadata`**: `registry_id`, `version`, `issued_at`, `expires_at`, `updated_at`, `document_hash`, `merkle_root`, `prev_document_hash`, `endpoints` (`{primary, mirrors[]}`)
- **`governance`**: `roles[]` -- each role has `role` (GovernanceRoleName), `display_name`, `addresses[]`, `quorum`, `features`
  - Closed set of role names: `SYSTEM_ADMIN` (mandatory), `POLICY_COMPLIANCE`, `TREASURY_OPS`, `AUDIT_OBSERVER`
  - `SYSTEM_ADMIN` requires min 3 addresses, quorum >= 2
- **`ceremony_config`**: `global_threshold_t`, `max_participants_n`, `allowed_protocols[]`, `allowed_curves[]`
- **`trusted_infrastructure`**: `backoffice_pubkey`, `market_oracle_pubkey`, `trusted_binary_hashes[]`
- **`nodes[]`**: NodeRecord with `node_id`, `ik_pub`, `ek_pub`, `role`, `status`, `enrolled_at`, `updated_at`, `revoked_at`, `ik_rotations[]`
- **`immutable_policies`**: `max_withdrawal_usd_24h`, `require_oracle_price`, `enforce_whitelist`
- **`signatures[]`**: `{role, signer, signature}` (RoleSignature)

### Cryptographic Design

- **Document hash**: SHA-256 of deterministic JSON (keys sorted recursively), computed with `document_hash` field set to empty string
- **Merkle root**: binary Merkle tree over `hash("leaf:" + hash(nodeRecord))` for each node, sorted by `node_id`
- **Hash chain**: each document's `prev_document_hash` links to the previous version's `document_hash`
- **Signatures**: EIP-712 v2 typed data signatures over the full document; role-based verification checks that ALL roles from the previous version meet their quorum
- **Chain-of-trust**: signatures are verified against the PREVIOUS version's role addresses (not the current document's addresses). For genesis (v1), SYSTEM_ADMIN addresses are verified against `ADMIN_ADDRESS_*` env vars.
- **EIP-712 domain**: `{ name: 'MPC Node Registry', version: '2' }`
- **IK rotation proofs**: Ed25519 signatures by the old identity key, verifying the transition to a new key

### Governance Model

- Multiple roles replace the flat admin list: `SYSTEM_ADMIN`, `POLICY_COMPLIANCE`, `TREASURY_OPS`, `AUDIT_OBSERVER`
- Each role has its own `quorum` (minimum signatures required) and `addresses[]`
- `SYSTEM_ADMIN` is mandatory and requires at least 3 addresses with quorum >= 2
- When publishing a new version, ALL roles defined in the previous version must sign with their respective quorum
- Signatures are verified against the previous version's role addresses (chain-of-trust)

### Env Vars for Trust Root

- `ADMIN_ADDRESS_0/1/2` -> SYSTEM_ADMIN (required, min 3)
- `POLICY_COMPLIANCE_ADDRESS_0/1/...` -> POLICY_COMPLIANCE (optional)
- `TREASURY_OPS_ADDRESS_0/1/...` -> TREASURY_OPS (optional)
- `AUDIT_OBSERVER_ADDRESS_0/1/...` -> AUDIT_OBSERVER (optional)

These are mapped via `CONFIG.GENESIS_ROLE_PREFIXES`.

### API Routes

**Read endpoints:**
- `GET /api/registry/health` -- server status and governance info
- `GET /api/registry/current` -- active signed document
- `GET /api/registry/pending` -- unsigned draft for next version
- `GET /api/registry/pending/message` -- EIP-712 v2 typed data payload for signing
- `GET /api/registry/nodes` -- list nodes (filter: `?role=`)
- `GET /api/registry/nodes/:id` -- single node record
- `GET /api/registry/audit` -- event audit log
- `GET /api/registry/versions` -- list all published versions
- `GET /api/registry/versions/:v` -- get specific version document

**Write endpoints:**
- `POST /api/registry/pending` -- create new pending draft
- `POST /api/registry/pending/sign` -- submit role-based signature `{role, signer, signature, document_hash}`
- `DELETE /api/registry/pending` -- discard pending draft
- `POST /api/registry/nodes/enroll` -- propose enrolling a node
- `POST /api/registry/nodes/revoke` -- propose revoking a node
- `POST /api/registry/nodes/rotate-ik` -- rotate node identity key
- `POST /api/registry/nodes/maintenance` -- set node to maintenance mode
- `POST /api/registry/nodes/reactivate` -- reactivate a maintenance node
- `POST /api/registry/governance/role` -- add/modify governance role
- `POST /api/registry/ceremony-config/propose` -- propose ceremony configuration
- `POST /api/registry/infrastructure/propose` -- propose trusted infrastructure changes
- `POST /api/registry/endpoints/propose` -- propose registry endpoints
- `POST /api/registry/immutable-policies/propose` -- propose immutable policies
- `POST /api/registry/verify` -- verify any document (12-step pipeline)
- `POST /api/registry/publish` -- publish a fully signed document

### Verification Pipeline (12 steps)

1. Structure -- all required sections present (`registry_metadata`, `governance`, `ceremony_config`, `trusted_infrastructure`, `nodes`, `immutable_policies`, `signatures`)
2. Registry ID -- matches configured ID
3. Expiry -- document not expired
4. Document hash -- SHA-256 integrity check
5. Merkle root -- node list integrity
6. Hash chain -- links to previous version
7. SYSTEM_ADMIN validation -- >= 3 addresses, quorum >= 2
8. Per-role quorum -- ALL roles must meet their quorum with valid signatures (verified against previous version's role addresses)
9. Ceremony config -- `global_threshold_t` >= 2, `allowed_curves`/`allowed_protocols` non-empty
10. Endpoints -- URL format validation, no duplicates
11. Immutable policies -- policy fields present and valid
12. Trusted infrastructure -- address format validation, binary hashes integrity

### Testing

Tests are in `test/registry.test.ts` (33 tests). They use `.env.test`, generate fresh keypairs in `beforeAll`, and write to `/tmp/test-registry-jest.json`. Tests cover verification failure cases (missing fields, expired, tampered, insufficient signatures, per-role quorum failures) and the full publish flow (genesis -> enroll -> sign -> publish -> query).

### Version Chain

Each published version is persisted as `data/versions/{N}.json` alongside `data/registry.json`. This enables:
- **Chain-walk recovery**: nodes that miss a governance rotation can fetch intermediate versions
- **CI enforcement**: append-only check, version continuity, hash chain verification
- **Audit trail**: complete immutable history of all published versions

### State Management

The registry is fully in-memory with disk persistence to `REGISTRY_FILE` (default `data/registry.json`) and `VERSIONS_DIR` (default `data/versions/`). The staged draft lives only in memory and is cleared on publish or server restart.

### Web UI

The signing UI (`sign.html`) has a two-panel layout:
- **Left panel**: management forms (enroll nodes, configure governance, etc.)
- **Right panel**: JSON preview with diff highlighting
- Node actions (revoke, maintenance, rotate IK) are accessible via modal popups on node cards
