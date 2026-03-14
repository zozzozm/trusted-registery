# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MPC Custody Node Registry — a NestJS server that manages a cryptographically signed registry of MPC custody nodes. Registry documents are versioned, hash-chained, Merkle-rooted, and require multi-signature (2-of-3) EIP-712 admin approval before publishing.

## Commands

- `npm run start:dev` — run dev server (ts-node-dev, auto-restarts on changes)
- `npm run build` — compile TypeScript to `dist/`
- `npm run test` — run all tests (`jest --runInBand`)
- `npm run keygen` — generate 3 admin Ethereum keypairs, writes `.env`
- `npm run setup` — create and sign genesis (v1) registry document
- `ADMIN_INDEX=0 npm run sign` — sign the pending draft as a specific admin

## Initial Dev Setup

1. `npm install`
2. `npm run keygen` (generates `.env` with 3 admin keypairs)
3. `npm run setup` (creates signed genesis doc at `data/registry.json`)
4. `npm run start:dev`

## Architecture

**NestJS app with a single module** (`RegistryModule`). All API routes are under the `/api/registry` prefix.

### Core Flow

1. **Propose changes** — `POST /nodes/enroll` or `/nodes/revoke` creates/modifies a staged draft in memory
2. **Configure document** — `POST /admins/propose`, `/backoffice-pubkey/propose`, `/mpc-policy/propose`, `/endpoints/propose` modify draft metadata
3. **Sign draft** — `POST /pending/sign` adds an admin signature (or use `npm run sign` offline)
4. **Publish** — `POST /publish` validates the fully-signed document through 10 verification steps and persists it

### Key Files

- `src/common/crypto.ts` — EIP-712 typed data signing/verification (ethers.js), SHA-256 hashing with deterministic JSON serialization (sorted keys), Merkle tree construction
- `src/common/types.ts` — Core types: `RegistryDocument`, `NodeRecord`, `AdminSignature`, `UnsignedDocument`, `RegistryEndpoints`
- `src/common/config.ts` — Config from env vars; admin Ethereum addresses are the trust root
- `src/registry/registry.service.ts` — All business logic: in-memory state (currentDoc, stagedDraft, auditLog), verification pipeline, disk persistence
- `src/registry/registry.controller.ts` — REST endpoints mapping to service methods

### Registry Document Fields

- **Core**: `registryId`, `version`, `issuedAt`, `expiresAt`
- **Admin**: `adminAddresses` (Ethereum addresses, 2-of-3 multi-sig)
- **Nodes**: `nodes[]` (NodeRecord with ikPub, ekPub, role, status)
- **Backoffice**: `backofficeServicePubkey` (32-byte hex public key, nullable)
- **MPC Policy**: `allowedCurves` (e.g. secp256k1, ed25519), `allowedProtocols` (e.g. cggmp21, frost), `threshold` (minimum signers required, >= 2)
- **Endpoints**: `endpoints` (nullable object with `primary` URL, `mirrors[]` URLs, `updated_at` timestamp)
- **Integrity**: `merkleRoot`, `prevDocumentHash`, `documentHash`
- **Auth**: `signatures[]` (EIP-712 typed data signatures)

### Cryptographic Design

- **Document hash**: SHA-256 of deterministic JSON (keys sorted recursively), computed with `documentHash` field set to empty string
- **Merkle root**: binary Merkle tree over `hash("leaf:" + hash(nodeRecord))` for each node, sorted by `nodeId`
- **Hash chain**: each document's `prevDocumentHash` links to the previous version's `documentHash`
- **Signatures**: EIP-712 typed data signatures over the full document; `verifyMultiSig` checks for ≥ `MIN_SIGNATURES` valid unique admin signatures

### Verification Pipeline (10 steps)

1. Structure — all required fields present
2. Registry ID — matches configured ID
3. Expiry — document not expired
4. Document hash — SHA-256 integrity check
5. Merkle root — node list integrity
6. Hash chain — links to previous version
7. Multi-sig — 2-of-3 EIP-712 admin signatures
8. Admin addresses — minimum count validation
9. MPC Policy — allowedCurves/allowedProtocols non-empty, threshold >= 2
10. Endpoints — URL format validation, no duplicates

### Testing

Tests are in `test/registry.test.ts`. They use `.env.test`, generate fresh keypairs in `beforeAll`, and write to `/tmp/test-registry-jest.json`. Tests cover verification failure cases (missing fields, expired, tampered, insufficient signatures) and the full publish flow (genesis → enroll → sign → publish → query).

### State Management

The registry is fully in-memory with disk persistence to `REGISTRY_FILE` (default `data/registry.json`). The staged draft lives only in memory and is cleared on publish or server restart.
