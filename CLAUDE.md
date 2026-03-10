# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MPC Custody Node Registry — a NestJS server that manages a cryptographically signed registry of MPC custody nodes. Registry documents are versioned, hash-chained, Merkle-rooted, and require multi-signature (2-of-3) Ed25519 admin approval before publishing.

## Commands

- `npm run start:dev` — run dev server (ts-node-dev, auto-restarts on changes)
- `npm run build` — compile TypeScript to `dist/`
- `npm run test` — run all tests (`jest --runInBand`)
- `npm run keygen` — generate 3 admin Ed25519 keypairs, writes `.env`
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
2. **Sign draft** — `POST /pending/sign` adds an admin signature (or use `npm run sign` offline)
3. **Publish** — `POST /publish` validates the fully-signed document through 7 verification steps (structure, registry ID, expiry, document hash, merkle root, hash chain, multi-sig) and persists it

### Key Files

- `src/common/crypto.ts` — Ed25519 signing/verification (`@noble/ed25519`), SHA-256 hashing with deterministic JSON serialization (sorted keys), Merkle tree construction
- `src/common/types.ts` — Core types: `RegistryDocument`, `NodeRecord`, `AdminSignature`, `UnsignedDocument`
- `src/common/config.ts` — Config from env vars; admin public keys are the trust root
- `src/registry/registry.service.ts` — All business logic: in-memory state (currentDoc, stagedDraft, auditLog), verification pipeline, disk persistence
- `src/registry/registry.controller.ts` — REST endpoints mapping to service methods

### Cryptographic Design

- **Document hash**: SHA-256 of deterministic JSON (keys sorted recursively), computed with `documentHash` field set to empty string
- **Merkle root**: binary Merkle tree over `hash("leaf:" + hash(nodeRecord))` for each node, sorted by `nodeId`
- **Hash chain**: each document's `prevDocumentHash` links to the previous version's `documentHash`
- **Signatures**: Ed25519 signatures over the `documentHash` hex string; `verifyMultiSig` checks for ≥ `MIN_SIGNATURES` valid unique admin signatures

### Testing

Tests are in `test/registry.test.ts`. They use `.env.test`, generate fresh keypairs in `beforeAll`, and write to `/tmp/test-registry-jest.json`. Tests cover verification failure cases (missing fields, expired, tampered, insufficient signatures) and the full publish flow (genesis → enroll → sign → publish → query).

### State Management

The registry is fully in-memory with disk persistence to `REGISTRY_FILE` (default `data/registry.json`). The staged draft lives only in memory and is cleared on publish or server restart.
