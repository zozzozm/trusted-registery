# MPC Node Registry

A signed JSON registry for MPC custody node admission. Uses Ed25519 multi-signatures with hardcoded admin keys — no blockchain required.

## How it works

1. **Admin keys** are hardcoded in every MPC node binary (3 keys, require 2-of-3)
2. **Registry documents** are JSON files signed by ≥2 admins
3. **Every node** independently verifies the document before any ceremony
4. **GitHub** stores the signed documents as immutable commit history

## Quick start

```bash
npm install
npm run keygen       # generate 3 admin keypairs → writes .env
npm run setup        # create genesis registry document
npm run start:dev    # start the server

# Then follow TESTING.md for step-by-step curl/Postman guide
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/registry/health | Server status |
| GET | /api/registry/current | Active signed document |
| GET | /api/registry/pending | Unsigned draft for next version |
| GET | /api/registry/nodes | List nodes (filter: ?wallet= ?role=) |
| GET | /api/registry/nodes/:id | Single node record |
| GET | /api/registry/audit | Event audit log |
| POST | /api/registry/verify | ⭐ Verify any document — step by step |
| POST | /api/registry/nodes/enroll | Propose enrolling a node |
| POST | /api/registry/nodes/revoke | Propose revoking a node |
| POST | /api/registry/publish | Publish a fully signed document |

## Read the testing guide

```bash
cat TESTING.md
```

## Run tests

```bash
npm test
```
