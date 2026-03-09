# Step-by-Step Manual Testing Guide
## MPC Node Registry — curl & Postman

This guide walks through every endpoint from zero.  
You will understand exactly what the system verifies and why.

---

## Prerequisites

```bash
npm install
npm run keygen      # generates 3 admin keypairs → writes .env
npm run setup       # creates genesis registry document
npm run start:dev   # start the server on port 3000
```

You should see:
```
🚀 Registry running at http://localhost:3000/api
```

---

## PART 1 — Basic Health & Read Endpoints

---

### 1.1 — Health Check

**What it does:** Shows server status, current version, and admin key fingerprints.

```bash
curl http://localhost:3000/api/registry/health | jq
```

**Expected response:**
```json
{
  "status": "ok",
  "registryId": "dev-custody-v1",
  "version": 1,
  "totalNodes": 0,
  "activeNodes": 0,
  "adminKeys": [
    { "index": 0, "pubKey": "a1b2c3d4..." },
    { "index": 1, "pubKey": "e5f6g7h8..." },
    { "index": 2, "pubKey": "i9j0k1l2..." }
  ]
}
```

**What to notice:** `version: 1` — the genesis document was published by `npm run setup`.

---

### 1.2 — Read the Current Signed Registry

**What it does:** Returns the complete signed registry document.  
This is what every MPC node fetches before any ceremony.

```bash
curl http://localhost:3000/api/registry/current | jq
```

**Expected response:**
```json
{
  "registryId": "dev-custody-v1",
  "version": 1,
  "issuedAt": 1709000000,
  "expiresAt": 1709604800,
  "nodes": [],
  "merkleRoot": "abc123...",
  "prevDocumentHash": null,
  "documentHash": "def456...",
  "signatures": [
    { "adminIndex": 0, "signature": "aabb..." },
    { "adminIndex": 1, "signature": "ccdd..." }
  ]
}
```

**What to notice:**
- `nodes: []` — no nodes enrolled yet
- `prevDocumentHash: null` — this is the genesis (first) document
- `signatures` — two admin signatures, one from admin[0] and one from admin[1]

---

### 1.3 — Read the Pending (Unsigned) Draft

**What it does:** Returns what the NEXT version would look like, without signatures.  
Admins fetch this, sign it offline, then POST it back with signatures.

```bash
curl http://localhost:3000/api/registry/pending | jq
```

**Expected response:**
```json
{
  "registryId": "dev-custody-v1",
  "version": 2,
  "issuedAt": 1709001000,
  "expiresAt": 1709605800,
  "nodes": [],
  "merkleRoot": "abc123...",
  "prevDocumentHash": "def456...",
  "documentHash": "ghi789..."
}
```

**What to notice:**
- `version: 2` — this would be the next version
- `prevDocumentHash` — links to the current v1 document (hash chain!)
- No `signatures` field — it is unsigned, waiting for admin approval

---

## PART 2 — The Verify Endpoint (Main Learning Tool)

The `/verify` endpoint runs every verification step and tells you exactly what passed or failed.  
This is the same logic every MPC node runs before trusting a registry document.

---

### 2.1 — Verify the Current Valid Document

First, grab the current document and immediately verify it:

```bash
curl -s http://localhost:3000/api/registry/current | \
  curl -s -X POST http://localhost:3000/api/registry/verify \
    -H "Content-Type: application/json" \
    -d @- | jq
```

**Expected response:**
```json
{
  "valid": true,
  "summary": "✓ Document is valid",
  "steps": [
    { "step": "structure",     "passed": true, "detail": "All required fields present" },
    { "step": "registryId",    "passed": true, "detail": "Registry ID matches: \"dev-custody-v1\"" },
    { "step": "expiry",        "passed": true, "detail": "Valid for 167h 59m more" },
    { "step": "documentHash",  "passed": true, "detail": "Hash verified: def456..." },
    { "step": "merkleRoot",    "passed": true, "detail": "Merkle root verified: abc123..." },
    { "step": "hashChain",     "passed": true, "detail": "No previous version — this is the genesis document" },
    { "step": "signatures",    "passed": true, "detail": "2 valid signatures from: admin[0], admin[1]" }
  ]
}
```

All 7 steps pass. Now let's break each one deliberately.

---

### 2.2 — ATTACK: Wrong Registry ID

What happens if someone creates a document for a different deployment?

```bash
curl -s http://localhost:3000/api/registry/current | \
  jq '.registryId = "attacker-registry"' | \
  curl -X POST http://localhost:3000/api/registry/verify \
    -H "Content-Type: application/json" -d @- | jq '.steps[] | select(.step == "registryId")'
```

**Expected:**
```json
{
  "step": "registryId",
  "passed": false,
  "detail": "Got \"attacker-registry\", expected \"dev-custody-v1\""
}
```

**What this teaches:** Even if someone creates a perfectly signed document for a different system, nodes reject it because the registryId doesn't match what's hardcoded in their binary.

---

### 2.3 — ATTACK: Tampered Node List (Most Important Test)

What if an attacker modifies the nodes list after the document was signed?  
This simulates someone intercepting the document and injecting a fake node.

```bash
curl -s http://localhost:3000/api/registry/current | jq '
  .nodes += [{
    "nodeId": "attacker-node-id",
    "ikPub": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "ekPub": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "role": "RECOVERY_GUARDIAN",
    "walletScope": ["wallet-001"],
    "status": "ACTIVE",
    "enrolledAt": 1709000000
  }]
' | curl -X POST http://localhost:3000/api/registry/verify \
  -H "Content-Type: application/json" -d @- | jq '.steps[] | select(.step == "documentHash")'
```

**Expected:**
```json
{
  "step": "documentHash",
  "passed": false,
  "detail": "Recomputed: 1234567890abcdef...\nDocument has: def456..."
}
```

**What this teaches:** The documentHash is computed over ALL the content. Any tampering — even adding one character — produces a completely different hash. The signatures were made over the original hash, so they no longer match the tampered content. The attacker cannot inject nodes without re-signing with 2 admin keys.

---

### 2.4 — ATTACK: Only 1 Admin Signature

What if only one admin signs? Maybe an attacker compromised one admin key.

```bash
curl -s http://localhost:3000/api/registry/current | \
  jq '.signatures = [.signatures[0]]' | \
  curl -X POST http://localhost:3000/api/registry/verify \
    -H "Content-Type: application/json" -d @- | jq '.steps[] | select(.step == "signatures")'
```

**Expected:**
```json
{
  "step": "signatures",
  "passed": false,
  "detail": "Need ≥2 signatures, got 1"
}
```

---

### 2.5 — ATTACK: Duplicate Admin Index (Fake Multi-Sig)

What if an attacker signs with the same key twice, pretending it counts as two approvals?

```bash
curl -s http://localhost:3000/api/registry/current | jq '
  .signatures = [
    .signatures[0],
    (.signatures[0] | .adminIndex = 0)
  ]
' | curl -X POST http://localhost:3000/api/registry/verify \
  -H "Content-Type: application/json" -d @- | jq '.steps[] | select(.step == "signatures")'
```

**Expected:**
```json
{
  "step": "signatures",
  "passed": false,
  "detail": "Duplicate adminIndex 0"
}
```

---

### 2.6 — ATTACK: Invalid Signature (Wrong Key)

What if someone claims to be admin[2] but uses the wrong key?

```bash
curl -s http://localhost:3000/api/registry/current | jq '
  .signatures[0].adminIndex = 2
' | curl -X POST http://localhost:3000/api/registry/verify \
  -H "Content-Type: application/json" -d @- | jq '.steps[] | select(.step == "signatures")'
```

**Expected:**
```json
{
  "step": "signatures",
  "passed": false,
  "detail": "Invalid signature at adminIndex 2"
}
```

---

## PART 3 — Node Enrollment Flow

---

### 3.1 — Step 1: Propose Enrolling a Node

This creates a draft document with the new node included.  
It does NOT change the registry — that requires admin signatures.

```bash
curl -X POST http://localhost:3000/api/registry/nodes/enroll \
  -H "Content-Type: application/json" \
  -d '{
    "ikPub":       "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "ekPub":       "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
    "role":        "PROVIDER_COSIGNER",
    "walletScope": ["wallet-001", "wallet-002"]
  }' | jq
```

**Expected:**
```json
{
  "nodeId": "3f4a5b...",
  "draft": {
    "registryId": "dev-custody-v1",
    "version": 2,
    "nodes": [
      {
        "nodeId": "3f4a5b...",
        "ikPub": "a1b2c3...",
        "role": "PROVIDER_COSIGNER",
        "walletScope": ["wallet-001", "wallet-002"],
        "status": "ACTIVE",
        "enrolledAt": 1709001234
      }
    ],
    "documentHash": "newHash123...",
    "prevDocumentHash": "def456..."
  }
}
```

**Save the nodeId** — you will need it for the revoke test later.

---

### 3.2 — Step 2: Sign the Draft (Admin 0)

```bash
ADMIN_INDEX=0 npm run sign
```

This fetches the current pending draft, signs it with admin 0's key,  
and saves it to `./data/draft-pending-signed-0.json`.

**You will see:**
```
=== Signing as Admin 0 ===

Fetching pending draft from http://localhost:3000/api/registry/pending...
Document hash: ghi789...
Signature:  aabbccdd...
Self-verify: ✓ passed

✓ Saved to ./data/draft-pending-signed-0.json
  Signatures so far: 1/2 required

1 more signature(s) needed.
  ADMIN_INDEX=1 DRAFT_FILE=./data/draft-pending-signed-0.json npm run sign
```

---

### 3.3 — Step 3: Sign the Draft (Admin 1)

```bash
ADMIN_INDEX=1 DRAFT_FILE=./data/draft-pending-signed-0.json npm run sign
```

**You will see:**
```
✓ Saved to ./data/draft-pending-signed-0-signed-1.json
  Signatures so far: 2/2 required

✓ Threshold reached! Ready to publish.

Publish with:
  curl -X POST http://localhost:3000/api/registry/publish \
    -H "Content-Type: application/json" \
    -d @./data/draft-pending-signed-0-signed-1.json
```

---

### 3.4 — Step 4: Publish the Signed Document

```bash
curl -X POST http://localhost:3000/api/registry/publish \
  -H "Content-Type: application/json" \
  -d @./data/draft-pending-signed-0-signed-1.json | jq
```

**Expected:**
```json
{
  "published": true,
  "version": 2
}
```

---

### 3.5 — Verify the Node is Now in the Registry

```bash
# List all nodes
curl http://localhost:3000/api/registry/nodes | jq

# Filter by wallet
curl "http://localhost:3000/api/registry/nodes?wallet=wallet-001" | jq

# Filter by role
curl "http://localhost:3000/api/registry/nodes?role=PROVIDER_COSIGNER" | jq

# Get one specific node (use the nodeId from step 3.1)
curl http://localhost:3000/api/registry/nodes/PUT_NODE_ID_HERE | jq
```

---

## PART 4 — Rollback Attack (Hash Chain)

This tests one of the most important security properties.

---

### 4.1 — Try to Publish an Old Version

We currently have version 2. Try to publish version 1 again.

```bash
# First, grab the original v1 document
curl http://localhost:3000/api/registry/current | jq

# The current IS v2. Let's manually craft a v1 attempt:
curl -X POST http://localhost:3000/api/registry/publish \
  -H "Content-Type: application/json" \
  -d '{
    "registryId": "dev-custody-v1",
    "version": 1,
    "nodes": [],
    "signatures": [
      { "adminIndex": 0, "signature": "fake00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" },
      { "adminIndex": 1, "signature": "fake11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" }
    ]
  }' | jq
```

**Expected: 400 Bad Request**

The verify step "hashChain" will report:  
`"Version 1 ≤ current 2 — rollback"`

---

### 4.2 — Try to Publish v3 with Wrong prevDocumentHash

This simulates a fork attack — trying to create an alternate history.

```bash
curl http://localhost:3000/api/registry/pending | \
  jq '.prevDocumentHash = "aaaa0000000000000000000000000000000000000000000000000000000000000000"' | \
  curl -X POST http://localhost:3000/api/registry/verify \
    -H "Content-Type: application/json" -d @- | jq '.steps[] | select(.step == "hashChain")'
```

**Expected:**
```json
{
  "step": "hashChain",
  "passed": false,
  "detail": "prevDocumentHash does not match current document hash"
}
```

---

## PART 5 — Node Revocation Flow

---

### 5.1 — Propose Revoking a Node

Replace `NODE_ID_HERE` with the nodeId from step 3.1.

```bash
curl -X POST http://localhost:3000/api/registry/nodes/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "nodeId": "NODE_ID_HERE",
    "reason": "Key compromise suspected"
  }' | jq > ./data/revoke-draft.json

cat ./data/revoke-draft.json | jq '.nodes[] | { nodeId, status, revokedAt }'
```

**Expected:** The node appears in the draft with `"status": "REVOKED"` and a `revokedAt` timestamp.

---

### 5.2 — Sign and Publish the Revocation

```bash
# Sign with admin 0
ADMIN_INDEX=0 DRAFT_FILE=./data/revoke-draft.json npm run sign

# Sign with admin 1
ADMIN_INDEX=1 DRAFT_FILE=./data/revoke-draft-signed-0.json npm run sign

# Publish
curl -X POST http://localhost:3000/api/registry/publish \
  -H "Content-Type: application/json" \
  -d @./data/revoke-draft-signed-0-signed-1.json | jq
```

---

### 5.3 — Verify the Node is Revoked

```bash
curl http://localhost:3000/api/registry/nodes | jq '.[].status'
# → "REVOKED"

curl "http://localhost:3000/api/registry/nodes?wallet=wallet-001" | jq
# → still returns revoked nodes (use status filter in real code)
```

---

## PART 6 — Postman Collection Setup

If you prefer Postman over curl, import this collection manually.

### Base URL variable
Set a variable `base` = `http://localhost:3000/api`

### Requests to create:

| Name | Method | URL |
|------|--------|-----|
| Health | GET | `{{base}}/registry/health` |
| Current Registry | GET | `{{base}}/registry/current` |
| Pending Draft | GET | `{{base}}/registry/pending` |
| List Nodes | GET | `{{base}}/registry/nodes` |
| Verify Document | POST | `{{base}}/registry/verify` |
| Propose Enroll | POST | `{{base}}/registry/nodes/enroll` |
| Propose Revoke | POST | `{{base}}/registry/nodes/revoke` |
| Publish Signed | POST | `{{base}}/registry/publish` |
| Audit Log | GET | `{{base}}/registry/audit` |

### Enroll body (raw JSON):
```json
{
  "ikPub": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "ekPub": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
  "role": "PROVIDER_COSIGNER",
  "walletScope": ["wallet-001"]
}
```

### Postman test script for Verify (paste in Tests tab):
```javascript
pm.test("Response has valid field", () => {
  pm.expect(pm.response.json()).to.have.property('valid')
  pm.expect(pm.response.json()).to.have.property('steps')
})

pm.test("Steps array is not empty", () => {
  pm.expect(pm.response.json().steps.length).to.be.greaterThan(0)
})

// Log each step result for debugging
pm.response.json().steps.forEach(step => {
  pm.test(`Step: ${step.step}`, () => {
    pm.expect(step).to.have.property('passed')
    pm.expect(step).to.have.property('detail')
  })
})
```

---

## PART 7 — GitHub Setup

Push this project to GitHub so the registry document lives in source control.

### 7.1 — Initialize and push

```bash
git init
git add .
git commit -m "initial: MPC node registry"

# Create a repo on GitHub, then:
git remote add origin git@github.com:YOUR_USERNAME/mpc-node-registry.git
git push -u origin main
```

### 7.2 — Add GitHub Actions verification

The `.github/workflows/verify.yml` included in this project automatically verifies every registry document pushed to the `data/` folder. On every push it runs the same signature verification the nodes run.

### 7.3 — Make the registry publicly readable

Once public, any node can fetch the current document with:
```bash
curl https://raw.githubusercontent.com/YOUR_USERNAME/mpc-node-registry/main/data/registry.json
```

### 7.4 — Commit a new registry version

After publishing a new version via the API, commit the updated file:
```bash
git add data/registry.json
git commit -m "registry: enroll provider node v2"
git push
```

Now the signed document lives in GitHub's immutable commit history.

---

## Quick Reference — All curl Commands

```bash
# Health
curl http://localhost:3000/api/registry/health | jq

# Current signed document
curl http://localhost:3000/api/registry/current | jq

# Pending unsigned draft
curl http://localhost:3000/api/registry/pending | jq

# All nodes
curl http://localhost:3000/api/registry/nodes | jq

# Filter nodes by wallet
curl "http://localhost:3000/api/registry/nodes?wallet=wallet-001" | jq

# Filter nodes by role
curl "http://localhost:3000/api/registry/nodes?role=PROVIDER_COSIGNER" | jq

# Get specific node
curl http://localhost:3000/api/registry/nodes/NODE_ID | jq

# Audit log
curl http://localhost:3000/api/registry/audit | jq

# Verify any document (pipe current doc into verify)
curl -s http://localhost:3000/api/registry/current | \
  curl -s -X POST http://localhost:3000/api/registry/verify \
    -H "Content-Type: application/json" -d @- | jq

# Propose enroll
curl -X POST http://localhost:3000/api/registry/nodes/enroll \
  -H "Content-Type: application/json" \
  -d '{"ikPub":"a1b2...","ekPub":"c3d4...","role":"PROVIDER_COSIGNER","walletScope":["wallet-001"]}' | jq

# Sign with admin 0
ADMIN_INDEX=0 npm run sign

# Sign with admin 1
ADMIN_INDEX=1 DRAFT_FILE=./data/draft-pending-signed-0.json npm run sign

# Publish
curl -X POST http://localhost:3000/api/registry/publish \
  -H "Content-Type: application/json" \
  -d @./data/draft-pending-signed-0-signed-1.json | jq
```
