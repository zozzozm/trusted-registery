# Step-by-Step Manual Testing Guide
## MPC Node Registry -- curl & Postman

This guide walks through every endpoint from zero.
You will understand exactly what the system verifies and why.

---

## Prerequisites

```bash
npm install

# Set admin wallet addresses in .env (no private keys needed):
# ADMIN_ADDRESS_0=0x...
# ADMIN_ADDRESS_1=0x...
# ADMIN_ADDRESS_2=0x...
#
# Optional governance roles:
# POLICY_COMPLIANCE_ADDRESS_0=0x...
# TREASURY_OPS_ADDRESS_0=0x...
# AUDIT_OBSERVER_ADDRESS_0=0x...

npm run setup       # creates unsigned genesis document from .env addresses
npm run start:dev   # start the server on port 3000

# Open http://localhost:3000/sign.html
# Connect MetaMask with admin wallets, sign genesis, then publish
```

You should see:
```
Registry running at http://localhost:3000/api
```

---

## PART 1 -- Basic Health & Read Endpoints

---

### 1.1 -- Health Check

**What it does:** Shows server status, current version, and governance role information.

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
  "governanceRoles": [
    {
      "role": "SYSTEM_ADMIN",
      "addresses": ["0xa1b2...", "0xe5f6...", "0xi9j0..."],
      "quorum": 2
    }
  ]
}
```

**What to notice:** `version: 1` -- the genesis document was created by `npm run setup` and signed via the web UI.

---

### 1.2 -- Read the Current Signed Registry

**What it does:** Returns the complete signed registry document.
This is what every MPC node fetches before any ceremony.

```bash
curl http://localhost:3000/api/registry/current | jq
```

**Expected response:**
```json
{
  "registry_metadata": {
    "registry_id": "dev-custody-v1",
    "version": 1,
    "issued_at": 1709000000,
    "expires_at": 1709604800,
    "updated_at": "2026-03-12T10:30:00.000Z",
    "document_hash": "def456...",
    "merkle_root": "abc123...",
    "prev_document_hash": null,
    "endpoints": null
  },
  "governance": {
    "roles": [
      {
        "role": "SYSTEM_ADMIN",
        "display_name": "System Administrator",
        "addresses": ["0xa1b2...", "0xe5f6...", "0xi9j0..."],
        "quorum": 2,
        "features": {}
      }
    ]
  },
  "ceremony_config": {
    "global_threshold_t": 2,
    "max_participants_n": 3,
    "allowed_protocols": ["cmp"],
    "allowed_curves": ["Secp256k1"]
  },
  "trusted_infrastructure": {
    "backoffice_pubkey": null,
    "market_oracle_pubkey": null,
    "trusted_binary_hashes": []
  },
  "nodes": [],
  "immutable_policies": {
    "max_withdrawal_usd_24h": 1000000,
    "require_oracle_price": true,
    "enforce_whitelist": true
  },
  "signatures": [
    { "role": "SYSTEM_ADMIN", "signer": "0xa1b2...", "signature": "aabb..." },
    { "role": "SYSTEM_ADMIN", "signer": "0xe5f6...", "signature": "ccdd..." }
  ]
}
```

**What to notice:**
- `nodes: []` -- no nodes enrolled yet
- `registry_metadata.prev_document_hash: null` -- this is the genesis (first) document
- `signatures` -- two SYSTEM_ADMIN signatures meeting the quorum of 2
- The document is organized into nested sections: `registry_metadata`, `governance`, `ceremony_config`, `trusted_infrastructure`, `nodes`, `immutable_policies`, `signatures`

---

### 1.3 -- Read the Pending (Unsigned) Draft

**What it does:** Returns what the NEXT version would look like, without signatures.
Role signers fetch this, sign it offline, then POST it back with signatures.

```bash
curl http://localhost:3000/api/registry/pending | jq
```

**Expected response:**
```json
{
  "registry_metadata": {
    "registry_id": "dev-custody-v1",
    "version": 2,
    "issued_at": 1709001000,
    "expires_at": 1709605800,
    "updated_at": "2026-03-12T10:30:00.000Z",
    "document_hash": "ghi789...",
    "merkle_root": "abc123...",
    "prev_document_hash": "def456..."
  },
  "governance": { "roles": ["..."] },
  "ceremony_config": { "..." : "..." },
  "trusted_infrastructure": { "..." : "..." },
  "nodes": [],
  "immutable_policies": { "..." : "..." }
}
```

**What to notice:**
- `registry_metadata.version: 2` -- this would be the next version
- `registry_metadata.prev_document_hash` -- links to the current v1 document (hash chain)
- No `signatures` field -- it is unsigned, waiting for role-based approval

---

## PART 2 -- The Verify Endpoint (Main Learning Tool)

The `/verify` endpoint runs every verification step and tells you exactly what passed or failed.
This is the same logic every MPC node runs before trusting a registry document.

---

### 2.1 -- Verify the Current Valid Document

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
  "summary": "Document is valid",
  "steps": [
    { "step": "structure",          "passed": true, "detail": "All required sections present" },
    { "step": "registryId",         "passed": true, "detail": "Registry ID matches: \"dev-custody-v1\"" },
    { "step": "expiry",             "passed": true, "detail": "Valid for 167h 59m more" },
    { "step": "documentHash",       "passed": true, "detail": "Hash verified: def456..." },
    { "step": "merkleRoot",         "passed": true, "detail": "Merkle root verified: abc123..." },
    { "step": "hashChain",          "passed": true, "detail": "No previous version -- this is the genesis document" },
    { "step": "systemAdmin",        "passed": true, "detail": "SYSTEM_ADMIN: 3 addresses, quorum 2" },
    { "step": "roleQuorum",         "passed": true, "detail": "All roles meet quorum requirements" },
    { "step": "ceremonyConfig",     "passed": true, "detail": "Ceremony config valid" },
    { "step": "endpoints",          "passed": true, "detail": "No endpoints configured" },
    { "step": "immutablePolicies",  "passed": true, "detail": "Immutable policies valid" },
    { "step": "trustedInfra",       "passed": true, "detail": "Trusted infrastructure valid" }
  ]
}
```

All 12 steps pass. Now let's break each one deliberately.

---

### 2.2 -- ATTACK: Wrong Registry ID

What happens if someone creates a document for a different deployment?

```bash
curl -s http://localhost:3000/api/registry/current | \
  jq '.registry_metadata.registry_id = "attacker-registry"' | \
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

**What this teaches:** Even if someone creates a perfectly signed document for a different system, nodes reject it because the registry_id doesn't match what's hardcoded in their binary.

---

### 2.3 -- ATTACK: Tampered Node List (Most Important Test)

What if an attacker modifies the nodes list after the document was signed?
This simulates someone intercepting the document and injecting a fake node.

```bash
curl -s http://localhost:3000/api/registry/current | jq '
  .nodes += [{
    "nodeId": "attacker-node-id",
    "ikPub": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "ekPub": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "role": "RECOVERY_GUARDIAN",
    "status": "ACTIVE",
    "enrolledAt": 1709000000,
    "updatedAt": 1709000000
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

**What this teaches:** The document_hash is computed over ALL the content. Any tampering -- even adding one character -- produces a completely different hash. The signatures were made over the original hash, so they no longer match the tampered content. The attacker cannot inject nodes without re-signing with all required role quorums.

---

### 2.4 -- ATTACK: Insufficient Role Signatures

What if only one SYSTEM_ADMIN signs? Maybe an attacker compromised one admin key.

```bash
curl -s http://localhost:3000/api/registry/current | \
  jq '.signatures = [.signatures[0]]' | \
  curl -X POST http://localhost:3000/api/registry/verify \
    -H "Content-Type: application/json" -d @- | jq '.steps[] | select(.step == "roleQuorum")'
```

**Expected:**
```json
{
  "step": "roleQuorum",
  "passed": false,
  "detail": "SYSTEM_ADMIN: need 2 signatures, got 1"
}
```

---

### 2.5 -- ATTACK: Duplicate Signer (Fake Quorum)

What if an attacker signs with the same key twice, pretending it counts as two approvals?

```bash
curl -s http://localhost:3000/api/registry/current | jq '
  .signatures = [
    .signatures[0],
    (.signatures[0] | .signer = .signer)
  ]
' | curl -X POST http://localhost:3000/api/registry/verify \
  -H "Content-Type: application/json" -d @- | jq '.steps[] | select(.step == "roleQuorum")'
```

**Expected:**
```json
{
  "step": "roleQuorum",
  "passed": false,
  "detail": "Duplicate signer in SYSTEM_ADMIN"
}
```

---

### 2.6 -- ATTACK: Invalid Signature (Wrong Key)

What if someone claims to be a SYSTEM_ADMIN signer but uses the wrong key?

```bash
curl -s http://localhost:3000/api/registry/current | jq '
  .signatures[0].signer = "0x0000000000000000000000000000000000000000"
' | curl -X POST http://localhost:3000/api/registry/verify \
  -H "Content-Type: application/json" -d @- | jq '.steps[] | select(.step == "roleQuorum")'
```

**Expected:**
```json
{
  "step": "roleQuorum",
  "passed": false,
  "detail": "Invalid signature: signer 0x0000... not in SYSTEM_ADMIN addresses"
}
```

---

## PART 3 -- Node Enrollment Flow

---

### 3.1 -- Step 1: Propose Enrolling a Node

This creates a draft document with the new node included.
It does NOT change the registry -- that requires role-based signatures.

```bash
curl -X POST http://localhost:3000/api/registry/nodes/enroll \
  -H "Content-Type: application/json" \
  -d '{
    "ikPub":       "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "ekPub":       "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
    "role":        "PROVIDER_COSIGNER"
  }' | jq
```

**Expected:**
```json
{
  "nodeId": "3f4a5b...",
  "draft": {
    "registry_metadata": {
      "registry_id": "dev-custody-v1",
      "version": 2,
      "document_hash": "newHash123...",
      "prev_document_hash": "def456..."
    },
    "nodes": [
      {
        "nodeId": "3f4a5b...",
        "ikPub": "a1b2c3...",
        "role": "PROVIDER_COSIGNER",
        "status": "ACTIVE",
        "enrolledAt": 1709001234,
        "updatedAt": 1709001234
      }
    ]
  }
}
```

**Save the nodeId** -- you will need it for the revoke test later.

---

### 3.2 -- Step 2: Sign the Draft (via Web UI)

1. Open `http://localhost:3000/sign.html`
2. Connect MetaMask with a SYSTEM_ADMIN wallet
3. Go to the **Sign & Publish** tab
4. Click **Fetch Draft** to load the pending document
5. Click **Sign Document** -- MetaMask will show the EIP-712 v2 typed data for review
6. Approve the signature in MetaMask
7. Click **Submit Signature** -- the signature is submitted with `{role: "SYSTEM_ADMIN", signer, signature, document_hash}`

Repeat with a second SYSTEM_ADMIN wallet (switch accounts in MetaMask) to meet the quorum of 2.

If additional governance roles exist (e.g., POLICY_COMPLIANCE), those roles must also sign with their respective quorum.

---

### 3.3 -- Step 3: Publish the Signed Document

Once all roles have met their quorum:

1. In the **Sign & Publish** tab, click **Verify & Publish**
2. The document will be verified (12-step pipeline) and published

**Expected result:** `Published! Version 2`

---

### 3.5 -- Verify the Node is Now in the Registry

```bash
# List all nodes
curl http://localhost:3000/api/registry/nodes | jq

# Filter by role
curl "http://localhost:3000/api/registry/nodes?role=PROVIDER_COSIGNER" | jq

# Get one specific node (use the nodeId from step 3.1)
curl http://localhost:3000/api/registry/nodes/PUT_NODE_ID_HERE | jq
```

---

## PART 4 -- Rollback Attack (Hash Chain)

This tests one of the most important security properties.

---

### 4.1 -- Try to Publish an Old Version

We currently have version 2. Try to publish version 1 again.

```bash
# First, grab the current document
curl http://localhost:3000/api/registry/current | jq

# The current IS v2. Let's manually craft a v1 attempt:
curl -X POST http://localhost:3000/api/registry/publish \
  -H "Content-Type: application/json" \
  -d '{
    "registry_metadata": {
      "registry_id": "dev-custody-v1",
      "version": 1
    },
    "nodes": [],
    "signatures": [
      { "role": "SYSTEM_ADMIN", "signer": "0xa1b2...", "signature": "fake00..." },
      { "role": "SYSTEM_ADMIN", "signer": "0xe5f6...", "signature": "fake11..." }
    ]
  }' | jq
```

**Expected: 400 Bad Request**

The verify step "hashChain" will report:
`"Version 1 <= current 2 -- rollback"`

---

### 4.2 -- Try to Publish v3 with Wrong prevDocumentHash

This simulates a fork attack -- trying to create an alternate history.

```bash
curl http://localhost:3000/api/registry/pending | \
  jq '.registry_metadata.prev_document_hash = "aaaa0000000000000000000000000000000000000000000000000000000000000000"' | \
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

## PART 5 -- Node Revocation Flow

---

### 5.1 -- Propose Revoking a Node

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

### 5.2 -- Sign and Publish the Revocation

1. Open `http://localhost:3000/sign.html` -> **Sign & Publish** tab
2. **Fetch Draft** -- the revocation draft will load
3. Sign with SYSTEM_ADMIN wallets (2 signatures to meet quorum)
4. If other governance roles exist, sign with those roles too
5. **Verify & Publish** once all role quorums are met

---

### 5.3 -- Verify the Node is Revoked

```bash
curl http://localhost:3000/api/registry/nodes | jq '.[].status'
# -> "REVOKED"

curl "http://localhost:3000/api/registry/nodes?role=PROVIDER_COSIGNER" | jq
# -> still returns revoked nodes (use status filter in real code)
```

---

## PART 6 -- Postman Collection Setup

If you prefer Postman over curl, import this collection manually.

### Base URL variable
Set a variable `base` = `http://localhost:3000/api`

### Requests to create:

| Name | Method | URL |
|------|--------|-----|
| Health | GET | `{{base}}/registry/health` |
| Current Registry | GET | `{{base}}/registry/current` |
| Pending Draft | GET | `{{base}}/registry/pending` |
| Create Pending | POST | `{{base}}/registry/pending` |
| Delete Pending | DELETE | `{{base}}/registry/pending` |
| List Nodes | GET | `{{base}}/registry/nodes` |
| Verify Document | POST | `{{base}}/registry/verify` |
| Propose Enroll | POST | `{{base}}/registry/nodes/enroll` |
| Propose Revoke | POST | `{{base}}/registry/nodes/revoke` |
| Rotate IK | POST | `{{base}}/registry/nodes/rotate-ik` |
| Set Maintenance | POST | `{{base}}/registry/nodes/maintenance` |
| Reactivate | POST | `{{base}}/registry/nodes/reactivate` |
| Governance Role | POST | `{{base}}/registry/governance/role` |
| Ceremony Config | POST | `{{base}}/registry/ceremony-config/propose` |
| Infrastructure | POST | `{{base}}/registry/infrastructure/propose` |
| Endpoints | POST | `{{base}}/registry/endpoints/propose` |
| Immutable Policies | POST | `{{base}}/registry/immutable-policies/propose` |
| Sign Pending | POST | `{{base}}/registry/pending/sign` |
| Publish Signed | POST | `{{base}}/registry/publish` |
| Audit Log | GET | `{{base}}/registry/audit` |
| Versions | GET | `{{base}}/registry/versions` |

### Enroll body (raw JSON):
```json
{
  "ikPub": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "ekPub": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
  "role": "PROVIDER_COSIGNER"
}
```

### Postman test script for Verify (paste in Tests tab):
```javascript
pm.test("Response has valid field", () => {
  pm.expect(pm.response.json()).to.have.property('valid')
  pm.expect(pm.response.json()).to.have.property('steps')
})

pm.test("Steps array has 12 steps", () => {
  pm.expect(pm.response.json().steps.length).to.equal(12)
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

## PART 7 -- GitHub Setup

Push this project to GitHub so the registry document lives in source control.

### 7.1 -- Initialize and push

```bash
git init
git add .
git commit -m "initial: MPC node registry"

# Create a repo on GitHub, then:
git remote add origin git@github.com:YOUR_USERNAME/mpc-node-registry.git
git push -u origin main
```

### 7.2 -- Add GitHub Actions verification

The `.github/workflows/verify.yml` included in this project automatically verifies every registry document pushed to the `data/` folder. On every push it runs the same signature verification the nodes run, including role-based quorum checks and version chain validation.

### 7.3 -- Make the registry publicly readable

Once public, any node can fetch the current document with:
```bash
curl https://raw.githubusercontent.com/YOUR_USERNAME/mpc-node-registry/main/data/registry.json
```

### 7.4 -- Commit a new registry version

After publishing a new version via the API, commit the updated file:
```bash
git add data/registry.json data/versions/
git commit -m "registry: enroll provider node v2"
git push
```

Now the signed document lives in GitHub's immutable commit history.

---

## Quick Reference -- All curl Commands

```bash
# Health
curl http://localhost:3000/api/registry/health | jq

# Current signed document
curl http://localhost:3000/api/registry/current | jq

# Pending unsigned draft
curl http://localhost:3000/api/registry/pending | jq

# Create a new pending draft
curl -X POST http://localhost:3000/api/registry/pending | jq

# Delete pending draft
curl -X DELETE http://localhost:3000/api/registry/pending | jq

# All nodes
curl http://localhost:3000/api/registry/nodes | jq

# Filter nodes by role
curl "http://localhost:3000/api/registry/nodes?role=PROVIDER_COSIGNER" | jq

# Get specific node
curl http://localhost:3000/api/registry/nodes/NODE_ID | jq

# Audit log
curl http://localhost:3000/api/registry/audit | jq

# Version history
curl http://localhost:3000/api/registry/versions | jq
curl http://localhost:3000/api/registry/versions/1 | jq

# Verify any document (pipe current doc into verify)
curl -s http://localhost:3000/api/registry/current | \
  curl -s -X POST http://localhost:3000/api/registry/verify \
    -H "Content-Type: application/json" -d @- | jq

# Propose enroll
curl -X POST http://localhost:3000/api/registry/nodes/enroll \
  -H "Content-Type: application/json" \
  -d '{"ikPub":"a1b2...","ekPub":"c3d4...","role":"PROVIDER_COSIGNER"}' | jq

# Propose governance role change
curl -X POST http://localhost:3000/api/registry/governance/role \
  -H "Content-Type: application/json" \
  -d '{"role":"POLICY_COMPLIANCE","display_name":"Policy & Compliance","addresses":["0x..."],"quorum":1,"features":{}}' | jq

# Propose infrastructure changes
curl -X POST http://localhost:3000/api/registry/infrastructure/propose \
  -H "Content-Type: application/json" \
  -d '{"backoffice_pubkey":"0x...","market_oracle_pubkey":"0x...","trusted_binary_hashes":[]}' | jq

# Propose ceremony config
curl -X POST http://localhost:3000/api/registry/ceremony-config/propose \
  -H "Content-Type: application/json" \
  -d '{"global_threshold_t":2,"max_participants_n":3,"allowed_protocols":["cmp"],"allowed_curves":["Secp256k1"]}' | jq

# Propose immutable policies
curl -X POST http://localhost:3000/api/registry/immutable-policies/propose \
  -H "Content-Type: application/json" \
  -d '{"max_withdrawal_usd_24h":1000000,"require_oracle_price":true,"enforce_whitelist":true}' | jq

# Sign and publish via web UI:
# Open http://localhost:3000/sign.html -> Sign & Publish tab
# Connect MetaMask, sign with required role wallets to meet all quorums, then publish
```
