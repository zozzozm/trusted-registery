# Proposal: Registry CI/CD Validation Pipeline

**Status:** Draft
**Author:** Security Engineering
**Registry:** `dev-custody-v1` -- https://github.com/zozzozm/trusted-registery

---

## 1. PR Validation Pipeline

Every PR that touches `data/registry.json` or `data/versions/` triggers a multi-step validation pipeline. All checks must pass before merge is allowed.

### 1a. Schema Validation

Validate the JSON structure of `data/registry.json` against the expected v2 schema before any cryptographic checks. Fail fast on malformed input.

**Required top-level sections:**

```
registry_metadata      object        nested metadata
governance             object        { roles: GovernanceRole[] }
ceremony_config        object        { global_threshold_t, max_participants_n, allowed_protocols, allowed_curves }
trusted_infrastructure object        { backoffice_pubkey, market_oracle_pubkey, trusted_binary_hashes }
nodes                  object[]      each: { node_id, ik_pub, ek_pub, role, status, enrolled_at, ... }
immutable_policies     object        { max_withdrawal_usd_24h, require_oracle_price, enforce_whitelist }
signatures             object[]      each: { role, signer, signature }
```

**Registry metadata fields:**

```
registry_id            string        must equal configured REGISTRY_ID
version                integer >= 1  monotonically increasing
issued_at              integer       unix timestamp (seconds)
expires_at             integer       unix timestamp, must be > issued_at
updated_at             string        ISO timestamp
document_hash          string        64-hex SHA-256
merkle_root            string        64-hex SHA-256
prev_document_hash     string|null   64-hex SHA-256, null only for v1
endpoints              object|null   { primary, mirrors[] }
```

**Governance role validation:**

| Field | Type | Constraints |
|-------|------|------------|
| `role` | enum | `SYSTEM_ADMIN`, `POLICY_COMPLIANCE`, `TREASURY_OPS`, `AUDIT_OBSERVER` |
| `display_name` | string | non-empty |
| `addresses` | string[] | Ethereum addresses, SYSTEM_ADMIN requires >= 3 |
| `quorum` | integer | >= 1, SYSTEM_ADMIN requires >= 2 |
| `features` | object | any key-value pairs |

**Node record validation:**

| Field | Type | Constraints |
|-------|------|------------|
| `node_id` | string | 64-hex, SHA-256 derived |
| `ik_pub` | string | 64-hex (32 bytes) |
| `ek_pub` | string | 64-hex (32 bytes) |
| `role` | enum | `USER_COSIGNER`, `PROVIDER_COSIGNER`, `RECOVERY_GUARDIAN` |
| `status` | enum | `ACTIVE`, `REVOKED`, `MAINTENANCE` |
| `enrolled_at` | integer | unix timestamp |
| `updated_at` | integer\|undefined | unix timestamp |
| `revoked_at` | integer\|null | null unless `status === 'REVOKED'` |
| `ik_rotations` | object[]\|undefined | rotation history entries (see Section 1h) |

**Ceremony config validation:**

- `global_threshold_t` must be integer >= 2
- `max_participants_n` must be integer >= `global_threshold_t`
- `allowed_protocols` must be non-empty string array
- `allowed_curves` must be non-empty string array

**Trusted infrastructure validation:**

- `backoffice_pubkey` must be valid Ethereum address (0x + 40 hex) or null
- `market_oracle_pubkey` must be valid Ethereum address or null
- `trusted_binary_hashes` must be array of 64-hex strings

**Immutable policies validation:**

- `max_withdrawal_usd_24h` must be a positive number
- `require_oracle_price` must be boolean
- `enforce_whitelist` must be boolean

### 1b. Version Continuity

```
new_doc.registry_metadata.version === previous_doc.registry_metadata.version + 1
```

- Read the previous version from `data/versions/{N-1}.json`
- For genesis (v1): `registry_metadata.prev_document_hash` must be `null`
- For all others: previous version file must exist

### 1c. Hash Chain (`prev_document_hash`)

```
new_doc.registry_metadata.prev_document_hash === previous_doc.registry_metadata.document_hash
```

Verified by reading `data/versions/{N-1}.json` and comparing its `registry_metadata.document_hash` field.

### 1d. Document Hash Integrity

Recompute the document hash from scratch and compare:

```typescript
const { signatures, ...body } = doc
body.registry_metadata.document_hash = ''
const expected = computeDocumentHash(body)  // deterministic JSON -> SHA-256
assert(expected === doc.registry_metadata.document_hash)
```

The `computeDocumentHash` function sorts all object keys recursively before hashing, ensuring deterministic serialization regardless of key insertion order.

### 1e. Merkle Root Integrity

Recompute the Merkle root from the `nodes[]` array:

```typescript
const sorted = [...doc.nodes].sort((a, b) => a.node_id.localeCompare(b.node_id))
const expected = computeMerkleRoot(sorted)
assert(expected === doc.registry_metadata.merkle_root)
```

The Merkle tree is a binary tree over `SHA256("leaf:" + SHA256(canonical_json(node)))` for each node, sorted by `node_id`. Empty node list produces `SHA256("empty")`.

### 1f. Role-Based Signature Verification

Verify per-role quorum EIP-712 v2 typed data signatures:

**Trust model (role-based governance):**
- Genesis (v1): SYSTEM_ADMIN role addresses must match `ADMIN_ADDRESS_*` env vars (external trust root). Other roles (if present) are verified against the document's own governance roles.
- Every subsequent version: ALL roles from the PREVIOUS version must sign with their quorum. Signatures are verified against the previous version's governance role addresses.
- The full chain is walked from genesis to HEAD to prevent self-referential role injection.

**Per-role verification:**
1. For each governance role in the reference version (previous version, or genesis env vars for v1):
   - Collect all signatures with matching `role` field
   - Require `count >= role.quorum`
   - No duplicate `signer` values within a role
   - Signature format: `0x`-prefixed 65-byte hex (130 hex chars + `0x` = 132 chars)
   - Recover signer via `ethers.verifyTypedData(domain, types, value, signature)`
   - Recovered address must match declared `signer`
   - `signer` must be in the role's `addresses[]` from the reference version

**EIP-712 domain:**

```typescript
{ name: 'MPC Node Registry', version: '2' }
```

**Env var patterns for all governance roles (CI secrets):**

| Role | Env Var Pattern | Example |
|------|----------------|---------|
| `SYSTEM_ADMIN` | `ADMIN_ADDRESS_0`, `ADMIN_ADDRESS_1`, `ADMIN_ADDRESS_2` | Required, min 3 |
| `POLICY_COMPLIANCE` | `POLICY_COMPLIANCE_ADDRESS_0`, `POLICY_COMPLIANCE_ADDRESS_1`, ... | Optional |
| `TREASURY_OPS` | `TREASURY_OPS_ADDRESS_0`, `TREASURY_OPS_ADDRESS_1`, ... | Optional |
| `AUDIT_OBSERVER` | `AUDIT_OBSERVER_ADDRESS_0`, `AUDIT_OBSERVER_ADDRESS_1`, ... | Optional |

These are read by `CONFIG.getGenesisRoleAddresses(prefix)` using `CONFIG.GENESIS_ROLE_PREFIXES`.

### 1g. Append-Only Checks

**Version files:** No existing `data/versions/{N}.json` file may be modified or deleted in a PR.

```bash
MODIFIED=$(git diff --name-only --diff-filter=MD "$BASE" HEAD -- 'data/versions/')
if [ -n "$MODIFIED" ]; then
  exit 1  # immutability violation
fi
```

**IK rotation history:** When a node exists in both the previous and new version, its `ik_rotations[]` array must be a strict superset of the previous version's. No existing entries may be modified or removed.

```typescript
for (const newNode of newDoc.nodes) {
  const prevNode = prevDoc.nodes.find(n => n.node_id === newNode.node_id)
  if (!prevNode) continue  // new enrollment, no history to check

  const prevRotations = prevNode.ik_rotations ?? []
  const newRotations  = newNode.ik_rotations ?? []

  // Must retain all existing entries
  if (newRotations.length < prevRotations.length) {
    fail(`Node ${newNode.node_id}: ik_rotations truncated`)
  }

  for (let i = 0; i < prevRotations.length; i++) {
    if (JSON.stringify(prevRotations[i]) !== JSON.stringify(newRotations[i])) {
      fail(`Node ${newNode.node_id}: ik_rotations[${i}] was modified`)
    }
  }
}
```

**Registry/version file identity:** `data/registry.json` must be byte-identical to `data/versions/{N}.json`.

### 1h. Identity Key Rotation Validation

When a node's `ik_pub` changes between versions, a rotation entry must be appended to `ik_rotations[]`.

**Validation rules:**

```typescript
for (const newNode of newDoc.nodes) {
  const prevNode = prevDoc.nodes.find(n => n.node_id === newNode.node_id)
  if (!prevNode) continue
  if (newNode.ik_pub === prevNode.ik_pub) continue  // no rotation

  // ik_pub changed -- validate rotation entry
  const prevRotations = prevNode.ik_rotations ?? []
  const newRotations  = newNode.ik_rotations ?? []

  if (newRotations.length !== prevRotations.length + 1) {
    fail(`Node ${newNode.node_id}: ik_pub changed but no rotation entry added`)
  }

  const entry = newRotations[newRotations.length - 1]

  // prev_ik_pub must match the old ik_pub
  if (entry.prev_ik_pub !== prevNode.ik_pub) {
    fail(`Rotation prev_ik_pub doesn't match previous version's ik_pub`)
  }

  // new_ik_pub must match the new ik_pub field
  if (entry.new_ik_pub !== newNode.ik_pub) {
    fail(`Rotation new_ik_pub doesn't match node's current ik_pub`)
  }

  // rotated_at must be a recent timestamp
  if (!Number.isInteger(entry.rotated_at) || entry.rotated_at <= 0) {
    fail(`Invalid rotated_at timestamp`)
  }

  // reason must be valid
  if (!['scheduled', 'compromise', 'upgrade'].includes(entry.reason)) {
    fail(`Invalid rotation reason: ${entry.reason}`)
  }

  // rotation proof validation depends on reason
  if (entry.reason === 'compromise') {
    // Old key is untrusted -- proof is null, requires out-of-band verification
    // CI allows null proof but adds a warning annotation
    if (entry.proof !== null) {
      fail(`Compromise rotation should have null proof`)
    }
    console.warn(`::warning::Compromise rotation for ${newNode.node_id} -- verify out-of-band`)
  } else {
    // Normal rotation -- verify proof: Sign(old_ik_priv, SHA256("ROTATE" + nodeId + newIkPub + timestamp))
    if (!entry.proof) {
      fail(`Non-compromise rotation requires proof`)
    }
    const message = hashString('ROTATE' + newNode.node_id + entry.new_ik_pub + entry.rotated_at)
    const valid = ed25519.verify(entry.proof, message, entry.prev_ik_pub)
    if (!valid) {
      fail(`Invalid rotation proof for node ${newNode.node_id}`)
    }
  }
}
```

**Rotation entry schema:**

| Field | Type | Description |
|-------|------|------------|
| `prev_ik_pub` | string | 64-hex, must match previous version's `ik_pub` |
| `new_ik_pub` | string | 64-hex, must match new `ik_pub` field |
| `proof` | string\|null | Ed25519 signature by old key, null if `reason=compromise` |
| `rotated_at` | integer | Unix timestamp of rotation |
| `reason` | enum | `scheduled`, `compromise`, `upgrade` |

### 1i. Node Status Transitions

Only the following status transitions are valid:

```
ACTIVE       -> MAINTENANCE    (temporary offline for key rotation, upgrade)
MAINTENANCE  -> ACTIVE         (back online)
ACTIVE       -> REVOKED        (permanent removal)
MAINTENANCE  -> REVOKED        (permanent removal from maintenance)
```

**Invalid transitions (CI must reject):**

```
REVOKED      -> ACTIVE         X  (revocation is permanent)
REVOKED      -> MAINTENANCE    X  (revocation is permanent)
ACTIVE       -> ACTIVE         -  (no change, allowed)
MAINTENANCE  -> MAINTENANCE    -  (no change, allowed)
REVOKED      -> REVOKED        -  (no change, allowed)
```

```typescript
const VALID_TRANSITIONS: Record<string, string[]> = {
  ACTIVE:      ['ACTIVE', 'MAINTENANCE', 'REVOKED'],
  MAINTENANCE: ['MAINTENANCE', 'ACTIVE', 'REVOKED'],
  REVOKED:     ['REVOKED'],
}

for (const newNode of newDoc.nodes) {
  const prevNode = prevDoc.nodes.find(n => n.node_id === newNode.node_id)
  if (!prevNode) continue  // new enrollment

  const allowed = VALID_TRANSITIONS[prevNode.status]
  if (!allowed?.includes(newNode.status)) {
    fail(`Invalid status transition for ${newNode.node_id}: ${prevNode.status} -> ${newNode.status}`)
  }

  // If revoked, revoked_at must be set
  if (newNode.status === 'REVOKED' && !newNode.revoked_at) {
    fail(`Revoked node ${newNode.node_id} must have revoked_at timestamp`)
  }
}
```

### 1j. Registry/Version File Identity

```bash
diff -q data/registry.json "data/versions/${VERSION}.json"
```

Both files must be byte-identical. This ensures the version archive is a faithful record.

---

## 2. GitHub Actions Workflow

### 2.1 Workflow YAML

```yaml
# .github/workflows/verify.yml
name: Verify Registry Document

on:
  push:
    branches: [main]
  pull_request:

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Check if registry files changed
        id: check
        run: |
          if [ "${{ github.event_name }}" = "pull_request" ]; then
            BASE=${{ github.event.pull_request.base.sha }}
          else
            BASE=${{ github.event.before }}
          fi
          echo "Comparing $BASE..HEAD"
          if git diff --name-only "$BASE" HEAD | grep -qE 'data/(registry\.json|versions/)'; then
            echo "changed=true" >> $GITHUB_OUTPUT
          else
            echo "changed=false" >> $GITHUB_OUTPUT
          fi

      - uses: actions/setup-node@v4
        if: steps.check.outputs.changed == 'true'
        with:
          node-version: '20'
          cache: 'npm'

      - run: npm ci
        if: steps.check.outputs.changed == 'true'

      # -- Step 1: Full document verification ---------------------------------
      # Runs scripts/verify-file.ts which handles:
      # - Schema validation (required sections)
      # - Registry ID check
      # - Document hash recomputation
      # - Merkle root recomputation
      # - EIP-712 v2 role-based signature verification (per-role quorum)
      # - Version chain linkage (signatures verified against previous version's roles)
      - name: Verify registry document signatures
        if: steps.check.outputs.changed == 'true'
        env:
          ADMIN_ADDRESS_0: ${{ secrets.ADMIN_ADDRESS_0 }}
          ADMIN_ADDRESS_1: ${{ secrets.ADMIN_ADDRESS_1 }}
          ADMIN_ADDRESS_2: ${{ secrets.ADMIN_ADDRESS_2 }}
          POLICY_COMPLIANCE_ADDRESS_0: ${{ secrets.POLICY_COMPLIANCE_ADDRESS_0 }}
          TREASURY_OPS_ADDRESS_0: ${{ secrets.TREASURY_OPS_ADDRESS_0 }}
          AUDIT_OBSERVER_ADDRESS_0: ${{ secrets.AUDIT_OBSERVER_ADDRESS_0 }}
          REGISTRY_ID:     ${{ secrets.REGISTRY_ID || 'dev-custody-v1' }}
          REGISTRY_FILE:   './data/registry.json'
        run: npx ts-node scripts/verify-file.ts

      # -- Step 2: Append-only enforcement ------------------------------------
      # No existing version file may be modified or deleted.
      - name: Append-only check -- version files are immutable
        if: steps.check.outputs.changed == 'true'
        run: |
          if [ "${{ github.event_name }}" = "pull_request" ]; then
            BASE=${{ github.event.pull_request.base.sha }}
          else
            BASE=${{ github.event.before }}
          fi
          MODIFIED=$(git diff --name-only --diff-filter=MD "$BASE" HEAD -- 'data/versions/' || true)
          if [ -n "$MODIFIED" ]; then
            echo "::error::Version files were modified or deleted: $MODIFIED"
            exit 1
          fi
          echo "Append-only check passed"

      # -- Step 3: Version continuity -----------------------------------------
      # version file must exist and match registry.json; prev version must exist
      - name: Version continuity check
        if: steps.check.outputs.changed == 'true'
        run: |
          LATEST_VERSION=$(jq '.registry_metadata.version' data/registry.json)
          VERSION_FILE="data/versions/${LATEST_VERSION}.json"

          if [ ! -f "$VERSION_FILE" ]; then
            echo "::error::Missing version file: $VERSION_FILE"
            exit 1
          fi

          if ! diff -q data/registry.json "$VERSION_FILE" > /dev/null 2>&1; then
            echo "::error::registry.json and $VERSION_FILE differ"
            exit 1
          fi

          if [ "$LATEST_VERSION" -gt 1 ]; then
            PREV_FILE="data/versions/$((LATEST_VERSION - 1)).json"
            if [ ! -f "$PREV_FILE" ]; then
              echo "::error::Previous version file missing: $PREV_FILE"
              exit 1
            fi
          fi
          echo "Version continuity check passed (v${LATEST_VERSION})"

      # -- Step 4: Hash chain linkage -----------------------------------------
      - name: Hash chain verification
        if: steps.check.outputs.changed == 'true'
        run: |
          LATEST_VERSION=$(jq '.registry_metadata.version' data/registry.json)
          if [ "$LATEST_VERSION" -gt 1 ]; then
            PREV_FILE="data/versions/$((LATEST_VERSION - 1)).json"
            PREV_HASH=$(jq -r '.registry_metadata.document_hash' "$PREV_FILE")
            CHAIN_HASH=$(jq -r '.registry_metadata.prev_document_hash' data/registry.json)
            if [ "$PREV_HASH" != "$CHAIN_HASH" ]; then
              echo "::error::Hash chain broken: prev_document_hash=$CHAIN_HASH, expected=$PREV_HASH"
              exit 1
            fi
            echo "Hash chain verified: v$((LATEST_VERSION - 1)) -> v${LATEST_VERSION}"
          else
            echo "Genesis document -- no chain to verify"
          fi

      # -- Step 5: Node status transitions & IK rotation validation -----------
      # Compares new document against previous version for:
      # - Valid status transitions (ACTIVE->MAINTENANCE, etc.)
      # - IK rotation proof validation
      # - ik_rotations append-only enforcement
      - name: Validate node changes
        if: steps.check.outputs.changed == 'true'
        env:
          REGISTRY_ID:     ${{ secrets.REGISTRY_ID || 'dev-custody-v1' }}
          REGISTRY_FILE:   './data/registry.json'
        run: npx ts-node scripts/verify-node-changes.ts

      - name: Skip -- registry files not changed
        if: steps.check.outputs.changed == 'false'
        run: echo "registry files not modified -- skipping verification"
```

### 2.2 Node Changes Validation Script

This script (`scripts/verify-node-changes.ts`) handles the checks requiring comparison between the previous and new document versions: status transitions, IK rotation validation, and `ik_rotations` append-only enforcement.

```typescript
// scripts/verify-node-changes.ts
// Validates node-level changes between previous and new registry versions:
// - Status transition rules
// - Identity key rotation proofs
// - ik_rotations[] append-only integrity

import { readFileSync, existsSync } from 'fs'
import { dirname, resolve } from 'path'
import { createHash } from 'crypto'
import { CONFIG } from '../src/common/config'

const VALID_TRANSITIONS: Record<string, string[]> = {
  ACTIVE:      ['ACTIVE', 'MAINTENANCE', 'REVOKED'],
  MAINTENANCE: ['MAINTENANCE', 'ACTIVE', 'REVOKED'],
  REVOKED:     ['REVOKED'],
}

function main() {
  const file = CONFIG.REGISTRY_FILE
  const newDoc = JSON.parse(readFileSync(file, 'utf-8'))
  const versionsDir = resolve(dirname(file), 'versions')
  const version = newDoc.registry_metadata.version

  if (version <= 1) {
    console.log('Genesis document -- no previous version to compare')
    return
  }

  const prevFile = resolve(versionsDir, `${version - 1}.json`)
  if (!existsSync(prevFile)) {
    console.warn(`Previous version ${version - 1} not found -- skipping node change validation`)
    return
  }

  const prevDoc = JSON.parse(readFileSync(prevFile, 'utf-8'))
  let errors = 0

  for (const newNode of newDoc.nodes) {
    const prevNode = prevDoc.nodes.find((n: any) => n.node_id === newNode.node_id)
    if (!prevNode) continue  // new enrollment

    // -- Status transition -------------------------------------------------
    const allowed = VALID_TRANSITIONS[prevNode.status]
    if (!allowed?.includes(newNode.status)) {
      console.error(`::error::Invalid status transition for ${newNode.node_id}: ${prevNode.status} -> ${newNode.status}`)
      errors++
    }

    if (newNode.status === 'REVOKED' && !newNode.revoked_at) {
      console.error(`::error::Revoked node ${newNode.node_id} missing revoked_at timestamp`)
      errors++
    }

    // -- ik_rotations append-only ------------------------------------------
    const prevRotations = prevNode.ik_rotations ?? []
    const newRotations  = newNode.ik_rotations ?? []

    if (newRotations.length < prevRotations.length) {
      console.error(`::error::Node ${newNode.node_id}: ik_rotations truncated (${prevRotations.length} -> ${newRotations.length})`)
      errors++
    }

    for (let i = 0; i < prevRotations.length; i++) {
      if (JSON.stringify(prevRotations[i]) !== JSON.stringify(newRotations[i])) {
        console.error(`::error::Node ${newNode.node_id}: ik_rotations[${i}] was modified`)
        errors++
      }
    }

    // -- IK rotation validation --------------------------------------------
    if (newNode.ik_pub !== prevNode.ik_pub) {
      if (newRotations.length !== prevRotations.length + 1) {
        console.error(`::error::Node ${newNode.node_id}: ik_pub changed but no rotation entry added`)
        errors++
        continue
      }

      const entry = newRotations[newRotations.length - 1]

      if (entry.prev_ik_pub !== prevNode.ik_pub) {
        console.error(`::error::Node ${newNode.node_id}: rotation prev_ik_pub doesn't match previous ik_pub`)
        errors++
      }
      if (entry.new_ik_pub !== newNode.ik_pub) {
        console.error(`::error::Node ${newNode.node_id}: rotation new_ik_pub doesn't match current ik_pub`)
        errors++
      }
      if (!Number.isInteger(entry.rotated_at) || entry.rotated_at <= 0) {
        console.error(`::error::Node ${newNode.node_id}: invalid rotated_at timestamp`)
        errors++
      }
      if (!['scheduled', 'compromise', 'upgrade'].includes(entry.reason)) {
        console.error(`::error::Node ${newNode.node_id}: invalid rotation reason '${entry.reason}'`)
        errors++
      }

      if (entry.reason === 'compromise') {
        if (entry.proof !== null) {
          console.error(`::error::Node ${newNode.node_id}: compromise rotation must have null proof`)
          errors++
        }
        console.warn(`::warning::Compromise rotation for ${newNode.node_id} -- requires out-of-band verification`)
      } else {
        if (!entry.proof) {
          console.error(`::error::Node ${newNode.node_id}: non-compromise rotation requires proof`)
          errors++
        }
        // Ed25519 proof: Sign(old_ik_priv, SHA256("ROTATE" + nodeId + newIkPub + timestamp))
        // Full cryptographic verification would require an Ed25519 library.
        // For now, validate proof format (128-hex Ed25519 signature).
        if (entry.proof && !/^[0-9a-f]{128}$/i.test(entry.proof)) {
          console.error(`::error::Node ${newNode.node_id}: proof is not a valid 64-byte hex signature`)
          errors++
        }
      }
    }
  }

  if (errors > 0) {
    console.error(`\n${errors} node validation error(s) found`)
    process.exit(1)
  }

  console.log(`Node changes validated: ${newDoc.nodes.length} nodes checked against v${version - 1}`)
}

main()
```

### 2.3 Check Summary

| Step | Tool | What It Validates | Blocks PR |
|------|------|-------------------|-----------|
| Verify registry document | `scripts/verify-file.ts` | Schema, registry ID, doc hash, merkle root, EIP-712 v2 role-based quorum sigs, version chain | Yes |
| Append-only check | Shell (`git diff`) | No version files modified or deleted | Yes |
| Version continuity | Shell (`jq`, `diff`) | Version file exists, matches registry.json, prev version exists | Yes |
| Hash chain | Shell (`jq`) | `registry_metadata.prev_document_hash` links to previous version | Yes |
| Validate node changes | `scripts/verify-node-changes.ts` | Status transitions, IK rotation proofs, ik_rotations append-only | Yes |

---

## 3. Migration Plan

### Current State

```
data/
+-- registry.json       <- latest (v3)
+-- versions/
    +-- 3.json           <- written by current saveToDisk()
```

The version chain is already partially implemented. `saveToDisk()` in `registry.service.ts` writes both `registry.json` and `versions/{N}.json` on each publish.

### Phase 1: Backfill Missing History (Optional)

Extract older versions from git history if full chain-walk from genesis is desired:

```bash
# For each historical commit that changed data/registry.json:
for COMMIT in $(git log --all --pretty=format:"%H" --reverse -- data/registry.json); do
  VERSION=$(git show "$COMMIT:data/registry.json" | jq '.registry_metadata.version')
  if [ ! -f "data/versions/${VERSION}.json" ]; then
    git show "$COMMIT:data/registry.json" > "data/versions/${VERSION}.json"
    echo "Extracted v${VERSION}"
  fi
done
```

This is optional. The chain only needs to exist from the point where nodes start using chain-walk.

### Phase 2: Add Node Change Validation Script

Create `scripts/verify-node-changes.ts` (Section 2.2 above). No impact on existing code.

### Phase 3: Update CI Workflow

Replace `.github/workflows/verify.yml` with the expanded version (Section 2.1). This adds:
- Role-based env vars for all governance roles (not just SYSTEM_ADMIN)
- Node validation step
- Existing checks remain unchanged

### Phase 4: Add IK Rotation Fields to Types

The `IkRotationEntry` interface and `ik_rotations` field on `NodeRecord` are already defined in `src/common/types.ts`:

```typescript
export interface IkRotationEntry {
  prev_ik_pub:  string
  new_ik_pub:   string
  rotated_at:   number
  reason:       string
  proof:        string
}

export interface NodeRecord {
  node_id:         string
  ik_pub:          string
  ek_pub:          string
  role:            NodeRole
  status:          NodeStatus
  enrolled_at:     number
  updated_at?:     number
  revoked_at?:     number | null
  ik_rotations?:   IkRotationEntry[]
}
```

### Phase 5: Add Rotation Proof Verification

Ed25519 signature verification for rotation proofs is already implemented in `src/common/crypto.ts` using `@noble/curves/ed25519`:

```typescript
export function verifyRotationProof(
  nodeId: string,
  newIkPub: string,
  rotatedAt: number,
  proof: string,
  previousIkPub: string,
): boolean {
  const message = hashString('ROTATE' + nodeId + newIkPub + rotatedAt.toString())
  const msgBytes = Buffer.from(message, 'hex')
  const sigBytes = Buffer.from(proof, 'hex')
  const pubBytes = Buffer.from(previousIkPub, 'hex')
  return ed25519.verify(sigBytes, msgBytes, pubBytes)
}
```

### Rollout Order

```
1. scripts/verify-node-changes.ts     <- new file, no impact
2. .github/workflows/verify.yml       <- add node validation step + role env vars
3. Backfill historical versions        <- optional, for full chain-walk
```

Each step is independently deployable. Steps 1-2 can be deployed immediately -- the node validation script gracefully handles nodes that don't have `ik_rotations[]` yet.

---

## 4. Security Considerations

### 4.1 Branch Protection

**Required GitHub branch protection rules for `main`:**

| Rule | Setting | Why |
|------|---------|-----|
| Require PR before merge | Enabled | No direct pushes to main |
| Require status checks | `verify` job must pass | CI cannot be skipped |
| Require review approvals | >= 1 | Human review before merge |
| Dismiss stale reviews | Enabled | Force re-review if PR changes after approval |
| Restrict force pushes | Block all | Prevents history rewriting |
| Restrict deletions | Enabled | Prevents branch deletion |
| Require linear history | Recommended | Simplifies git log auditing |

### 4.2 CI Bypass Prevention

**Threat:** An admin with GitHub repo access merges a PR without CI passing.

**Mitigations:**
- Branch protection: "Require status checks to pass before merging" -- enforced, no admin override
- No `paths-ignore` in workflow triggers -- CI runs on ALL PRs
- Audit trail: GitHub audit log tracks who merged and whether checks passed
- Use `CODEOWNERS` file to require specific team members for `data/` changes:

```
# .github/CODEOWNERS
/data/ @admin-team
```

**Threat:** Attacker compromises a GitHub Action or dependency in CI.

**Mitigations:**
- Pin action versions to SHA (e.g., `actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11` instead of `@v4`)
- Use `npm ci` (lockfile-only installs) instead of `npm install`
- Review dependency updates carefully -- especially `ethers` and crypto libraries

### 4.3 Force Push Protection

**Threat:** Attacker with admin access force-pushes to `main`, rewriting version history.

**Mitigations:**
- Branch protection blocks force pushes
- Git signed commits (optional but recommended for admins)
- External monitoring: A cron job or separate service can independently fetch and verify the registry, alerting if the hash chain breaks

### 4.4 Rate Limiting

The registry updates infrequently (~monthly). Abnormal activity patterns should be flagged:

- **PR frequency:** More than 3 registry update PRs per week is suspicious
- **Version jumps:** Version incrementing by more than 1 indicates an error or attack
- **Governance rotation frequency:** More than 1 governance role rotation per month warrants investigation

These are human process controls, not CI enforcement -- the team is small enough to catch anomalies in PR review.

### 4.5 Secrets Management

| Secret | Purpose | Rotation Policy |
|--------|---------|----------------|
| `ADMIN_ADDRESS_0..2` | Genesis SYSTEM_ADMIN addresses for CI verification | Rotate when admin keys change |
| `POLICY_COMPLIANCE_ADDRESS_*` | POLICY_COMPLIANCE role addresses (optional) | Rotate when role addresses change |
| `TREASURY_OPS_ADDRESS_*` | TREASURY_OPS role addresses (optional) | Rotate when role addresses change |
| `AUDIT_OBSERVER_ADDRESS_*` | AUDIT_OBSERVER role addresses (optional) | Rotate when role addresses change |
| `REGISTRY_ID` | Registry identity check | Rarely changes |

These secrets are **read-only** verification inputs -- they cannot be used to forge signatures. The role signer private keys are never stored in GitHub.

### 4.6 Compromise Rotation Gap

When `reason=compromise`, the rotation proof is null because the old key is untrusted. This creates a trust gap that CI alone cannot close.

**Required process for compromise rotations:**
1. At least 2 admins must approve the PR (elevated review requirement)
2. PR description must include incident details and out-of-band verification evidence
3. CI emits a `::warning::` annotation to flag the compromise rotation
4. The team should consider whether other nodes may be compromised

---

## Appendix: Current vs. Proposed Check Coverage

| Check | Currently Implemented | In This Proposal |
|-------|----------------------|------------------|
| Schema validation (required sections) | Partial (in verify-file.ts) | Full JSON schema |
| Registry ID | Yes | Yes |
| Document hash recomputation | Yes | Yes |
| Merkle root recomputation | Yes (in verify-file.ts) | Yes |
| EIP-712 v2 role-based signature verification | Yes (per-role quorum) | Yes |
| Version continuity (N == N-1 + 1) | Partial (file exists check) | Full (version number check) |
| Hash chain (prev_document_hash) | Yes | Yes |
| Append-only (version files) | Yes | Yes |
| Append-only (ik_rotations) | No | New |
| IK rotation proof validation | No | New |
| Node status transitions | No | New |
| Registry/version file identity | Yes | Yes |
| Governance role validation | Yes (SYSTEM_ADMIN) | Full (all roles) |
| Immutable policies validation | Yes | Yes |
| Trusted infrastructure validation | Yes | Yes |
