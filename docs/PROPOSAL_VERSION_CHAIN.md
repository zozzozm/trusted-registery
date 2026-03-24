# Proposal: Registry Version Chain

## 1. Problem Statement

The trusted registry uses a chained trust model where each version is signed by the current governance roles. Role changes (e.g., adding POLICY_COMPLIANCE or rotating SYSTEM_ADMIN addresses) are authorized by the existing roles -- version N+1 (with updated roles) is signed by the governance roles from version N. This creates a **sequential dependency**: a node must see every version to track governance changes.

**Currently, only the latest `data/registry.json` is stored on GitHub.** Historical versions are overwritten on each publish. If a node misses an intermediate version where governance roles rotated, it gets stuck:

```
Node cache:  v41  SYSTEM_ADMIN=[A,B,C]  <- last version the node saw
GitHub v42:  SYSTEM_ADMIN=[D,E,F]  signed by [A,B]  <- node missed this (was offline)
GitHub v43:  SYSTEM_ADMIN=[D,E,F]  signed by [D,E]  <- node fetches this, but trusts [A,B,C]
                                                        -> verification fails, node is stuck
```

The node cannot verify v43 because it still trusts `[A,B,C]`, but v43 was signed by `[D,E]`. The intermediate v42 -- which bridges the trust from `[A,B,C]` to `[D,E,F]` -- no longer exists on GitHub.

**Impact:** Any node that goes offline during a governance role rotation is permanently unable to sync. The only recovery is manual intervention: an operator must update the node's trusted governance roles out-of-band, which defeats the purpose of the cryptographic trust chain.

This hasn't been a problem yet because governance rotations are rare and all nodes have been online. But for a custody system, "works as long as nothing goes wrong" is not acceptable.

---

## 2. Proposed Solution -- Versioned Directory

### Repository Structure Change

```
data/
+-- registry.json              <- always the latest version (backward-compatible)
+-- versions/
    +-- 1.json                 <- genesis document (immutable)
    +-- 2.json                 <- v2 (immutable)
    +-- 3.json                 <- v3 (immutable)
    +-- ...
```

**Rules:**
- `data/registry.json` is always identical to the highest-numbered version file. Existing consumers that only read this file continue to work unchanged.
- `data/versions/{N}.json` is append-only. Once a version file is committed, it is never modified or deleted.
- Each PR that updates `registry.json` must also add the corresponding `data/versions/{N}.json`. CI enforces this.

### What Changes, What Doesn't

| Component | Changes? | Details |
|-----------|----------|---------|
| GitHub repo structure | Yes | Add `data/versions/` directory |
| `registry.json` content/format | No | Identical document format |
| Role-based signing flow | No | Same EIP-712 v2 per-role quorum signatures |
| Registry server (`registry.service.ts`) | Yes | `saveToDisk()` also writes version file |
| CI workflow (`verify.yml`) | Yes | Append-only check + chain verification |
| Node fetch logic (wallet consumers) | Yes | Chain-walk on version gap |
| `scripts/verify-file.ts` | Minor | Also verify chain continuity |

---

## 3. Chain-Walk Algorithm

When a node detects a version gap, it walks the chain from its cached version to the latest, verifying each step and updating its trusted governance roles along the way.

### Pseudocode

```
function syncRegistry(cachedDoc, latestDoc):
    // No gap -- simple case
    if latestDoc.registry_metadata.version == cachedDoc.registry_metadata.version + 1:
        verify(latestDoc, cachedDoc.governance.roles)
        return latestDoc

    if latestDoc.registry_metadata.version <= cachedDoc.registry_metadata.version:
        reject("rollback detected")

    // Gap detected -- walk the chain
    trustedRoles = cachedDoc.governance.roles
    prevHash     = cachedDoc.registry_metadata.document_hash
    current      = cachedDoc

    for v in (cachedDoc.registry_metadata.version + 1) ... latestDoc.registry_metadata.version:
        doc = fetchVersion(v)  // GET data/versions/{v}.json

        if doc is null:
            abort("missing intermediate version v{v}")

        // Verify this version against current trusted state
        assert doc.registry_metadata.version == v
        assert doc.registry_metadata.prev_document_hash == prevHash
        assert doc.registry_metadata.registry_id == cachedDoc.registry_metadata.registry_id
        verifyDocumentHash(doc)
        verifyMerkleRoot(doc)
        // Verify ALL governance roles meet their quorum
        for role in trustedRoles:
            verifyRoleQuorum(doc, role)

        // Trust transition: adopt this version's governance roles
        trustedRoles = doc.governance.roles
        prevHash     = doc.registry_metadata.document_hash
        current      = doc

    return current  // now equals latestDoc, fully verified
```

### Key Properties

1. **Each step is verified against the governance roles from the previous step.** This is the same trust model as sequential updates -- the chain-walk just replays what the node missed.
2. **The node never trusts a new set of governance roles without cryptographic proof** that the previous roles authorized the transition.
3. **ALL roles from the previous version must sign with their quorum.** Adding POLICY_COMPLIANCE in v5 means v6 requires both SYSTEM_ADMIN and POLICY_COMPLIANCE signatures.
4. **If any intermediate version is missing or invalid, the walk aborts.** The node stays on its last known-good version.
5. **The walk is O(k) where k = number of missed versions.** With a few updates per month, k is small (typically < 10 even for a node offline for months).

---

## 4. Node Fetch Flow

### Current Flow

```
1. Fetch registry.json from primary endpoint
2. If fetch fails, try mirrors
3. If all fail, use cached version
4. Verify document (hash, merkle, role-based signatures against trusted governance roles)
5. If version <= HWM, reject (rollback protection)
6. Accept and cache
```

### Updated Flow

```
1. Fetch registry.json from primary endpoint
2. If fetch fails, try mirrors
3. If all fail, use cached version -> DONE

4. If latest.version == cached.version:
     -> no update, DONE

5. If latest.version < cached.version:
     -> rollback detected, reject, DONE

6. If latest.version == cached.version + 1:
     -> verify against current trusted governance roles
     -> if valid: accept, update cache, update HWM, DONE
     -> if invalid: reject, keep cache

7. If latest.version > cached.version + 1:
     -> GAP DETECTED -- chain-walk required
     -> for v in (cached.version + 1) to (latest.version):
         fetch data/versions/{v}.json
         verify against current trusted governance roles (all roles, all quorums)
         update trusted governance roles from verified doc
     -> if all steps pass: accept latest, update cache, update HWM
     -> if any step fails: reject, keep cache, log error
```

### Version File URL Pattern

Nodes construct version URLs from the primary endpoint:

```
primary:  https://raw.githubusercontent.com/.../data/registry.json
version:  https://raw.githubusercontent.com/.../data/versions/{N}.json
```

The base path is derived by replacing `registry.json` with `versions/{N}.json`. This avoids adding a new field to the document -- the version URL is deterministic from the primary endpoint.

### Backward Compatibility

Nodes that haven't been updated to support chain-walk continue to work exactly as before:
- They fetch `registry.json` (unchanged location and format)
- If they miss a governance rotation, they fail verification and stay on their cached version
- This is the same behavior as today -- no regression

Updated nodes gain the ability to recover from missed governance rotations automatically.

---

## 5. CI / GitHub Actions

### Updated Workflow

The existing `verify.yml` workflow needs three additional checks when `data/versions/` is involved:

#### 5.1 Append-Only Check

No existing version file may be modified or deleted.

```yaml
- name: Append-only check -- version files are immutable
  run: |
    MODIFIED=$(git diff --name-only --diff-filter=MD "$BASE" HEAD -- 'data/versions/')
    if [ -n "$MODIFIED" ]; then
      echo "::error::Version files were modified or deleted: $MODIFIED"
      exit 1
    fi
```

#### 5.2 Version Continuity Check

The new version file must be exactly `{prev_max + 1}.json`, and `registry.json` must match it.

```yaml
- name: Version continuity check
  run: |
    LATEST_VERSION=$(jq '.registry_metadata.version' data/registry.json)
    VERSION_FILE="data/versions/${LATEST_VERSION}.json"

    if [ ! -f "$VERSION_FILE" ]; then
      echo "::error::Missing version file: $VERSION_FILE"
      exit 1
    fi

    # registry.json and version file must be identical
    if ! diff -q data/registry.json "$VERSION_FILE" > /dev/null 2>&1; then
      echo "::error::registry.json and $VERSION_FILE differ"
      exit 1
    fi

    # Previous version file must exist (unless genesis)
    if [ "$LATEST_VERSION" -gt 1 ]; then
      PREV_FILE="data/versions/$((LATEST_VERSION - 1)).json"
      if [ ! -f "$PREV_FILE" ]; then
        echo "::error::Previous version file missing: $PREV_FILE"
        exit 1
      fi
    fi
```

#### 5.3 Hash Chain Verification

Verify `prev_document_hash` links correctly to the previous version file.

```yaml
- name: Hash chain verification
  run: |
    LATEST_VERSION=$(jq '.registry_metadata.version' data/registry.json)
    if [ "$LATEST_VERSION" -gt 1 ]; then
      PREV_FILE="data/versions/$((LATEST_VERSION - 1)).json"
      PREV_HASH=$(jq -r '.registry_metadata.document_hash' "$PREV_FILE")
      CHAIN_HASH=$(jq -r '.registry_metadata.prev_document_hash' data/registry.json)
      if [ "$PREV_HASH" != "$CHAIN_HASH" ]; then
        echo "::error::Hash chain broken: prev=$CHAIN_HASH, expected=$PREV_HASH"
        exit 1
      fi
    fi
```

#### 5.4 Existing Signature Verification

The existing `scripts/verify-file.ts` verifies `data/registry.json` using role-based quorum verification. For genesis (v1), SYSTEM_ADMIN role addresses are verified against `ADMIN_ADDRESS_*` env vars. For subsequent versions, each role's signatures are verified against the previous version's governance roles.

### Full CI Check Summary

| Check | What it verifies | Blocks PR if |
|-------|-----------------|--------------|
| Append-only | No version file modified/deleted | Any existing `data/versions/*.json` changed |
| Continuity | Version N file exists, matches registry.json | Missing file, or content mismatch |
| Hash chain | `prev_document_hash` links to N-1 | Chain link broken |
| Role-based signatures | EIP-712 v2 per-role quorum valid | Any role fails quorum or signature verification |

---

## 6. Security Analysis

### Attacks This Prevents

| Attack | How chain-walk helps |
|--------|---------------------|
| **Stale node lockout** | Node recovers by walking the chain -- no manual intervention needed |
| **Governance rotation confusion** | Each trust transition is cryptographically verified step-by-step, across all governance roles |
| **Version file tampering** | CI append-only check + hash chain + role-based signatures prevent modification |
| **Selective version deletion** | CI continuity check ensures no gaps; chain-walk aborts on missing files |
| **Forged intermediate version** | Each version's signatures are verified against the previous version's governance roles |
| **Role injection attack** | A new role added in version N must be signed by all roles from version N-1 |

### What This Does NOT Prevent

| Attack | Why | Mitigation |
|--------|-----|-----------|
| **GitHub total compromise** (attacker replaces all version files consistently) | If attacker controls the repo and can forge valid signatures, no file-based solution helps | This requires compromising quorum keys across all governance roles -- much harder with multiple roles |
| **Multi-role key compromise** | Attacker with quorum keys for ALL governance roles can sign arbitrary versions | Key management hygiene, hardware wallets, rotation policy, separation of duties across roles |
| **GitHub outage** | Can't fetch version files at all | Mirrors, local cache -- same as today |
| **Storage exhaustion** | Attacker submits many valid versions to fill repo | Rate limiting at PR review level; versions are small (~2KB each) |

### Trust Model

The trust model is unchanged. The version chain does not introduce new trust assumptions -- it preserves the existing ones:

1. **Genesis trust root**: `ADMIN_ADDRESS_*` env vars (SYSTEM_ADMIN addresses) compiled into the node binary
2. **Chained trust**: Each version's governance roles are authorized by the previous version's role signatures
3. **Per-role quorum**: No single signer within a role can authorize changes alone (SYSTEM_ADMIN requires 2-of-3)
4. **All-role coverage**: ALL governance roles from the previous version must sign the new version

The version chain simply makes this model **recoverable** -- a node that misses updates can replay the chain instead of getting stuck.

---

## 7. Migration Plan

### Phase 1: Backfill History (One-Time)

Create `data/versions/` with all historical versions. Since we're currently at an early version and the repo has been overwriting `registry.json`, we only have the current version available. Two options:

**Option A -- Start fresh (recommended for dev registry):**
1. Create `data/versions/{N}.json` as a copy of current `data/registry.json`
2. All nodes already have the current version cached -- no chain-walk needed
3. Future versions will have full chain history from this point

**Option B -- Backfill from git history:**
1. Extract each historical `data/registry.json` from git commits: `git log --all --pretty=format:"%H" -- data/registry.json`
2. For each commit, checkout and copy the file to `data/versions/{version}.json`
3. Verify the chain is intact

Option A is simpler and sufficient. The chain only needs to exist from the point where nodes start using chain-walk. Older versions are already trusted by all running nodes.

### Phase 2: Server-Side Changes

Update `registry.service.ts` `saveToDisk()` to also write the version file:

```typescript
private saveToDisk() {
  const dir = dirname(CONFIG.REGISTRY_FILE)
  try { mkdirSync(dir, { recursive: true }) } catch {}

  // Write registry.json (unchanged)
  const tmpFile = CONFIG.REGISTRY_FILE + '.tmp'
  writeFileSync(tmpFile, JSON.stringify(this.currentDoc, null, 2))
  renameSync(tmpFile, CONFIG.REGISTRY_FILE)

  // Write version file
  const versionDir = resolve(dir, 'versions')
  try { mkdirSync(versionDir, { recursive: true }) } catch {}
  const versionFile = resolve(versionDir, `${this.currentDoc?.registry_metadata.version}.json`)
  writeFileSync(versionFile, JSON.stringify(this.currentDoc, null, 2))

  console.log(`[Registry] Saved version ${this.currentDoc?.registry_metadata.version} to disk`)
}
```

### Phase 3: CI Updates

Add the append-only, continuity, and hash-chain checks to `.github/workflows/verify.yml` (see Section 5).

### Phase 4: Node Updates

Update wallet/node fetch logic to support chain-walk (see Section 4). This can be rolled out gradually -- nodes without chain-walk support continue to work as before.

### Rollout Order

```
1. Backfill data/versions/{N}.json              <- no impact on anything
2. Update saveToDisk() in registry server        <- starts writing version files
3. Update CI workflow                            <- enforces append-only + chain
4. Update node fetch logic                       <- nodes gain chain-walk
```

Each step is independently deployable. Steps 1-3 are backward-compatible -- no node changes needed. Step 4 is the only client-side change.

---

## 8. Edge Cases

### Very Stale Node

**Scenario:** A node cached v5 and the registry is now at v50. The node needs to fetch 45 intermediate versions.

**Handling:** The chain-walk fetches v6, v7, ..., v50 sequentially. At ~2KB per version and a few HTTP requests per second, this completes in under a minute. No special handling needed -- the algorithm is the same regardless of gap size.

**Practical limit:** If a node is so stale that early version files have been deliberately pruned from the repo (a policy decision, not currently planned), the node falls back to its compiled genesis SYSTEM_ADMIN addresses and an operator must intervene. This is the same failure mode as today, just pushed much further into the future.

### Corrupted or Missing Version File

**Scenario:** `data/versions/23.json` returns a 404 or contains invalid JSON.

**Handling:** The chain-walk aborts immediately. The node stays on its last verified version and logs an error. It retries on the next poll cycle.

```
if doc is null or doc fails JSON parse:
    log.error("chain-walk failed: version {v} unavailable or corrupt")
    return cachedDoc  // stay on known-good version
```

This is fail-safe: a missing file can never cause the node to accept an unverified registry.

### GitHub Outage During Chain Walk

**Scenario:** Node successfully fetches v15-v18 but GitHub returns 503 for v19.

**Handling:** Same as above -- the walk aborts and the node stays on its cached version. It does NOT partially update to v18, because the goal is to reach the latest version. Partial walks would leave the node in a state where it has internally updated its trusted roles but hasn't reached the latest version, creating confusion on the next sync cycle.

**Alternative (more complex, not recommended now):** Allow partial walks where the node commits intermediate progress. This adds complexity (need to persist intermediate trusted-role state) for minimal benefit -- the next poll cycle will complete the walk once GitHub recovers.

### Registry Repo Storage Growth

**Scenario:** After years of operation, `data/versions/` contains hundreds of files.

**Analysis:** Each version file is ~1-3 KB. At 5 updates/month for 5 years = 300 files = ~600 KB. This is negligible for a git repo. GitHub repos commonly hold millions of files.

**If growth becomes a concern (unlikely):** Old version files could be archived to a separate branch or tag. The chain-walk only needs versions from the node's cached version forward -- ancient history is never fetched by active nodes. But don't implement this unless it's actually needed.

### Concurrent Governance Rotations

**Scenario:** SYSTEM_ADMIN addresses rotate in v15, then POLICY_COMPLIANCE is added in v16.

**Handling:** The chain-walk handles this correctly -- it verifies v15 against the v14 governance roles, updates trusted roles to v15's set, then verifies v16 against v15's governance roles (which now include both SYSTEM_ADMIN and any roles from v15). Multiple consecutive governance changes work because the walk processes versions in order.

### Node Starts from Genesis

**Scenario:** A brand-new node with no cache and only genesis SYSTEM_ADMIN addresses compiled in.

**Handling:** The node fetches `registry.json` (latest). If the latest version's governance roles differ from genesis, the node chain-walks from v1. Genesis version (v1) is verified against the compiled SYSTEM_ADMIN addresses, then trust transitions forward through the chain.

This requires `data/versions/1.json` to exist. Migration Phase 1 should ensure this.
