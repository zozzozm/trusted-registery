# AI Agent Guide — Consuming the MPC Custody Node Registry

This document is for AI agents (e.g., Claude) that implement an MPC custody platform and need to consume `registry.json` as the **source of truth** for authorized MPC custody nodes, governance policies, and ceremony parameters.

---

## 1. What is registry.json?

`registry.json` is a cryptographically signed JSON document that defines:

- **Which MPC nodes are authorized** to participate in key-generation and signing ceremonies
- **Who governs the registry** (multi-role governance with per-role quorum)
- **What cryptographic protocols and curves** are allowed for ceremonies
- **What policies** constrain operations (withdrawal limits, oracle requirements, whitelisting)
- **What infrastructure** is trusted (backoffice service, oracle, approved binaries)

The document is **versioned**, **hash-chained**, **Merkle-rooted**, and requires **multi-signature approval** from all governance roles before any change takes effect. It is the single source of truth — no node should participate in any MPC ceremony without first fetching and verifying this document.

---

## 2. Where to Fetch

### Primary URL

```
https://raw.githubusercontent.com/zozzozm/trusted-registery/refs/heads/main/data/registry.json
```

### Mirror URLs

Check `registry_metadata.endpoints.mirrors[]` in the document itself for fallback URLs.

### Version History

Individual versions are stored at:

```
https://raw.githubusercontent.com/zozzozm/trusted-registery/refs/heads/main/data/versions/{N}.json
```

---

## 3. Document Structure

```jsonc
{
  // ── SECTION 1: Registry Metadata ──────────────────────────────────────
  // Identifies the document, its version, integrity hashes, and fetch endpoints.
  "registry_metadata": {
    "registry_id":        "custody-wallet",           // unique registry identifier — reject if mismatched
    "version":            5,                           // monotonically increasing version number
    "issued_at":          1774208956,                  // unix timestamp (seconds) when this version was created
    "expires_at":         1774813756,                  // unix timestamp — REJECT if current time > expires_at
    "updated_at":         "2026-03-22T23:00:00.000Z",  // ISO 8601 timestamp of last modification
    "document_hash":      "a27c42863d52b3de...",       // SHA-256 of the entire document (with this field set to "")
    "merkle_root":        "a2eb39f61be8f810...",       // Merkle root over all nodes (integrity of node list)
    "prev_document_hash": "8f4a2b1c9e3d7f05...",       // hash of the previous version (null for genesis v1)
    "endpoints": {                                      // where to fetch registry updates (or null)
      "primary": "https://raw.githubusercontent.com/.../data/registry.json",
      "mirrors": ["https://mirror.example.com/registry.json"]
    }
  },

  // ── SECTION 2: Governance ─────────────────────────────────────────────
  // Defines who can authorize changes to the registry.
  // Each role has its own set of Ethereum addresses and quorum requirement.
  // ALL roles from the previous version must sign a new version.
  "governance": {
    "roles": [
      {
        "role": "SYSTEM_ADMIN",                        // mandatory role — always required
        "display_name": "System Administrators",
        "addresses": [                                  // Ethereum addresses (min 3 for SYSTEM_ADMIN)
          "0x3f1707FDAF87eE42F9D53fE0Af2Fd96995a80059",
          "0x9140c30772D963fe04f64D2c8d2454CF67A9Ab48",
          "0x7C9f957De53D154320b2D0Bb4547B094FE372e47"
        ],
        "quorum": 2,                                   // minimum signatures required (>= 2 for SYSTEM_ADMIN)
        "features": {}                                 // role-specific feature flags (key-value)
      },
      {
        "role": "POLICY_COMPLIANCE",                   // optional role
        "display_name": "Compliance & Policy Team",
        "addresses": ["0x5340CCBF4F7EFf08ccE505377f4c0876BEF6c7e6", "0x..."],
        "quorum": 1,
        "features": {
          "reshare_lock_period_hours": 24,
          "authorized_scopes": ["threshold_update", "node_rotation"]
        }
      }
    ]
  },

  // ── SECTION 3: Ceremony Config ────────────────────────────────────────
  // Constraints for MPC key-generation and signing ceremonies.
  // Your agent MUST enforce these before initiating any ceremony.
  "ceremony_config": {
    "global_threshold_t": 2,                           // minimum signers required in any ceremony (t-of-n)
    "max_participants_n": 9,                           // maximum participants allowed
    "allowed_protocols": ["CGGMP21", "FROST"],           // only these MPC protocols may be used
    "allowed_curves":    ["Secp256k1", "Ed25519"]       // only these elliptic curves may be used
  },

  // ── SECTION 4: Trusted Infrastructure ─────────────────────────────────
  // Addresses and hashes of trusted system components.
  "trusted_infrastructure": {
    "backoffice_pubkey": "0x5340CCBF...",     // Ethereum address of the backoffice service (or null)
    "market_oracle_pubkey":      "0x5340CCBF...",     // Ethereum address of the price oracle (or null)
    "trusted_binary_hashes": [                         // SHA-256 hashes of approved node binaries
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
    ]
  },

  // ── SECTION 5: Nodes ──────────────────────────────────────────────────
  // The list of authorized MPC custody nodes.
  // This is the CORE data your agent consumes.
  "nodes": [
    {
      "node_id":      "4733ba782088140f...",           // unique ID (SHA-256 derived from ik_pub + role + enrolled_at)
      "ik_pub":       "d75a980182b10ab7...",           // Ed25519/X25519 identity public key (64 hex chars)
      "ek_pub":       "e86b990182b10ab7...",           // ephemeral public key for key exchange (64 hex chars)
      "role":         "USER_COSIGNER",                 // USER_COSIGNER | PROVIDER_COSIGNER | RECOVERY_GUARDIAN
      "status":       "ACTIVE",                        // ACTIVE | REVOKED | MAINTENANCE
      "enrolled_at":  1774209959,                      // unix timestamp when node was enrolled
      "updated_at":   1774215000,                      // unix timestamp of last status change (optional)
      "revoked_at":   null                             // unix timestamp if revoked, null otherwise
    }
  ],

  // ── SECTION 6: Immutable Policies ─────────────────────────────────────
  // Hard constraints that govern the custody platform's behavior.
  "immutable_policies": {
    "max_withdrawal_usd_24h": 50000,                   // maximum USD withdrawal in 24-hour window
    "require_oracle_price":   true,                    // must fetch oracle price before any transaction
    "enforce_whitelist":      true                     // only send to whitelisted addresses
  },

  // ── SECTION 7: Signatures ─────────────────────────────────────────────
  // EIP-712 v2 typed data signatures from governance role members.
  // Each role must meet its quorum. Verified against PREVIOUS version's role addresses.
  "signatures": [
    {
      "role":      "SYSTEM_ADMIN",                     // which governance role this signature is for
      "signer":    "0x9140c30772D963fe...",             // Ethereum address of the signer
      "signature": "0x..."                             // EIP-712 typed data signature (0x + 130 hex chars)
    }
  ]
}
```

---

## 4. How Your Agent Should Use This Document

### 4.1 — Fetch and Cache

```
1. Fetch registry.json from the primary endpoint
2. If fetch fails, try each mirror URL
3. If all fail, use your cached copy (if not expired)
4. Cache the document locally for resilience
5. Re-fetch every 5-15 minutes or on application boot
```

### 4.2 — Verification Checklist (MANDATORY)

**Never trust the document without running ALL these checks:**

| # | Check | How | Reject if |
|---|-------|-----|-----------|
| 1 | **Registry ID** | `registry_metadata.registry_id === "custody-wallet"` | ID doesn't match your hardcoded expected value |
| 2 | **Expiry** | `Date.now()/1000 < registry_metadata.expires_at` | Document is expired |
| 3 | **Document hash** | Recompute SHA-256 of document (with `document_hash` set to `""`, keys sorted recursively). Compare to `registry_metadata.document_hash` | Hash mismatch = content tampered |
| 4 | **Merkle root** | Recompute binary Merkle tree over sorted nodes. Compare to `registry_metadata.merkle_root` | Root mismatch = node list tampered |
| 5 | **Signatures** | For each governance role, verify EIP-712 v2 signatures using `ethers.verifyTypedData()`. Each role must have `>= quorum` valid unique signatures from its `addresses[]` | Any role fails quorum |
| 6 | **Version** | `version > your_cached_version` | Rollback attempt (version went backwards) |
| 7 | **Hash chain** | `registry_metadata.prev_document_hash === previous_version.registry_metadata.document_hash` | Chain broken = fork attack |

### 4.3 — Extract Active Nodes

```typescript
// Only use ACTIVE nodes for MPC ceremonies
const activeNodes = doc.nodes.filter(n => n.status === 'ACTIVE')

// Get nodes by role
const userCosigners     = activeNodes.filter(n => n.role === 'USER_COSIGNER')
const providerCosigners = activeNodes.filter(n => n.role === 'PROVIDER_COSIGNER')
const recoveryGuardians = activeNodes.filter(n => n.role === 'RECOVERY_GUARDIAN')
```

### 4.4 — Enforce Ceremony Config

Before initiating ANY MPC ceremony:

```typescript
// 1. Check you have enough active nodes
const activeCount = activeNodes.length
if (activeCount < doc.ceremony_config.global_threshold_t) {
  throw new Error(`Need ${doc.ceremony_config.global_threshold_t} nodes, have ${activeCount}`)
}

// 2. Check protocol is allowed
if (!doc.ceremony_config.allowed_protocols.includes(selectedProtocol)) {
  throw new Error(`Protocol ${selectedProtocol} not allowed`)
}

// 3. Check curve is allowed
if (!doc.ceremony_config.allowed_curves.includes(selectedCurve)) {
  throw new Error(`Curve ${selectedCurve} not allowed`)
}

// 4. Check participant count doesn't exceed max
if (participantCount > doc.ceremony_config.max_participants_n) {
  throw new Error(`Too many participants: ${participantCount} > ${doc.ceremony_config.max_participants_n}`)
}
```

### 4.5 — Enforce Immutable Policies

```typescript
// Before any withdrawal/transaction:
if (withdrawalUsd > doc.immutable_policies.max_withdrawal_usd_24h) {
  throw new Error(`Withdrawal $${withdrawalUsd} exceeds 24h limit $${doc.immutable_policies.max_withdrawal_usd_24h}`)
}

if (doc.immutable_policies.require_oracle_price) {
  const price = await fetchOraclePrice(doc.trusted_infrastructure.market_oracle_pubkey)
  // ... use oracle price for conversion
}

if (doc.immutable_policies.enforce_whitelist && !isWhitelisted(destinationAddress)) {
  throw new Error('Destination not in whitelist')
}
```

### 4.6 — Verify Trusted Infrastructure

```typescript
// Before connecting to backoffice service:
if (doc.trusted_infrastructure.backoffice_pubkey) {
  // Verify the backoffice service identity matches this address
}

// Before accepting a binary update:
if (doc.trusted_infrastructure.trusted_binary_hashes.length > 0) {
  const binaryHash = sha256(binaryBuffer)
  if (!doc.trusted_infrastructure.trusted_binary_hashes.includes(binaryHash)) {
    throw new Error('Binary hash not in trusted list — refusing to run')
  }
}
```

---

## 5. Node Roles Explained

| Role | Purpose | Used for |
|------|---------|----------|
| `USER_COSIGNER` | The end-user's key-share holder (mobile/device) | User-initiated signing ceremonies |
| `PROVIDER_COSIGNER` | The cloud service's key-share holder | Every ceremony (always participates) |
| `RECOVERY_GUARDIAN` | Backup signer for account recovery | Recovery flows when user key is lost |

### Node Status Values

| Status | Meaning | Can participate in ceremonies? |
|--------|---------|-------------------------------|
| `ACTIVE` | Node is enrolled and operational | **Yes** |
| `MAINTENANCE` | Temporarily offline (upgrade, rotation) | **No** — wait for reactivation |
| `REVOKED` | Permanently removed | **No** — never use again |

### Identity Key Rotations

A node's `ik_pub` may change over time. The `ik_rotations[]` array contains the history:

```jsonc
{
  "ik_rotations": [
    {
      "prev_ik_pub": "old_key_hex...",
      "new_ik_pub":  "new_key_hex...",
      "rotated_at":  1774300000,
      "reason":      "scheduled",        // "scheduled" | "compromise" | "upgrade"
      "proof":       "Ed25519_sig_hex"    // Ed25519 signature by old key (null if compromise)
    }
  ]
}
```

**Important:** Always use the current `ik_pub` field, not historical values. The rotation history is for audit purposes.

---

## 6. Governance Model

### Roles

| Role | Required | Min Addresses | Min Quorum | Purpose |
|------|----------|---------------|------------|---------|
| `SYSTEM_ADMIN` | **Yes** | 3 | 2 | Full administrative control — node enrollment, revocation, all config changes |
| `POLICY_COMPLIANCE` | No | 1 | 1 | Compliance oversight — policy changes, audit |
| `TREASURY_OPS` | No | 1 | 1 | Treasury operations — withdrawal limits, oracle config |
| `AUDIT_OBSERVER` | No | 1 | 1 | Read-only audit observation |

### Chain-of-Trust Rule

When a new version is published:
1. **ALL roles from the previous version** must sign the new version with their respective quorum
2. Signatures are verified against the **previous version's** role addresses (not the new version's)
3. This prevents unauthorized role injection — you can't add yourself as a new admin and self-sign

### What This Means for Your Agent

- If `governance.roles` changes between versions, the new addresses were authorized by the old governance
- You can trust the current governance roles because they are cryptographically chained back to the genesis trust root
- The genesis trust root is the `SYSTEM_ADMIN` addresses that are hardcoded/configured out-of-band

---

## 7. Version Chain and Gap Recovery

Each version's `prev_document_hash` links to the previous version's `document_hash`, forming an immutable chain:

```
v1 (genesis) → v2 → v3 → v4 → ... → vN (current)
```

### If Your Agent Misses Versions

If you cached v3 but the current is v7, and the governance roles changed in between:

1. Fetch `versions/4.json`, `versions/5.json`, `versions/6.json`, `versions/7.json`
2. For each version, verify:
   - Hash chain linkage (`prev_document_hash` matches previous version)
   - Signatures against the **previous** version's governance roles
3. Walk forward, updating your trusted governance roles at each step
4. After reaching v7, you have verified the full chain of trust

```
Your cache (v3, trusts roles A)
  → verify v4 signed by roles A → adopt v4's roles B
    → verify v5 signed by roles B → adopt v5's roles B
      → verify v6 signed by roles B → adopt v6's roles C
        → verify v7 signed by roles C → DONE, trust v7
```

---

## 8. Cryptographic Details

### Document Hash

SHA-256 of deterministic JSON serialization:
- All object keys sorted recursively (alphabetically)
- `registry_metadata.document_hash` set to empty string `""` before hashing
- `signatures` array excluded from the hash input

### Merkle Root

Binary Merkle tree over sorted nodes:
- Nodes sorted by `node_id` (lexicographic)
- Leaf: `SHA256("leaf:" + SHA256(canonical_json(node_record)))`
- Internal: `SHA256("node:" + left_hash + ":" + right_hash)`
- Empty tree: `SHA256("empty")`

### EIP-712 Signature Verification

- **Domain**: `{ name: 'MPC Node Registry', version: '2' }`
- **Primary type**: `RegistryDocument`
- **Verification**: `ethers.verifyTypedData(domain, types, value, signature)`
- Each signature's recovered address must match the declared `signer` field
- The `signer` must be in the corresponding role's `addresses[]` from the reference version

---

## 9. Quick Reference — Fields Your Agent Needs Most

| What you need | Where to find it |
|---------------|-----------------|
| Registry version | `registry_metadata.version` |
| Is document expired? | `Date.now()/1000 > registry_metadata.expires_at` |
| Active nodes | `nodes.filter(n => n.status === 'ACTIVE')` |
| Node identity key | `node.ik_pub` (64 hex chars) |
| Node ephemeral key | `node.ek_pub` (64 hex chars) |
| Node role | `node.role` (USER_COSIGNER, PROVIDER_COSIGNER, RECOVERY_GUARDIAN) |
| MPC threshold | `ceremony_config.global_threshold_t` |
| Max participants | `ceremony_config.max_participants_n` |
| Allowed protocols | `ceremony_config.allowed_protocols` |
| Allowed curves | `ceremony_config.allowed_curves` |
| Withdrawal limit | `immutable_policies.max_withdrawal_usd_24h` |
| Oracle required? | `immutable_policies.require_oracle_price` |
| Whitelist enforced? | `immutable_policies.enforce_whitelist` |
| Oracle address | `trusted_infrastructure.market_oracle_pubkey` |
| Backoffice address | `trusted_infrastructure.backoffice_pubkey` |
| Approved binaries | `trusted_infrastructure.trusted_binary_hashes` |
| Governance roles | `governance.roles` |
| Fetch URL | `registry_metadata.endpoints.primary` |
| Previous version hash | `registry_metadata.prev_document_hash` |

---

## 10. Error Handling

| Scenario | What to do |
|----------|-----------|
| Fetch fails (all URLs) | Use cached document if not expired. Retry on next poll cycle. |
| Document expired | **Stop all ceremonies.** Alert operators. Do not use expired registry. |
| Hash mismatch | **Reject document.** Content has been tampered. Use cached version. |
| Signature verification fails | **Reject document.** Possible forgery or unauthorized change. |
| Version rollback (new < cached) | **Reject document.** Possible replay attack. |
| Node with `REVOKED` status | **Never use.** Remove from all ceremony candidate lists. |
| Node with `MAINTENANCE` status | **Skip temporarily.** May come back as ACTIVE in next version. |
| Unknown `role` in governance | Ignore — your agent only needs to verify signatures, not interpret roles. |
| Missing `endpoints` | Use your hardcoded primary URL as fallback. |

---

## 11. TypeScript Types

Copy these into your agent's codebase:

```typescript
type NodeRole   = 'USER_COSIGNER' | 'PROVIDER_COSIGNER' | 'RECOVERY_GUARDIAN'
type NodeStatus = 'ACTIVE' | 'REVOKED' | 'MAINTENANCE'

interface NodeRecord {
  node_id:       string
  ik_pub:        string     // 64 hex chars — Ed25519/X25519 identity public key
  ek_pub:        string     // 64 hex chars — ephemeral public key
  role:          NodeRole
  status:        NodeStatus
  enrolled_at:   number     // unix timestamp
  updated_at?:   number
  revoked_at?:   number | null
  ik_rotations?: IkRotationEntry[]
}

interface IkRotationEntry {
  prev_ik_pub: string
  new_ik_pub:  string
  rotated_at:  number
  reason:      string
  proof:       string
}

interface GovernanceRole {
  role:         string
  display_name: string
  addresses:    string[]
  quorum:       number
  features:     Record<string, any>
}

interface RegistryEndpoints {
  primary: string
  mirrors: string[]
}

interface RegistryMetadata {
  registry_id:        string
  version:            number
  issued_at:          number
  expires_at:         number
  updated_at:         string
  document_hash:      string
  merkle_root:        string
  prev_document_hash: string | null
  endpoints:          RegistryEndpoints | null
}

interface CeremonyConfig {
  global_threshold_t: number
  max_participants_n: number
  allowed_protocols:  string[]
  allowed_curves:     string[]
}

interface TrustedInfrastructure {
  backoffice_pubkey: string | null
  market_oracle_pubkey:      string | null
  trusted_binary_hashes:      string[]
}

interface ImmutablePolicies {
  max_withdrawal_usd_24h: number
  require_oracle_price:   boolean
  enforce_whitelist:       boolean
}

interface RoleSignature {
  role:      string
  signer:    string
  signature: string
}

interface RegistryDocument {
  registry_metadata:      RegistryMetadata
  governance:             { roles: GovernanceRole[] }
  ceremony_config:        CeremonyConfig
  trusted_infrastructure: TrustedInfrastructure
  nodes:                  NodeRecord[]
  immutable_policies:     ImmutablePolicies
  signatures:             RoleSignature[]
}
```

---

## 12. Summary for AI Agent Implementation

```
BEFORE any MPC ceremony:
  1. Fetch registry.json (primary → mirrors → cache)
  2. Verify: registry_id, expiry, document_hash, merkle_root, signatures, version chain
  3. Extract ACTIVE nodes by role
  4. Enforce ceremony_config (threshold, protocol, curve, max participants)
  5. Enforce immutable_policies (withdrawal limit, oracle, whitelist)
  6. Use node ik_pub/ek_pub for key exchange and ceremony participation
  7. Verify trusted_infrastructure.trusted_binary_hashes if applicable

NEVER:
  - Use a node with status REVOKED or MAINTENANCE
  - Use an expired document
  - Accept a document that fails any verification step
  - Skip signature verification
  - Use protocols or curves not in ceremony_config
  - Exceed max_withdrawal_usd_24h
  - Skip oracle price check if require_oracle_price is true
  - Send to non-whitelisted addresses if enforce_whitelist is true
```
