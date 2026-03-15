# MPC Wallet — Trusted Registry Integration Guide

This document describes how an MPC wallet cloud console application can consume the **Trusted Node Registry** published at GitHub as its source of truth for authorized MPC custody nodes.

---

## 1. Overview

The MPC wallet needs to know **which nodes are legitimate** before participating in key-generation or signing ceremonies. Instead of hardcoding node lists, the wallet fetches a cryptographically signed `registry.json` from the trusted registry's GitHub repository and verifies it locally.

```
┌──────────────┐       HTTPS / raw.githubusercontent.com       ┌─────────────────────┐
│  MPC Wallet  │ ───────────────────────────────────────────── │  GitHub Repository  │
│  Cloud App   │   GET /data/registry.json                     │  (trusted-registry) │
└──────┬───────┘                                               └─────────────────────┘
       │
       │  1. Fetch registry.json (primary URL or mirrors)
       │  2. Verify document integrity (hash, merkle, chain, signatures)
       │  3. Check ceremony_bounds and endpoints
       │  4. Extract active nodes by role
       │  5. Use node keys (ik_pub, ek_pub) in MPC ceremonies
       │
```

---

## 2. Registry Document Structure

The `registry.json` file contains a single `RegistryDocument`:

```jsonc
{
  "registry_id":       "dev-custody-v1",        // unique registry identifier
  "version":           3,                        // monotonically increasing
  "issued_at":         1710000000,               // unix timestamp (seconds)
  "expires_at":        1712592000,               // unix timestamp (seconds)
  "admin_addresses":   ["0xAbc...", "0xDef...", "0x123..."],  // Ethereum addresses of admins
  "backoffice_service_pubkey": "64-hex-chars...", // backoffice service public key (or null)
  "ceremony_bounds": {                           // MPC ceremony constraints (signed by admins)
    "min_signing_threshold": 2,                  // minimum signers required (>= 2)
    "allowed_protocols":     ["cggmp21", "frost"],   // MPC protocols allowed
    "allowed_curves":        ["secp256k1", "ed25519"] // elliptic curves allowed
  },
  "endpoints": {                                 // where clients can fetch registry updates (or null)
    "primary":    "https://raw.githubusercontent.com/zozzozm/trusted-registery/main/data/registry.json",
    "mirrors":    ["https://mirror-1.custody.internal/registry.json"],
    "updated_at": "2026-03-12T10:30:00.000Z"
  },
  "nodes": [
    {
      "node_id":      "sha256-derived-id",
      "ik_pub":       "64-hex-char-identity-key",   // Ed25519 / X25519 identity public key
      "ek_pub":       "64-hex-char-ephemeral-key",  // ephemeral public key
      "role":         "USER_COSIGNER",               // USER_COSIGNER | PROVIDER_COSIGNER | RECOVERY_GUARDIAN
      "status":       "ACTIVE",                      // ACTIVE | REVOKED
      "enrolled_at":  1710000000
    }
  ],
  "merkle_root":       "sha256-hex...",
  "prev_document_hash": "sha256-hex... | null",   // null for genesis (v1)
  "document_hash":     "sha256-hex...",
  "signatures": [
    {
      "admin_address": "0xAbc...",
      "signature":     "0x...130-hex-chars..."    // EIP-712 typed data signature
    }
  ]
}
```

### Node Roles

| Role | Description |
|------|-------------|
| `USER_COSIGNER` | The user's device/key-share holder |
| `PROVIDER_COSIGNER` | The cloud service's key-share holder |
| `RECOVERY_GUARDIAN` | Backup signer used for recovery flows |

### Endpoints

The `endpoints` object tells clients where to fetch the registry:
- `primary` — the main URL (e.g., GitHub raw URL)
- `mirrors` — fallback URLs for redundancy
- `updated_at` — ISO timestamp of when endpoints were last configured
- The entire `endpoints` object is signed by the admins, so it cannot be tampered with

### Ceremony Bounds

The `ceremony_bounds` object controls which cryptographic parameters are allowed for MPC ceremonies:
- `min_signing_threshold` — minimum number of signers required (>= 2)
- `allowed_protocols` — list of allowed MPC protocols (e.g. `["cggmp21", "frost"]`)
- `allowed_curves` — list of allowed elliptic curves (e.g. `["secp256k1", "ed25519"]`)
- The entire `ceremony_bounds` object is covered by the document hash and admin signatures, so changes require multi-sig approval
- Can be updated via `POST /registry/mpc-policy/propose`

### Backoffice Service Public Key

The `backoffice_service_pubkey` is a 32-byte hex public key for the backoffice service. It is included in the signed document hash, so any change requires admin multi-sig approval.

---

## 3. Fetching the Registry

### Using Endpoints from the Document

If you already have a cached registry, use its `endpoints` field:

```typescript
async function fetchRegistry(cachedDoc?: RegistryDocument): Promise<RegistryDocument> {
  const urls: string[] = [];

  if (cachedDoc?.endpoints) {
    urls.push(cachedDoc.endpoints.primary);
    urls.push(...(cachedDoc.endpoints.mirrors || []));
  } else {
    // Bootstrap URL — hardcoded for first fetch
    urls.push('https://raw.githubusercontent.com/zozzozm/trusted-registery/main/data/registry.json');
  }

  for (const url of urls) {
    try {
      const res = await fetch(url);
      if (res.ok) return res.json();
    } catch {
      continue; // try next mirror
    }
  }

  throw new Error('Failed to fetch registry from all endpoints');
}
```

### Caching Strategy

- **Poll interval**: Fetch every 5–15 minutes, or on wallet boot.
- **Cache locally**: Store the last valid document on disk as a fallback.
- **Version check**: Only process if `version` > your cached version.
- **Expiry**: Reject documents where `Date.now()/1000 > expires_at`.
- **Endpoint discovery**: After successful verification, update your fetch URLs from the document's `endpoints` field.

---

## 4. Verification (REQUIRED)

**Never trust the registry without verification.** The wallet must run these checks before using any node data.

### 4.1 — Required Admin Public Keys (Trust Root)

Hardcode or securely configure the admin Ethereum addresses in your wallet app. These are the **only** trust anchors:

```typescript
// These are the admin addresses that are authorized to sign registry updates.
// Obtain these out-of-band from the registry operators.
const TRUSTED_ADMIN_ADDRESSES = [
  '0xAbc...', // Admin 0
  '0xDef...', // Admin 1
  '0x123...', // Admin 2
];

const MIN_SIGNATURES = 2; // 2-of-3 multi-sig
```

### 4.2 — Verification Steps

```typescript
import { createHash } from 'crypto';
import { ethers } from 'ethers';

// ── Step 1: Structure check ──────────────────────────────────────────────────
function checkStructure(doc: any): void {
  const required = [
    'registry_id', 'version', 'issued_at', 'expires_at',
    'admin_addresses', 'nodes', 'merkle_root',
    'prev_document_hash', 'document_hash', 'signatures',
    'ceremony_bounds',
  ];
  const missing = required.filter(f => doc[f] === undefined);
  if (missing.length) throw new Error(`Missing fields: ${missing.join(', ')}`);
}

// ── Step 2: Expiry check ─────────────────────────────────────────────────────
function checkExpiry(doc: RegistryDocument): void {
  const now = Math.floor(Date.now() / 1000);
  if (now > doc.expires_at) {
    throw new Error(`Registry expired at ${new Date(doc.expires_at * 1000).toISOString()}`);
  }
}

// ── Step 3: Document hash integrity ──────────────────────────────────────────
function deterministicHash(obj: object): string {
  const canonical = JSON.stringify(obj, (_k, v) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      return Object.fromEntries(
        Object.entries(v).sort(([a], [b]) => a.localeCompare(b)),
      );
    }
    return v;
  });
  return createHash('sha256').update(canonical).digest('hex');
}

function checkDocumentHash(doc: RegistryDocument): void {
  const unsigned = {
    registry_id:            doc.registry_id,
    version:                doc.version,
    issued_at:              doc.issued_at,
    expires_at:             doc.expires_at,
    admin_addresses:        doc.admin_addresses,
    backoffice_service_pubkey: doc.backoffice_service_pubkey,
    ceremony_bounds:        doc.ceremony_bounds,
    endpoints:              doc.endpoints,
    nodes:                  doc.nodes,
    merkle_root:            doc.merkle_root,
    prev_document_hash:     doc.prev_document_hash,
    document_hash:          '',  // set to empty string before hashing
  };
  const expected = deterministicHash(unsigned);
  if (expected !== doc.document_hash) {
    throw new Error('Document hash mismatch — content has been tampered with');
  }
}

// ── Step 4: Merkle root verification ─────────────────────────────────────────
function hashString(s: string): string {
  return createHash('sha256').update(s).digest('hex');
}

function buildMerkleTree(leaves: string[]): string[] {
  if (leaves.length === 1) return leaves;
  const next: string[] = [];
  for (let i = 0; i < leaves.length; i += 2) {
    const right = i + 1 < leaves.length ? leaves[i + 1] : leaves[i];
    next.push(hashString('node:' + leaves[i] + ':' + right));
  }
  return buildMerkleTree(next);
}

function checkMerkleRoot(doc: RegistryDocument): void {
  const sorted = [...doc.nodes].sort((a, b) => a.node_id.localeCompare(b.node_id));
  let expected: string;
  if (sorted.length === 0) {
    expected = hashString('empty');
  } else {
    const leaves = sorted.map(n => hashString('leaf:' + deterministicHash(n)));
    expected = buildMerkleTree(leaves)[0];
  }
  if (expected !== doc.merkle_root) {
    throw new Error('Merkle root mismatch — node list has been tampered with');
  }
}

// ── Step 5: EIP-712 multi-signature verification ─────────────────────────────
const EIP712_DOMAIN = { name: 'MPC Node Registry', version: '1' };

const EIP712_TYPES = {
  NodeRecord: [
    { name: 'node_id',      type: 'string' },
    { name: 'ik_pub',       type: 'string' },
    { name: 'ek_pub',       type: 'string' },
    { name: 'role',         type: 'string' },
    { name: 'status',       type: 'string' },
    { name: 'enrolled_at',  type: 'uint256' },
    { name: 'revoked_at',   type: 'uint256' },
  ],
  Endpoints: [
    { name: 'primary',    type: 'string' },
    { name: 'mirrors',    type: 'string[]' },
    { name: 'updated_at', type: 'string' },
  ],
  CeremonyBounds: [
    { name: 'min_signing_threshold', type: 'uint256' },
    { name: 'allowed_protocols',     type: 'string[]' },
    { name: 'allowed_curves',        type: 'string[]' },
  ],
  RegistryDocument: [
    { name: 'registry_id',            type: 'string' },
    { name: 'version',                type: 'uint256' },
    { name: 'issued_at',             type: 'uint256' },
    { name: 'expires_at',            type: 'uint256' },
    { name: 'admin_addresses',       type: 'address[]' },
    { name: 'backoffice_service_pubkey', type: 'string' },
    { name: 'ceremony_bounds',       type: 'CeremonyBounds' },
    { name: 'endpoints',             type: 'Endpoints' },
    { name: 'nodes',                 type: 'NodeRecord[]' },
    { name: 'merkle_root',           type: 'string' },
    { name: 'prev_document_hash',    type: 'string' },
    { name: 'document_hash',         type: 'string' },
  ],
};

function checkSignatures(doc: RegistryDocument): void {
  if (!doc.signatures || doc.signatures.length < MIN_SIGNATURES) {
    throw new Error(`Need >= ${MIN_SIGNATURES} signatures, got ${doc.signatures?.length ?? 0}`);
  }

  // Build typed data value (normalize for EIP-712)
  const value = {
    registry_id:            doc.registry_id,
    version:                doc.version,
    issued_at:              doc.issued_at,
    expires_at:             doc.expires_at,
    admin_addresses:        doc.admin_addresses,
    backoffice_service_pubkey: doc.backoffice_service_pubkey ?? '',
    ceremony_bounds: {
      min_signing_threshold: doc.ceremony_bounds.min_signing_threshold,
      allowed_protocols:     doc.ceremony_bounds.allowed_protocols,
      allowed_curves:        doc.ceremony_bounds.allowed_curves,
    },
    endpoints:              doc.endpoints
      ? { primary: doc.endpoints.primary, mirrors: doc.endpoints.mirrors, updated_at: doc.endpoints.updated_at }
      : { primary: '', mirrors: [], updated_at: '' },
    nodes:                  doc.nodes.map(n => ({
      node_id:      n.node_id,
      ik_pub:       n.ik_pub,
      ek_pub:       n.ek_pub,
      role:         n.role,
      status:       n.status,
      enrolled_at:  n.enrolled_at,
      revoked_at:   n.revoked_at ?? 0,
    })),
    merkle_root:       doc.merkle_root,
    prev_document_hash: doc.prev_document_hash ?? '',
    document_hash:     doc.document_hash,
  };

  const trustedSet = new Set(TRUSTED_ADMIN_ADDRESSES.map(a => a.toLowerCase()));
  const seen = new Set<string>();
  let validCount = 0;

  for (const sig of doc.signatures) {
    const addr = sig.admin_address.toLowerCase();

    if (seen.has(addr)) throw new Error(`Duplicate signature from ${sig.admin_address}`);
    seen.add(addr);

    if (!trustedSet.has(addr)) throw new Error(`Unknown admin: ${sig.admin_address}`);

    // Recover signer via EIP-712
    const recovered = ethers.verifyTypedData(EIP712_DOMAIN, EIP712_TYPES, value, sig.signature);
    if (recovered.toLowerCase() !== addr) {
      throw new Error(`Signature verification failed for ${sig.admin_address}`);
    }
    validCount++;
  }

  if (validCount < MIN_SIGNATURES) {
    throw new Error(`Only ${validCount} valid signatures, need ${MIN_SIGNATURES}`);
  }
}

// ── Step 6: Ceremony Bounds check ────────────────────────────────────────────
function checkCeremonyBounds(doc: RegistryDocument): void {
  const cb = doc.ceremony_bounds;
  if (!cb) throw new Error('ceremony_bounds is required');
  if (!Number.isInteger(cb.min_signing_threshold) || cb.min_signing_threshold < 2) {
    throw new Error('min_signing_threshold must be >= 2');
  }
  if (!Array.isArray(cb.allowed_curves) || cb.allowed_curves.length === 0) {
    throw new Error('allowed_curves must be a non-empty array');
  }
  if (!Array.isArray(cb.allowed_protocols) || cb.allowed_protocols.length === 0) {
    throw new Error('allowed_protocols must be a non-empty array');
  }
}

// ── Step 7: Endpoints check ──────────────────────────────────────────────────
function checkEndpoints(doc: RegistryDocument): void {
  if (!doc.endpoints) return; // endpoints are optional

  const urlPattern = /^https?:\/\/.+/;
  if (!urlPattern.test(doc.endpoints.primary)) {
    throw new Error(`Invalid primary endpoint URL: ${doc.endpoints.primary}`);
  }
  for (const mirror of doc.endpoints.mirrors) {
    if (!urlPattern.test(mirror)) {
      throw new Error(`Invalid mirror URL: ${mirror}`);
    }
  }
  const allUrls = [doc.endpoints.primary, ...doc.endpoints.mirrors];
  if (new Set(allUrls).size !== allUrls.length) {
    throw new Error('Duplicate URLs in endpoints');
  }
}
```

### 4.3 — Full Verification Function

```typescript
function verifyRegistry(doc: RegistryDocument): void {
  checkStructure(doc);
  checkExpiry(doc);
  checkDocumentHash(doc);
  checkMerkleRoot(doc);
  checkSignatures(doc);
  checkCeremonyBounds(doc);
  checkEndpoints(doc);
  // All checks passed — document is authentic and untampered
}
```

---

## 5. Using the Registry in the MPC Wallet

### 5.1 — Get Active Nodes

```typescript
function getActiveNodes(doc: RegistryDocument): NodeRecord[] {
  return doc.nodes.filter(n => n.status === 'ACTIVE');
}
```

### 5.2 — Get Nodes by Role

```typescript
function getNodesByRole(
  doc: RegistryDocument,
  role: 'USER_COSIGNER' | 'PROVIDER_COSIGNER' | 'RECOVERY_GUARDIAN',
): NodeRecord[] {
  return doc.nodes.filter(
    n => n.status === 'ACTIVE' && n.role === role,
  );
}
```

### 5.3 — Check Threshold Before Ceremony

```typescript
function canStartCeremony(doc: RegistryDocument): boolean {
  const activeNodes = getActiveNodes(doc);
  return activeNodes.length >= doc.ceremony_bounds.min_signing_threshold;
}
```

### 5.4 — MPC Ceremony Integration

```typescript
async function startSigningCeremony(txPayload: any) {
  // 1. Fetch and verify registry
  const registry = await fetchRegistry();
  verifyRegistry(registry);

  // 2. Check threshold
  if (!canStartCeremony(registry)) {
    throw new Error(`Not enough active nodes (need ${registry.ceremony_bounds.min_signing_threshold})`);
  }

  // 3. Resolve the signing quorum
  const userNode     = getNodesByRole(registry, 'USER_COSIGNER')[0];
  const providerNode = getNodesByRole(registry, 'PROVIDER_COSIGNER')[0];

  if (!userNode || !providerNode) {
    throw new Error('Missing required cosigners for this wallet');
  }

  // 4. Use ik_pub / ek_pub to establish encrypted channels and run MPC
  const participants = [
    { node_id: userNode.node_id,     ik_pub: userNode.ik_pub,     ek_pub: userNode.ek_pub },
    { node_id: providerNode.node_id, ik_pub: providerNode.ik_pub, ek_pub: providerNode.ek_pub },
  ];

  // ... initiate MPC signing protocol with these participants
}
```

### 5.5 — Using the Backoffice Service Public Key

```typescript
function getBackofficePubkey(doc: RegistryDocument): string | null {
  return doc.backoffice_service_pubkey;
}

// Use for establishing authenticated communication with the backoffice service
async function connectToBackoffice(doc: RegistryDocument) {
  const pubkey = getBackofficePubkey(doc);
  if (!pubkey) throw new Error('No backoffice service public key configured');

  // Use pubkey for key exchange or signature verification with backoffice
  // ...
}
```

---

## 6. High-Water Mark (Rollback Protection)

To prevent an attacker from serving a stale (older) registry version, the wallet should track the highest version it has seen:

```typescript
interface HighWaterMark {
  registry_id:  string;
  max_version:  number;
  last_doc_hash: string;
  updated_at:   number;
}

function checkRollback(doc: RegistryDocument, hwm: HighWaterMark | null): void {
  if (!hwm) return; // first fetch, nothing to compare

  if (doc.registry_id !== hwm.registry_id) {
    throw new Error('Registry ID changed — possible substitution attack');
  }
  if (doc.version < hwm.max_version) {
    throw new Error(`Rollback detected: got v${doc.version}, expected >= v${hwm.max_version}`);
  }
}

function updateHighWaterMark(doc: RegistryDocument): HighWaterMark {
  return {
    registry_id:  doc.registry_id,
    max_version:  doc.version,
    last_doc_hash: doc.document_hash,
    updated_at:   Math.floor(Date.now() / 1000),
  };
}
```

---

## 7. Hash Chain Verification (Optional, Recommended)

If your wallet caches previous documents, verify the hash chain links:

```typescript
function checkHashChain(
  newDoc: RegistryDocument,
  previousDoc: RegistryDocument | null,
): void {
  if (!previousDoc) {
    // Genesis document — prev_document_hash must be null
    if (newDoc.prev_document_hash !== null) {
      throw new Error('Genesis document must have null prev_document_hash');
    }
    return;
  }

  if (newDoc.prev_document_hash !== previousDoc.document_hash) {
    throw new Error('Hash chain broken — prev_document_hash does not match previous document');
  }

  if (newDoc.version !== previousDoc.version + 1) {
    throw new Error(`Version gap: expected ${previousDoc.version + 1}, got ${newDoc.version}`);
  }
}
```

---

## 8. Security Considerations

| Concern | Mitigation |
|---------|-----------|
| **GitHub compromise** | Registry is cryptographically signed. Even if GitHub is compromised, forged documents will fail signature verification. |
| **Admin key compromise** | 2-of-3 multi-sig means a single compromised key cannot produce a valid document. |
| **Rollback attack** | High-water mark tracking prevents serving old documents. |
| **Expired registry** | Always check `expires_at`. Refuse to use expired documents. |
| **Man-in-the-middle** | HTTPS + EIP-712 signature verification. Endpoints are signed in the document. |
| **Node key rotation** | When a node is revoked, its `status` changes to `REVOKED`. Always filter for `ACTIVE` nodes. |
| **Endpoint tampering** | Endpoint URLs are covered by the document hash and admin signatures. Changing them requires multi-sig approval. |
| **Insufficient quorum** | `ceremony_bounds.min_signing_threshold` validation ensures you have enough active nodes before starting MPC ceremonies. |

### Trust Root Summary

The wallet trusts **only** the hardcoded admin Ethereum addresses. Everything else is verified:

```
Admin Addresses (hardcoded)
  └── verify EIP-712 signatures on registry document
        └── document_hash (SHA-256 integrity of all fields)
              ├── merkle_root (integrity of individual nodes)
              ├── prev_document_hash (chain to previous version)
              ├── backoffice_service_pubkey (backoffice authentication)
              ├── ceremony_bounds (min threshold, protocols, curves)
              └── endpoints (primary + mirrors, signed discovery)
```

---

## 9. Dependencies

The wallet app needs these packages for verification:

```json
{
  "ethers": "^6.x"     // EIP-712 signature recovery
}
```

Node.js `crypto` module is used for SHA-256 hashing (built-in, no extra dependency).

---

## 10. TypeScript Types

Copy these types into your wallet project:

```typescript
type NodeRole   = 'USER_COSIGNER' | 'PROVIDER_COSIGNER' | 'RECOVERY_GUARDIAN';
type NodeStatus = 'ACTIVE' | 'REVOKED';

interface NodeRecord {
  node_id:      string;
  ik_pub:       string;
  ek_pub:       string;
  role:         NodeRole;
  status:       NodeStatus;
  enrolled_at:  number;
  revoked_at?:  number;
}

interface AdminSignature {
  admin_address: string;
  signature:     string;
}

interface RegistryEndpoints {
  primary:    string;
  mirrors:    string[];
  updated_at: string;
}

interface CeremonyBounds {
  min_signing_threshold: number;
  allowed_protocols:     string[];
  allowed_curves:        string[];
}

interface RegistryDocument {
  registry_id:            string;
  version:                number;
  issued_at:              number;
  expires_at:             number;
  admin_addresses:        string[];
  backoffice_service_pubkey: string | null;
  ceremony_bounds:        CeremonyBounds;
  endpoints:              RegistryEndpoints | null;
  nodes:                  NodeRecord[];
  merkle_root:            string;
  prev_document_hash:     string | null;
  document_hash:          string;
  signatures:             AdminSignature[];
}

interface HighWaterMark {
  registry_id:   string;
  max_version:   number;
  last_doc_hash: string;
  updated_at:    number;
}
```

---

## 11. API Endpoints Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/registry/current` | Get current published document |
| `GET` | `/api/registry/health` | Health check with admin info |
| `GET` | `/api/registry/nodes` | List nodes (filter: `?role=y`) |
| `GET` | `/api/registry/nodes/:node_id` | Get specific node |
| `POST` | `/api/registry/pending` | Create new draft |
| `GET` | `/api/registry/pending` | Get pending draft |
| `DELETE` | `/api/registry/pending` | Delete pending draft |
| `GET` | `/api/registry/pending/message` | Get EIP-712 payload for signing |
| `POST` | `/api/registry/pending/sign` | Submit admin signature |
| `POST` | `/api/registry/nodes/enroll` | Propose node enrollment |
| `POST` | `/api/registry/nodes/revoke` | Propose node revocation |
| `POST` | `/api/registry/admins/propose` | Propose admin rotation |
| `POST` | `/api/registry/backoffice-pubkey/propose` | Propose backoffice public key |
| `POST` | `/api/registry/mpc-policy/propose` | Propose ceremony bounds (min threshold, protocols, curves) |
| `POST` | `/api/registry/endpoints/propose` | Propose endpoint URLs |
| `POST` | `/api/registry/verify` | Verify a document (10-step pipeline) |
| `POST` | `/api/registry/publish` | Publish signed document |
| `GET` | `/api/registry/audit` | Get audit log |
