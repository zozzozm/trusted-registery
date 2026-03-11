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
       │  1. Fetch registry.json
       │  2. Verify document integrity (hash, merkle, chain, signatures)
       │  3. Extract active nodes for wallet scope
       │  4. Use node keys (ikPub, ekPub) in MPC ceremonies
       │
```

---

## 2. Registry Document Structure

The `registry.json` file contains a single `RegistryDocument`:

```jsonc
{
  "registryId":       "dev-custody-v1",        // unique registry identifier
  "version":          3,                        // monotonically increasing
  "issuedAt":         1710000000,               // unix timestamp (seconds)
  "expiresAt":        1712592000,               // unix timestamp (seconds)
  "adminAddresses":   ["0xAbc...", "0xDef...", "0x123..."],  // Ethereum addresses of admins
  "nodes": [
    {
      "nodeId":      "sha256-derived-id",
      "ikPub":       "64-hex-char-identity-key",   // Ed25519 / X25519 identity public key
      "ekPub":       "64-hex-char-ephemeral-key",  // ephemeral public key
      "role":        "USER_COSIGNER",               // USER_COSIGNER | PROVIDER_COSIGNER | RECOVERY_GUARDIAN
      "walletScope": ["wallet-abc", "wallet-xyz"],  // which wallets this node serves
      "status":      "ACTIVE",                      // ACTIVE | REVOKED
      "enrolledAt":  1710000000
    }
  ],
  "merkleRoot":       "sha256-hex...",
  "prevDocumentHash": "sha256-hex... | null",   // null for genesis (v1)
  "documentHash":     "sha256-hex...",
  "signatures": [
    {
      "adminAddress": "0xAbc...",
      "signature":    "0x...130-hex-chars..."    // EIP-712 typed data signature
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

---

## 3. Fetching the Registry

Fetch the raw `registry.json` from GitHub:

```
GET https://raw.githubusercontent.com/zozzozm/trusted-registery/main/data/registry.json
```

### TypeScript Example

```typescript
const REGISTRY_URL =
  'https://raw.githubusercontent.com/zozzozm/trusted-registery/main/data/registry.json';

async function fetchRegistry(): Promise<RegistryDocument> {
  const res = await fetch(REGISTRY_URL);
  if (!res.ok) throw new Error(`Failed to fetch registry: ${res.status}`);
  return res.json();
}
```

### Caching Strategy

- **Poll interval**: Fetch every 5–15 minutes, or on wallet boot.
- **Cache locally**: Store the last valid document on disk as a fallback.
- **Version check**: Only process if `version` > your cached version.
- **Expiry**: Reject documents where `Date.now()/1000 > expiresAt`.

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
    'registryId', 'version', 'issuedAt', 'expiresAt',
    'adminAddresses', 'nodes', 'merkleRoot',
    'prevDocumentHash', 'documentHash', 'signatures',
  ];
  const missing = required.filter(f => doc[f] === undefined);
  if (missing.length) throw new Error(`Missing fields: ${missing.join(', ')}`);
}

// ── Step 2: Expiry check ─────────────────────────────────────────────────────
function checkExpiry(doc: RegistryDocument): void {
  const now = Math.floor(Date.now() / 1000);
  if (now > doc.expiresAt) {
    throw new Error(`Registry expired at ${new Date(doc.expiresAt * 1000).toISOString()}`);
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
    registryId:       doc.registryId,
    version:          doc.version,
    issuedAt:         doc.issuedAt,
    expiresAt:        doc.expiresAt,
    adminAddresses:   doc.adminAddresses,
    nodes:            doc.nodes,
    merkleRoot:       doc.merkleRoot,
    prevDocumentHash: doc.prevDocumentHash,
    documentHash:     '',  // set to empty string before hashing
  };
  const expected = deterministicHash(unsigned);
  if (expected !== doc.documentHash) {
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
  const sorted = [...doc.nodes].sort((a, b) => a.nodeId.localeCompare(b.nodeId));
  let expected: string;
  if (sorted.length === 0) {
    expected = hashString('empty');
  } else {
    const leaves = sorted.map(n => hashString('leaf:' + deterministicHash(n)));
    expected = buildMerkleTree(leaves)[0];
  }
  if (expected !== doc.merkleRoot) {
    throw new Error('Merkle root mismatch — node list has been tampered with');
  }
}

// ── Step 5: EIP-712 multi-signature verification ─────────────────────────────
const EIP712_DOMAIN = { name: 'MPC Node Registry', version: '1' };

const EIP712_TYPES = {
  NodeRecord: [
    { name: 'nodeId',      type: 'string' },
    { name: 'ikPub',       type: 'string' },
    { name: 'ekPub',       type: 'string' },
    { name: 'role',        type: 'string' },
    { name: 'walletScope', type: 'string[]' },
    { name: 'status',      type: 'string' },
    { name: 'enrolledAt',  type: 'uint256' },
    { name: 'revokedAt',   type: 'uint256' },
  ],
  RegistryDocument: [
    { name: 'registryId',       type: 'string' },
    { name: 'version',          type: 'uint256' },
    { name: 'issuedAt',         type: 'uint256' },
    { name: 'expiresAt',        type: 'uint256' },
    { name: 'adminAddresses',   type: 'address[]' },
    { name: 'nodes',            type: 'NodeRecord[]' },
    { name: 'merkleRoot',       type: 'string' },
    { name: 'prevDocumentHash', type: 'string' },
    { name: 'documentHash',     type: 'string' },
  ],
};

function checkSignatures(doc: RegistryDocument): void {
  if (!doc.signatures || doc.signatures.length < MIN_SIGNATURES) {
    throw new Error(`Need >= ${MIN_SIGNATURES} signatures, got ${doc.signatures?.length ?? 0}`);
  }

  // Build typed data value (normalize for EIP-712)
  const value = {
    registryId:       doc.registryId,
    version:          doc.version,
    issuedAt:         doc.issuedAt,
    expiresAt:        doc.expiresAt,
    adminAddresses:   doc.adminAddresses,
    nodes:            doc.nodes.map(n => ({
      nodeId:      n.nodeId,
      ikPub:       n.ikPub,
      ekPub:       n.ekPub,
      role:        n.role,
      walletScope: n.walletScope,
      status:      n.status,
      enrolledAt:  n.enrolledAt,
      revokedAt:   n.revokedAt ?? 0,
    })),
    merkleRoot:       doc.merkleRoot,
    prevDocumentHash: doc.prevDocumentHash ?? '',
    documentHash:     doc.documentHash,
  };

  const trustedSet = new Set(TRUSTED_ADMIN_ADDRESSES.map(a => a.toLowerCase()));
  const seen = new Set<string>();
  let validCount = 0;

  for (const sig of doc.signatures) {
    const addr = sig.adminAddress.toLowerCase();

    if (seen.has(addr)) throw new Error(`Duplicate signature from ${sig.adminAddress}`);
    seen.add(addr);

    if (!trustedSet.has(addr)) throw new Error(`Unknown admin: ${sig.adminAddress}`);

    // Recover signer via EIP-712
    const recovered = ethers.verifyTypedData(EIP712_DOMAIN, EIP712_TYPES, value, sig.signature);
    if (recovered.toLowerCase() !== addr) {
      throw new Error(`Signature verification failed for ${sig.adminAddress}`);
    }
    validCount++;
  }

  if (validCount < MIN_SIGNATURES) {
    throw new Error(`Only ${validCount} valid signatures, need ${MIN_SIGNATURES}`);
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
  // All checks passed — document is authentic and untampered
}
```

---

## 5. Using the Registry in the MPC Wallet

### 5.1 — Get Active Nodes for a Wallet

```typescript
function getActiveNodesForWallet(
  doc: RegistryDocument,
  walletId: string,
): NodeRecord[] {
  return doc.nodes.filter(
    n => n.status === 'ACTIVE' && n.walletScope.includes(walletId),
  );
}
```

### 5.2 — Get Nodes by Role

```typescript
function getNodesByRole(
  doc: RegistryDocument,
  walletId: string,
  role: 'USER_COSIGNER' | 'PROVIDER_COSIGNER' | 'RECOVERY_GUARDIAN',
): NodeRecord[] {
  return doc.nodes.filter(
    n => n.status === 'ACTIVE' && n.role === role && n.walletScope.includes(walletId),
  );
}
```

### 5.3 — MPC Ceremony Integration

```typescript
async function startSigningCeremony(walletId: string, txPayload: any) {
  // 1. Fetch and verify registry
  const registry = await fetchRegistry();
  verifyRegistry(registry);

  // 2. Resolve the signing quorum
  const userNode     = getNodesByRole(registry, walletId, 'USER_COSIGNER')[0];
  const providerNode = getNodesByRole(registry, walletId, 'PROVIDER_COSIGNER')[0];

  if (!userNode || !providerNode) {
    throw new Error('Missing required cosigners for this wallet');
  }

  // 3. Use ikPub / ekPub to establish encrypted channels and run MPC
  const participants = [
    { nodeId: userNode.nodeId,     ikPub: userNode.ikPub,     ekPub: userNode.ekPub },
    { nodeId: providerNode.nodeId, ikPub: providerNode.ikPub, ekPub: providerNode.ekPub },
  ];

  // ... initiate MPC signing protocol with these participants
}
```

---

## 6. High-Water Mark (Rollback Protection)

To prevent an attacker from serving a stale (older) registry version, the wallet should track the highest version it has seen:

```typescript
interface HighWaterMark {
  registryId:  string;
  maxVersion:  number;
  lastDocHash: string;
  updatedAt:   number;
}

function checkRollback(doc: RegistryDocument, hwm: HighWaterMark | null): void {
  if (!hwm) return; // first fetch, nothing to compare

  if (doc.registryId !== hwm.registryId) {
    throw new Error('Registry ID changed — possible substitution attack');
  }
  if (doc.version < hwm.maxVersion) {
    throw new Error(`Rollback detected: got v${doc.version}, expected >= v${hwm.maxVersion}`);
  }
}

function updateHighWaterMark(doc: RegistryDocument): HighWaterMark {
  return {
    registryId:  doc.registryId,
    maxVersion:  doc.version,
    lastDocHash: doc.documentHash,
    updatedAt:   Math.floor(Date.now() / 1000),
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
    // Genesis document — prevDocumentHash must be null
    if (newDoc.prevDocumentHash !== null) {
      throw new Error('Genesis document must have null prevDocumentHash');
    }
    return;
  }

  if (newDoc.prevDocumentHash !== previousDoc.documentHash) {
    throw new Error('Hash chain broken — prevDocumentHash does not match previous document');
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
| **Expired registry** | Always check `expiresAt`. Refuse to use expired documents. |
| **Man-in-the-middle** | HTTPS to GitHub + signature verification. Consider pinning the GitHub TLS certificate. |
| **Node key rotation** | When a node is revoked, its `status` changes to `REVOKED`. Always filter for `ACTIVE` nodes. |

### Trust Root Summary

The wallet trusts **only** the hardcoded admin Ethereum addresses. Everything else is verified:

```
Admin Addresses (hardcoded)
  └── verify EIP-712 signatures on registry document
        └── documentHash (SHA-256 integrity of all fields)
              ├── merkleRoot (integrity of individual nodes)
              └── prevDocumentHash (chain to previous version)
```

---

## 9. Dependencies

The wallet app needs these packages for verification:

```json
{
  "ethers": "^6.x",     // EIP-712 signature recovery
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
  nodeId:      string;
  ikPub:       string;
  ekPub:       string;
  role:        NodeRole;
  walletScope: string[];
  status:      NodeStatus;
  enrolledAt:  number;
  revokedAt?:  number;
}

interface AdminSignature {
  adminAddress: string;
  signature:    string;
}

interface RegistryDocument {
  registryId:       string;
  version:          number;
  issuedAt:         number;
  expiresAt:        number;
  adminAddresses:   string[];
  nodes:            NodeRecord[];
  merkleRoot:       string;
  prevDocumentHash: string | null;
  documentHash:     string;
  signatures:       AdminSignature[];
}

interface HighWaterMark {
  registryId:  string;
  maxVersion:  number;
  lastDocHash: string;
  updatedAt:   number;
}
```
