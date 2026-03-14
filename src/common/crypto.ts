// ─────────────────────────────────────────────────────────────────────────────
// Cryptographic helpers — Ethereum ECDSA signatures + SHA256 hashing
// ─────────────────────────────────────────────────────────────────────────────

import { ethers } from 'ethers'
import { createHash } from 'crypto'
import { UnsignedDocument, AdminSignature, VerifyResult, NodeRecord, RegistryEndpoints } from './types'

// ── Hashing ───────────────────────────────────────────────────────────────────

/**
 * Deterministic JSON hash — sorts keys recursively before hashing
 * so { b: 2, a: 1 } and { a: 1, b: 2 } produce the same hash.
 */
export function hashObject(obj: object): string {
  const canonical = JSON.stringify(obj, (_k, v) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      return Object.fromEntries(
        Object.entries(v).sort(([a], [b]) => a.localeCompare(b))
      )
    }
    return v
  })
  return createHash('sha256').update(canonical).digest('hex')
}

export function hashString(s: string): string {
  return createHash('sha256').update(s).digest('hex')
}

/**
 * Build the documentHash field — hashes everything except signatures
 */
export function computeDocumentHash(doc: UnsignedDocument): string {
  return hashObject(doc)
}

// ── Merkle tree ───────────────────────────────────────────────────────────────

export function computeMerkleRoot(nodes: { nodeId: string }[]): string {
  if (nodes.length === 0) return hashString('empty')

  // Sort by nodeId for determinism
  const leaves = [...nodes]
    .sort((a, b) => a.nodeId.localeCompare(b.nodeId))
    .map(n => hashString('leaf:' + hashObject(n)))

  return buildMerkleTree(leaves)[0]
}

function buildMerkleTree(leaves: string[]): string[] {
  if (leaves.length === 1) return leaves
  const next: string[] = []
  for (let i = 0; i < leaves.length; i += 2) {
    const right = i + 1 < leaves.length ? leaves[i + 1] : leaves[i]
    next.push(hashString('node:' + leaves[i] + ':' + right))
  }
  return buildMerkleTree(next)
}

// ── EIP-712 Typed Data Signing ───────────────────────────────────────────────

/**
 * EIP-712 domain separator — identifies this signing context.
 * No chainId since this is chain-agnostic (off-chain registry).
 */
export const EIP712_DOMAIN = {
  name: 'MPC Node Registry',
  version: '1',
}

/**
 * EIP-712 type definitions.
 * MetaMask displays each field with its label and value.
 */
export const EIP712_TYPES = {
  NodeRecord: [
    { name: 'nodeId',      type: 'string' },
    { name: 'ikPub',       type: 'string' },
    { name: 'ekPub',       type: 'string' },
    { name: 'role',        type: 'string' },
    { name: 'status',      type: 'string' },
    { name: 'enrolledAt',  type: 'uint256' },
    { name: 'revokedAt',   type: 'uint256' },
  ],
  Endpoints: [
    { name: 'primary',    type: 'string' },
    { name: 'mirrors',    type: 'string[]' },
    { name: 'updated_at', type: 'string' },
  ],
  RegistryDocument: [
    { name: 'registryId',            type: 'string' },
    { name: 'version',               type: 'uint256' },
    { name: 'issuedAt',              type: 'uint256' },
    { name: 'expiresAt',             type: 'uint256' },
    { name: 'adminAddresses',        type: 'address[]' },
    { name: 'backofficeServicePubkey', type: 'string' },
    { name: 'threshold',             type: 'uint256' },
    { name: 'allowedCurves',         type: 'string[]' },
    { name: 'allowedProtocols',      type: 'string[]' },
    { name: 'minThreshold',          type: 'uint256' },
    { name: 'endpoints',             type: 'Endpoints' },
    { name: 'nodes',                 type: 'NodeRecord[]' },
    { name: 'merkleRoot',            type: 'string' },
    { name: 'prevDocumentHash',      type: 'string' },
    { name: 'documentHash',          type: 'string' },
  ],
}

type DocForSigning = {
  registryId: string
  version: number
  issuedAt: number
  expiresAt: number
  adminAddresses: string[]
  backofficeServicePubkey: string | null
  threshold: number
  allowedCurves: string[]
  allowedProtocols: string[]
  minThreshold: number
  endpoints: RegistryEndpoints | null
  nodes: NodeRecord[]
  merkleRoot: string
  prevDocumentHash: string | null
  documentHash: string
}

/**
 * Build the EIP-712 typed data value from a document.
 * Normalizes fields for EIP-712 compatibility (null → empty string, revokedAt → 0).
 */
export function buildTypedDataValue(doc: DocForSigning) {
  return {
    registryId:            doc.registryId,
    version:               doc.version,
    issuedAt:              doc.issuedAt,
    expiresAt:             doc.expiresAt,
    adminAddresses:        doc.adminAddresses,
    backofficeServicePubkey: doc.backofficeServicePubkey ?? '',
    threshold:             doc.threshold,
    allowedCurves:         doc.allowedCurves,
    allowedProtocols:      doc.allowedProtocols,
    minThreshold:          doc.minThreshold,
    endpoints:             doc.endpoints
      ? { primary: doc.endpoints.primary, mirrors: doc.endpoints.mirrors, updated_at: doc.endpoints.updated_at }
      : { primary: '', mirrors: [], updated_at: '' },
    nodes:                 doc.nodes.map(n => ({
      nodeId:      n.nodeId,
      ikPub:       n.ikPub,
      ekPub:       n.ekPub,
      role:        n.role,
      status:      n.status,
      enrolledAt:  n.enrolledAt,
      revokedAt:   n.revokedAt ?? 0,
    })),
    merkleRoot:       doc.merkleRoot,
    prevDocumentHash: doc.prevDocumentHash ?? '',
    documentHash:     doc.documentHash,
  }
}

/**
 * Returns the full EIP-712 payload for use by MetaMask (eth_signTypedData_v4).
 */
export function getEIP712Payload(doc: DocForSigning) {
  return {
    domain:      EIP712_DOMAIN,
    types:       EIP712_TYPES,
    primaryType: 'RegistryDocument' as const,
    message:     buildTypedDataValue(doc),
  }
}

/**
 * Sign a document using an ethers Wallet (for CLI / testing).
 * Produces the same signature as MetaMask eth_signTypedData_v4.
 */
export async function signDocument(doc: DocForSigning, privateKey: string): Promise<string> {
  const wallet = new ethers.Wallet(privateKey)
  const value = buildTypedDataValue(doc)
  return wallet.signTypedData(EIP712_DOMAIN, EIP712_TYPES, value)
}

/**
 * Recover the signer's Ethereum address from an EIP-712 signature.
 */
export function recoverSigner(doc: DocForSigning, signature: string): string {
  const value = buildTypedDataValue(doc)
  return ethers.verifyTypedData(EIP712_DOMAIN, EIP712_TYPES, value, signature)
}

/**
 * Verify a single signature against an expected admin address.
 */
export function verifySingleSig(doc: DocForSigning, signature: string, expectedAddress: string): boolean {
  try {
    const recovered = recoverSigner(doc, signature)
    return recovered.toLowerCase() === expectedAddress.toLowerCase()
  } catch {
    return false
  }
}

export function deriveNodeId(ikPub: string, role: string, enrolledAt: number): string {
  return hashString('nodeId:' + ikPub + ':' + role + ':' + enrolledAt.toString())
}

// ── Multi-signature verification ──────────────────────────────────────────────

export function verifyMultiSig(
  doc: {
    registryId: string
    version: number
    issuedAt: number
    expiresAt: number
    adminAddresses: string[]
    backofficeServicePubkey: string | null
    threshold: number
    allowedCurves: string[]
    allowedProtocols: string[]
    minThreshold: number
    endpoints: RegistryEndpoints | null
    nodes: NodeRecord[]
    merkleRoot: string
    prevDocumentHash: string | null
    documentHash: string
  },
  signatures: AdminSignature[],
  signingAdminAddresses: string[],
  required: number
): VerifyResult {

  if (!signatures || signatures.length < required) {
    return { valid: false, reason: `Need >= ${required} signatures, got ${signatures?.length ?? 0}` }
  }

  const adminSet = new Set(signingAdminAddresses.map(a => a.toLowerCase()))
  const seen = new Set<string>()
  let validCount = 0

  for (const sig of signatures) {
    const addr = sig.adminAddress.toLowerCase()

    if (seen.has(addr)) {
      return { valid: false, reason: `Duplicate admin address ${sig.adminAddress}` }
    }
    seen.add(addr)

    if (!adminSet.has(addr)) {
      return { valid: false, reason: `Unknown admin address: ${sig.adminAddress}` }
    }

    // Signature format: 0x-prefixed 65-byte hex = 132 chars
    if (!/^0x[0-9a-f]{130}$/i.test(sig.signature)) {
      return { valid: false, reason: `Malformed signature from ${sig.adminAddress}` }
    }

    const ok = verifySingleSig(doc, sig.signature, sig.adminAddress)
    if (!ok) {
      return { valid: false, reason: `Invalid signature from ${sig.adminAddress}` }
    }
    validCount++
  }

  if (validCount < required) {
    return { valid: false, reason: `Only ${validCount} valid signatures, need ${required}` }
  }

  return { valid: true }
}
