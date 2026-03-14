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
 * Build the document_hash field — hashes everything except signatures
 */
export function computeDocumentHash(doc: UnsignedDocument): string {
  return hashObject(doc)
}

// ── Merkle tree ───────────────────────────────────────────────────────────────

export function computeMerkleRoot(nodes: { node_id: string }[]): string {
  if (nodes.length === 0) return hashString('empty')

  // Sort by node_id for determinism
  const leaves = [...nodes]
    .sort((a, b) => a.node_id.localeCompare(b.node_id))
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
    { name: 'node_id',      type: 'string' },
    { name: 'ik_pub',       type: 'string' },
    { name: 'ek_pub',       type: 'string' },
    { name: 'role',        type: 'string' },
    { name: 'status',      type: 'string' },
    { name: 'enrolled_at',  type: 'uint256' },
    { name: 'revoked_at',   type: 'uint256' },
  ],
  Endpoints: [
    { name: 'primary',    type: 'string' },
    { name: 'mirrors',    type: 'string[]' },
    { name: 'updated_at', type: 'string' },
  ],
  RegistryDocument: [
    { name: 'registry_id',            type: 'string' },
    { name: 'version',               type: 'uint256' },
    { name: 'issued_at',              type: 'uint256' },
    { name: 'expires_at',             type: 'uint256' },
    { name: 'admin_addresses',        type: 'address[]' },
    { name: 'backoffice_service_pubkey', type: 'string' },
    { name: 'allowed_curves',         type: 'string[]' },
    { name: 'allowed_protocols',      type: 'string[]' },
    { name: 'admin_quorum',             type: 'uint256' },
    { name: 'endpoints',             type: 'Endpoints' },
    { name: 'nodes',                 type: 'NodeRecord[]' },
    { name: 'merkle_root',            type: 'string' },
    { name: 'prev_document_hash',      type: 'string' },
    { name: 'document_hash',          type: 'string' },
  ],
}

type DocForSigning = {
  registry_id: string
  version: number
  issued_at: number
  expires_at: number
  admin_addresses: string[]
  backoffice_service_pubkey: string | null
  allowed_curves: string[]
  allowed_protocols: string[]
  admin_quorum: number
  endpoints: RegistryEndpoints | null
  nodes: NodeRecord[]
  merkle_root: string
  prev_document_hash: string | null
  document_hash: string
}

/**
 * Build the EIP-712 typed data value from a document.
 * Normalizes fields for EIP-712 compatibility (null → empty string, revoked_at → 0).
 */
export function buildTypedDataValue(doc: DocForSigning) {
  return {
    registry_id:            doc.registry_id,
    version:               doc.version,
    issued_at:              doc.issued_at,
    expires_at:             doc.expires_at,
    admin_addresses:        doc.admin_addresses,
    backoffice_service_pubkey: doc.backoffice_service_pubkey ?? '',
    allowed_curves:         doc.allowed_curves,
    allowed_protocols:      doc.allowed_protocols,
    admin_quorum:             doc.admin_quorum,
    endpoints:             doc.endpoints
      ? { primary: doc.endpoints.primary, mirrors: doc.endpoints.mirrors, updated_at: doc.endpoints.updated_at }
      : { primary: '', mirrors: [], updated_at: '' },
    nodes:                 doc.nodes.map(n => ({
      node_id:      n.node_id,
      ik_pub:       n.ik_pub,
      ek_pub:       n.ek_pub,
      role:        n.role,
      status:      n.status,
      enrolled_at:  n.enrolled_at,
      revoked_at:   n.revoked_at ?? 0,
    })),
    merkle_root:       doc.merkle_root,
    prev_document_hash: doc.prev_document_hash ?? '',
    document_hash:     doc.document_hash,
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
    registry_id: string
    version: number
    issued_at: number
    expires_at: number
    admin_addresses: string[]
    backoffice_service_pubkey: string | null
    allowed_curves: string[]
    allowed_protocols: string[]
    admin_quorum: number
    endpoints: RegistryEndpoints | null
    nodes: NodeRecord[]
    merkle_root: string
    prev_document_hash: string | null
    document_hash: string
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
    const addr = sig.admin_address.toLowerCase()

    if (seen.has(addr)) {
      return { valid: false, reason: `Duplicate admin address ${sig.admin_address}` }
    }
    seen.add(addr)

    if (!adminSet.has(addr)) {
      return { valid: false, reason: `Unknown admin address: ${sig.admin_address}` }
    }

    // Signature format: 0x-prefixed 65-byte hex = 132 chars
    if (!/^0x[0-9a-f]{130}$/i.test(sig.signature)) {
      return { valid: false, reason: `Malformed signature from ${sig.admin_address}` }
    }

    const ok = verifySingleSig(doc, sig.signature, sig.admin_address)
    if (!ok) {
      return { valid: false, reason: `Invalid signature from ${sig.admin_address}` }
    }
    validCount++
  }

  if (validCount < required) {
    return { valid: false, reason: `Only ${validCount} valid signatures, need ${required}` }
  }

  return { valid: true }
}
