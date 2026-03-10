// ─────────────────────────────────────────────────────────────────────────────
// Cryptographic helpers — Ethereum ECDSA signatures + SHA256 hashing
// ─────────────────────────────────────────────────────────────────────────────

import { ethers } from 'ethers'
import { createHash } from 'crypto'
import { UnsignedDocument, AdminSignature, VerifyResult } from './types'

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

// ── Ethereum EIP-191 signatures ──────────────────────────────────────────────

/**
 * Build the human-readable message that wallets will display when signing.
 * Uses EIP-191 personal_sign format.
 */
export function buildSignMessage(documentHash: string): string {
  return `MPC Registry Sign\ndocumentHash:${documentHash}`
}

/**
 * Sign a documentHash using an ethers Wallet (for CLI / testing).
 * Produces the same signature format as MetaMask personal_sign.
 */
export async function signDocument(documentHash: string, privateKey: string): Promise<string> {
  const wallet = new ethers.Wallet(privateKey)
  const message = buildSignMessage(documentHash)
  return wallet.signMessage(message)
}

/**
 * Recover the signer's Ethereum address from a personal_sign signature.
 */
export function recoverSigner(documentHash: string, signature: string): string {
  const message = buildSignMessage(documentHash)
  return ethers.verifyMessage(message, signature)
}

/**
 * Verify a single signature against an expected admin address.
 */
export function verifySingleSig(documentHash: string, signature: string, expectedAddress: string): boolean {
  try {
    const recovered = recoverSigner(documentHash, signature)
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
  documentHash: string,
  signatures: AdminSignature[],
  adminAddresses: string[],
  required: number
): VerifyResult {

  if (!signatures || signatures.length < required) {
    return { valid: false, reason: `Need >= ${required} signatures, got ${signatures?.length ?? 0}` }
  }

  const adminSet = new Set(adminAddresses.map(a => a.toLowerCase()))
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

    const ok = verifySingleSig(documentHash, sig.signature, sig.adminAddress)
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
