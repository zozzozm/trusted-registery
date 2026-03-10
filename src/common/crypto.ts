// ─────────────────────────────────────────────────────────────────────────────
// Cryptographic helpers — Ed25519 signatures + SHA256 hashing
// ─────────────────────────────────────────────────────────────────────────────

import * as ed from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha512'
import { createHash } from 'crypto'
import { RegistryDocument, UnsignedDocument, AdminSignature, VerifyResult } from './types'

// noble/ed25519 v2 requires a SHA-512 implementation
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m))

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

// ── Ed25519 signatures ────────────────────────────────────────────────────────

export async function signHex(messageHex: string, privKeyHex: string): Promise<string> {
  const sig = await ed.sign(
    Buffer.from(messageHex, 'hex'),
    Buffer.from(privKeyHex, 'hex')
  )
  return Buffer.from(sig).toString('hex')
}

export function verifyHex(
  messageHex: string,
  signatureHex: string,
  pubKeyHex: string
): boolean {
  try {
    return ed.verify(
      Buffer.from(signatureHex, 'hex'),
      Buffer.from(messageHex, 'hex'),
      Buffer.from(pubKeyHex, 'hex')
    )
  } catch {
    return false
  }
}

export async function generateKeypair(): Promise<{ privKey: string; pubKey: string }> {
  const { randomBytes } = await import('crypto')
  const privKey = randomBytes(32)
  const pubKey  = await ed.getPublicKey(privKey)
  return {
    privKey: Buffer.from(privKey).toString('hex'),
    pubKey:  Buffer.from(pubKey).toString('hex'),
  }
}

export function deriveNodeId(ikPub: string, role: string, enrolledAt: number): string {
  return hashString('nodeId:' + ikPub + ':' + role + ':' + enrolledAt.toString())
}

// ── Multi-signature verification ──────────────────────────────────────────────

export function verifyMultiSig(
  documentHash: string,
  signatures: AdminSignature[],
  adminPubKeys: string[],   // hardcoded in node binary
  required: number
): VerifyResult {

  if (!signatures || signatures.length < required) {
    return { valid: false, reason: `Need ≥${required} signatures, got ${signatures?.length ?? 0}` }
  }

  const seen = new Set<number>()
  let validCount = 0

  for (const sig of signatures) {
    // No duplicate admin indices
    if (seen.has(sig.adminIndex)) {
      return { valid: false, reason: `Duplicate adminIndex ${sig.adminIndex}` }
    }
    seen.add(sig.adminIndex)

    // Valid admin index
    const pubKey = adminPubKeys[sig.adminIndex]
    if (!pubKey) {
      return { valid: false, reason: `Unknown adminIndex: ${sig.adminIndex}` }
    }

    // Valid signature format
    if (!/^[0-9a-f]{128}$/i.test(sig.signature)) {
      return { valid: false, reason: `Malformed signature at adminIndex ${sig.adminIndex}` }
    }

    // Cryptographic verification
    const ok = verifyHex(documentHash, sig.signature, pubKey)
    if (!ok) {
      return { valid: false, reason: `Invalid signature at adminIndex ${sig.adminIndex}` }
    }
    validCount++
  }

  if (validCount < required) {
    return { valid: false, reason: `Only ${validCount} valid signatures, need ${required}` }
  }

  return { valid: true }
}
