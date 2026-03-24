// ─────────────────────────────────────────────────────────────────────────────
// Cryptographic helpers — Ethereum ECDSA signatures + SHA256 hashing
// ─────────────────────────────────────────────────────────────────────────────

import { ethers } from 'ethers'
import { createHash } from 'crypto'
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { ed25519 } = require('@noble/curves/ed25519.js')
import {
  UnsignedDocument, RoleSignature, VerifyResult,
  NodeRecord, GovernanceRole, RegistryMetadata,
  CeremonyConfig, TrustedInfrastructure, ImmutablePolicies,
  RegistryEndpoints, Governance
} from './types'

// ── Hashing ───────────────────────────────────────────────────────────────────

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

export function computeDocumentHash(doc: UnsignedDocument): string {
  // Set document_hash to empty string before hashing
  const clone = JSON.parse(JSON.stringify(doc))
  clone.registry_metadata.document_hash = ''
  return hashObject(clone)
}

// ── Merkle tree ───────────────────────────────────────────────────────────────

export function computeMerkleRoot(nodes: { node_id: string }[]): string {
  if (nodes.length === 0) return hashString('empty')
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

export const EIP712_DOMAIN = {
  name: 'MPC Node Registry',
  version: '2',
}

export const EIP712_TYPES = {
  Endpoints: [
    { name: 'primary', type: 'string' },
    { name: 'mirrors', type: 'string[]' },
  ],
  RegistryMetadata: [
    { name: 'registry_id',        type: 'string' },
    { name: 'version',            type: 'uint256' },
    { name: 'issued_at',          type: 'uint256' },
    { name: 'expires_at',         type: 'uint256' },
    { name: 'updated_at',         type: 'string' },
    { name: 'document_hash',      type: 'string' },
    { name: 'merkle_root',        type: 'string' },
    { name: 'prev_document_hash', type: 'string' },
    { name: 'endpoints',          type: 'Endpoints' },
  ],
  GovernanceRole: [
    { name: 'role',          type: 'string' },
    { name: 'display_name',  type: 'string' },
    { name: 'addresses',     type: 'address[]' },
    { name: 'quorum',        type: 'uint256' },
    { name: 'features_json', type: 'string' },
  ],
  CeremonyConfig: [
    { name: 'global_threshold_t',  type: 'uint256' },
    { name: 'max_participants_n',  type: 'uint256' },
    { name: 'allowed_protocols',   type: 'string[]' },
    { name: 'allowed_curves',      type: 'string[]' },
  ],
  TrustedInfrastructure: [
    { name: 'backoffice_pubkey', type: 'string' },
    { name: 'market_oracle_pubkey',      type: 'string' },
    { name: 'trusted_binary_hashes',      type: 'string[]' },
  ],
  NodeRecord: [
    { name: 'node_id',      type: 'string' },
    { name: 'ik_pub',       type: 'string' },
    { name: 'ek_pub',       type: 'string' },
    { name: 'role',          type: 'string' },
    { name: 'status',        type: 'string' },
    { name: 'enrolled_at',   type: 'uint256' },
    { name: 'updated_at',    type: 'uint256' },
    { name: 'revoked_at',    type: 'uint256' },
  ],
  ImmutablePolicies: [
    { name: 'max_withdrawal_usd_24h', type: 'uint256' },
    { name: 'require_oracle_price',   type: 'bool' },
    { name: 'enforce_whitelist',       type: 'bool' },
  ],
  RegistryDocument: [
    { name: 'registry_metadata',      type: 'RegistryMetadata' },
    { name: 'governance',             type: 'GovernanceRole[]' },
    { name: 'ceremony_config',        type: 'CeremonyConfig' },
    { name: 'trusted_infrastructure', type: 'TrustedInfrastructure' },
    { name: 'nodes',                  type: 'NodeRecord[]' },
    { name: 'immutable_policies',     type: 'ImmutablePolicies' },
  ],
}

type DocForSigning = UnsignedDocument & { registry_metadata: { document_hash: string } }

export function buildTypedDataValue(doc: DocForSigning) {
  const meta = doc.registry_metadata
  return {
    registry_metadata: {
      registry_id:        meta.registry_id,
      version:            meta.version,
      issued_at:          meta.issued_at,
      expires_at:         meta.expires_at,
      updated_at:         meta.updated_at ?? '',
      document_hash:      meta.document_hash,
      merkle_root:        meta.merkle_root,
      prev_document_hash: meta.prev_document_hash ?? '',
      endpoints:          meta.endpoints
        ? { primary: meta.endpoints.primary, mirrors: meta.endpoints.mirrors }
        : { primary: '', mirrors: [] },
    },
    governance: doc.governance.roles.map(r => ({
      role:          r.role,
      display_name:  r.display_name,
      addresses:     r.addresses,
      quorum:        r.quorum,
      features_json: JSON.stringify(r.features ?? {}),
    })),
    ceremony_config: {
      global_threshold_t:  doc.ceremony_config.global_threshold_t,
      max_participants_n:  doc.ceremony_config.max_participants_n,
      allowed_protocols:   doc.ceremony_config.allowed_protocols,
      allowed_curves:      doc.ceremony_config.allowed_curves,
    },
    trusted_infrastructure: {
      backoffice_pubkey: doc.trusted_infrastructure.backoffice_pubkey ?? '',
      market_oracle_pubkey:      doc.trusted_infrastructure.market_oracle_pubkey ?? '',
      trusted_binary_hashes:      doc.trusted_infrastructure.trusted_binary_hashes ?? [],
    },
    nodes: doc.nodes.map(n => ({
      node_id:      n.node_id,
      ik_pub:       n.ik_pub,
      ek_pub:       n.ek_pub,
      role:          n.role,
      status:        n.status,
      enrolled_at:   n.enrolled_at,
      updated_at:    n.updated_at ?? 0,
      revoked_at:    n.revoked_at ?? 0,
    })),
    immutable_policies: {
      max_withdrawal_usd_24h: doc.immutable_policies.max_withdrawal_usd_24h,
      require_oracle_price:   doc.immutable_policies.require_oracle_price,
      enforce_whitelist:       doc.immutable_policies.enforce_whitelist,
    },
  }
}

export function getEIP712Payload(doc: DocForSigning) {
  return {
    domain:      EIP712_DOMAIN,
    types:       EIP712_TYPES,
    primaryType: 'RegistryDocument' as const,
    message:     buildTypedDataValue(doc),
  }
}

export async function signDocument(doc: DocForSigning, privateKey: string): Promise<string> {
  const wallet = new ethers.Wallet(privateKey)
  const value = buildTypedDataValue(doc)
  return wallet.signTypedData(EIP712_DOMAIN, EIP712_TYPES, value)
}

export function recoverSigner(doc: DocForSigning, signature: string): string {
  const value = buildTypedDataValue(doc)
  return ethers.verifyTypedData(EIP712_DOMAIN, EIP712_TYPES, value, signature)
}

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

// ── Ed25519 rotation proof verification ───────────────────────────────────────

export function verifyRotationProof(
  prevIkPub: string, newIkPub: string, timestamp: number, proof: string,
): boolean {
  try {
    const message = `rotate:${prevIkPub}:${newIkPub}:${timestamp}`
    const msgBytes = new TextEncoder().encode(message)
    const sigBytes = Buffer.from(proof, 'hex')
    const pubBytes = Buffer.from(prevIkPub, 'hex')
    return ed25519.verify(sigBytes, msgBytes, pubBytes)
  } catch {
    return false
  }
}

// ── Role-based signature verification ─────────────────────────────────────────

/**
 * Verify that a governance role's quorum is met by the given signatures.
 * Signatures are verified against the role's address list.
 */
export function verifyRoleQuorum(
  doc: DocForSigning,
  signatures: RoleSignature[],
  role: GovernanceRole,
): VerifyResult {
  const roleSigs = signatures.filter(s => s.role.toUpperCase() === role.role.toUpperCase())

  if (roleSigs.length < role.quorum) {
    return { valid: false, reason: `${role.role}: need >= ${role.quorum} signatures, got ${roleSigs.length}` }
  }

  const addrSet = new Set(role.addresses.map(a => a.toLowerCase()))
  const seen = new Set<string>()
  let validCount = 0

  for (const sig of roleSigs) {
    const addr = sig.signer.toLowerCase()
    if (seen.has(addr)) {
      return { valid: false, reason: `${role.role}: duplicate signer ${sig.signer}` }
    }
    seen.add(addr)

    if (!addrSet.has(addr)) {
      return { valid: false, reason: `${role.role}: unknown signer ${sig.signer}` }
    }

    if (!/^0x[0-9a-f]{130}$/i.test(sig.signature)) {
      return { valid: false, reason: `${role.role}: malformed signature from ${sig.signer}` }
    }

    const ok = verifySingleSig(doc, sig.signature, sig.signer)
    if (!ok) {
      return { valid: false, reason: `${role.role}: invalid signature from ${sig.signer}` }
    }
    validCount++
  }

  if (validCount < role.quorum) {
    return { valid: false, reason: `${role.role}: only ${validCount} valid, need ${role.quorum}` }
  }

  return { valid: true }
}

/**
 * Verify all roles in a governance section meet their quorum.
 */
export function verifyAllRoleQuorums(
  doc: DocForSigning,
  signatures: RoleSignature[],
  roles: GovernanceRole[],
): VerifyResult {
  for (const role of roles) {
    const result = verifyRoleQuorum(doc, signatures, role)
    if (!result.valid) return result
  }
  return { valid: true }
}
