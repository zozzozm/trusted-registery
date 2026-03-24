#!/usr/bin/env ts-node
// scripts/verify-file.ts — used by GitHub Actions to verify the registry file
//
// TRUST MODEL (role-based governance):
//   Genesis (v1) signatures are verified against the document's own governance roles.
//     SYSTEM_ADMIN role addresses must match ADMIN_ADDRESS_* env vars (external trust root).
//   Every subsequent version's signatures are verified against the PREVIOUS version's
//     governance roles — each role must meet its quorum using the previous version's addresses.
//   The full chain is walked from genesis to HEAD to prevent self-referential role injection.
import * as dotenv from 'dotenv'
dotenv.config()
import { readFileSync, existsSync, readdirSync } from 'fs'
import { dirname, resolve } from 'path'
import {
  computeDocumentHash, computeMerkleRoot, verifyRoleQuorum,
} from '../src/common/crypto'
import { CONFIG } from '../src/common/config'
import type { RegistryDocument, GovernanceRole } from '../src/common/types'

/** Verify a single document's hash and merkle root integrity. */
function verifyIntegrity(doc: RegistryDocument, label: string) {
  // Document hash
  const savedHash = doc.registry_metadata.document_hash
  const { signatures: _, ...body } = doc
  const expected = computeDocumentHash(body)
  if (expected !== savedHash) {
    console.error(`${label}: document hash mismatch`)
    process.exit(1)
  }

  // Merkle root
  const nodes = Array.isArray(doc.nodes) ? doc.nodes : []
  const expectedRoot = computeMerkleRoot(nodes)
  if (expectedRoot !== doc.registry_metadata.merkle_root) {
    console.error(`${label}: merkle root mismatch`)
    process.exit(1)
  }
}

/**
 * Verify signatures on a document against a set of governance roles.
 * Each role must meet its quorum — signatures are verified cryptographically.
 */
function verifyRoleSignatures(
  doc: RegistryDocument,
  roles: GovernanceRole[],
  label: string,
) {
  const { signatures: _, ...body } = doc
  // Build the doc-for-signing (unsigned doc with document_hash set)
  const docForSigning = { ...body, registry_metadata: { ...body.registry_metadata } } as any

  for (const role of roles) {
    const result = verifyRoleQuorum(docForSigning, doc.signatures, role)
    if (!result.valid) {
      console.error(`${label}: role quorum verification failed — ${result.reason}`)
      process.exit(1)
    }
  }
}

/** Find the SYSTEM_ADMIN role in a document's governance. */
function getSystemAdminRole(doc: RegistryDocument): GovernanceRole | undefined {
  return doc.governance.roles.find(r => r.role === 'SYSTEM_ADMIN')
}

function main() {
  const file = CONFIG.REGISTRY_FILE
  const doc: RegistryDocument = JSON.parse(readFileSync(file, 'utf-8'))
  const versionsDir = resolve(dirname(file), 'versions')

  const meta = doc.registry_metadata
  const sysAdmin = getSystemAdminRole(doc)

  console.log(`Verifying ${file}`)
  console.log(`  Registry: ${meta.registry_id}`)
  console.log(`  Version:  ${meta.version}`)
  console.log(`  Nodes:    ${doc.nodes?.length ?? 0}`)
  console.log(`  Roles:    ${doc.governance.roles.map(r => r.role).join(', ')}`)

  // Check registry ID
  if (meta.registry_id !== CONFIG.REGISTRY_ID) {
    console.error(`Registry ID mismatch: ${meta.registry_id} !== ${CONFIG.REGISTRY_ID}`)
    process.exit(1)
  }

  // Verify SYSTEM_ADMIN role exists and meets minimum requirements
  if (!sysAdmin) {
    console.error('Document is missing the SYSTEM_ADMIN governance role')
    process.exit(1)
  }
  if (sysAdmin.addresses.length < CONFIG.SYSTEM_ADMIN_MIN_ADDRESSES) {
    console.error(
      `SYSTEM_ADMIN needs at least ${CONFIG.SYSTEM_ADMIN_MIN_ADDRESSES} addresses, ` +
      `got ${sysAdmin.addresses.length}`,
    )
    process.exit(1)
  }
  if (sysAdmin.quorum < CONFIG.SYSTEM_ADMIN_QUORUM) {
    console.error(
      `SYSTEM_ADMIN quorum must be >= ${CONFIG.SYSTEM_ADMIN_QUORUM}, got ${sysAdmin.quorum}`,
    )
    process.exit(1)
  }

  // ── Establish trust root from env vars ──────────────────────────────────
  const genesisAddrs = CONFIG.GENESIS_ADMIN_ADDRESSES
  if (genesisAddrs.length === 0) {
    console.error('ADMIN_ADDRESS_* env vars are required as the trust root for verification')
    process.exit(1)
  }

  // Load trust root addresses for all roles from env vars
  const trustRootByRole: Record<string, string[]> = {}
  for (const [roleName, prefix] of Object.entries(CONFIG.GENESIS_ROLE_PREFIXES)) {
    const addrs = CONFIG.getGenesisRoleAddresses(prefix)
    if (addrs.length > 0) trustRootByRole[roleName] = addrs
  }
  console.log(`  Trust root roles: ${Object.keys(trustRootByRole).join(', ')}`)

  // Check expiry
  const now = Math.floor(Date.now() / 1000)
  if (now > meta.expires_at) {
    console.warn(`Document expired — renew it!`)
  }

  // ── Verify document integrity (hash + merkle) ──────────────────────────
  verifyIntegrity(doc, `v${meta.version}`)
  console.log(`  Document hash verified`)
  console.log(`  Merkle root verified`)

  // ── Full chain-of-trust verification ───────────────────────────────────
  const currentVersion = meta.version

  if (currentVersion === 1) {
    // Genesis: verify ALL roles that have env vars match the document
    for (const [roleName, envAddrs] of Object.entries(trustRootByRole)) {
      const docRole = doc.governance.roles.find((r: GovernanceRole) => r.role === roleName)
      if (!docRole) {
        console.error(`Genesis is missing ${roleName} role (expected from env vars)`)
        process.exit(1)
      }
      const docSet = new Set(docRole.addresses.map((a: string) => a.toLowerCase()))
      const envSet = new Set(envAddrs.map(a => a.toLowerCase()))
      const allMatch = [...envSet].every(a => docSet.has(a))
      if (!allMatch) {
        console.error(`Genesis ${roleName} addresses do not match env vars (trust root)`)
        process.exit(1)
      }
      console.log(`  Genesis ${roleName} addresses match trust root (env vars)`)
    }

    // Genesis: verify signatures against the document's own roles
    verifyRoleSignatures(doc, doc.governance.roles, 'v1')
    console.log(`  v1 role signatures verified against own governance roles`)
  } else {
    // Version 2+: walk the full chain from v1
    console.log(`\n  Walking chain of trust from v1 to v${currentVersion}...`)

    // Track the trusted governance roles from the previous version
    let trustedRoles: GovernanceRole[] = []

    for (let v = 1; v <= currentVersion; v++) {
      const isHead = v === currentVersion
      let vDoc: RegistryDocument

      if (isHead) {
        vDoc = doc
      } else {
        const vFile = resolve(versionsDir, `${v}.json`)
        if (!existsSync(vFile)) {
          console.error(`  Missing version file ${v}.json — cannot verify chain of trust`)
          process.exit(1)
        }
        vDoc = JSON.parse(readFileSync(vFile, 'utf-8'))
      }

      // Verify integrity of this version
      verifyIntegrity(vDoc, `v${v}`)

      // For v1: verify ALL roles with env vars match the document
      if (v === 1) {
        for (const [roleName, envAddrs] of Object.entries(trustRootByRole)) {
          const docRole = vDoc.governance.roles.find((r: GovernanceRole) => r.role === roleName)
          if (!docRole) {
            console.error(`  v1 is missing ${roleName} role (expected from env vars)`)
            process.exit(1)
          }
          const docSet = new Set(docRole.addresses.map((a: string) => a.toLowerCase()))
          const envSet = new Set(envAddrs.map(a => a.toLowerCase()))
          const allMatch = [...envSet].every(a => docSet.has(a))
          if (!allMatch) {
            console.error(`  v1 ${roleName} addresses do not match trust root (env vars)`)
            process.exit(1)
          }
        }

        // Genesis verifies against its own roles
        verifyRoleSignatures(vDoc, vDoc.governance.roles, 'v1')
        console.log(`    v1: role signatures verified against trust root (own roles)`)
      } else {
        // Verify hash chain linkage
        const prevFile = resolve(versionsDir, `${v - 1}.json`)
        const prevDoc: RegistryDocument = JSON.parse(readFileSync(prevFile, 'utf-8'))
        if (vDoc.registry_metadata.prev_document_hash !== prevDoc.registry_metadata.document_hash) {
          console.error(`  Hash chain broken at v${v}: prev_document_hash doesn't match v${v - 1}`)
          process.exit(1)
        }

        // Verify signatures against the PREVIOUS version's governance roles
        verifyRoleSignatures(vDoc, trustedRoles, `v${v}`)
        console.log(`    v${v}: role signatures verified against v${v - 1} governance roles`)
      }

      // This version's governance roles become the trusted set for the next version
      trustedRoles = vDoc.governance.roles
    }

    console.log(`  Chain of trust verified: v1 -> v${currentVersion}`)
  }

  // ── Summary ────────────────────────────────────────────────────────────
  const sigsByRole = new Map<string, number>()
  for (const sig of doc.signatures) {
    sigsByRole.set(sig.role, (sigsByRole.get(sig.role) ?? 0) + 1)
  }
  const sigSummary = [...sigsByRole.entries()]
    .map(([role, count]) => `${role}:${count}`)
    .join(', ')

  console.log(`\nDocument is valid — ${doc.signatures.length} role signatures verified (${sigSummary})`)
  console.log(`  Governance roles: ${doc.governance.roles.map(r => `${r.role}(${r.quorum}/${r.addresses.length})`).join(', ')}`)

  // ── Version file consistency checks ─────────────────────────────────────
  if (existsSync(versionsDir)) {
    const versionFile = resolve(versionsDir, `${currentVersion}.json`)
    if (existsSync(versionFile)) {
      const versionDoc: RegistryDocument = JSON.parse(readFileSync(versionFile, 'utf-8'))
      if (versionDoc.registry_metadata.document_hash !== meta.document_hash) {
        console.error(`  Version file ${currentVersion}.json does not match registry.json`)
        process.exit(1)
      }
      console.log(`  Version file ${currentVersion}.json matches registry.json`)
    } else {
      console.warn(`  Version file ${currentVersion}.json not found`)
    }

    // List all available versions
    const files = readdirSync(versionsDir)
      .filter(f => /^\d+\.json$/.test(f))
      .map(f => parseInt(f, 10))
      .sort((a, b) => a - b)
    console.log(`  Available versions: [${files.join(', ')}]`)
  }
}

main()
