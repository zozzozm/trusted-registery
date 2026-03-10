#!/usr/bin/env ts-node
// scripts/verify-file.ts — used by GitHub Actions to verify the registry file
import * as dotenv from 'dotenv'
dotenv.config()
import { readFileSync } from 'fs'
import { computeDocumentHash, computeMerkleRoot, verifyMultiSig } from '../src/common/crypto'
import { CONFIG } from '../src/common/config'

function main() {
  const file = CONFIG.REGISTRY_FILE
  const doc  = JSON.parse(readFileSync(file, 'utf-8'))

  console.log(`Verifying ${file}`)
  console.log(`  Registry: ${doc.registryId}`)
  console.log(`  Version:  ${doc.version}`)
  console.log(`  Nodes:    ${doc.nodes?.length ?? 0}`)

  // Check registry ID
  if (doc.registryId !== CONFIG.REGISTRY_ID) {
    console.error(`✗ Registry ID mismatch: ${doc.registryId} !== ${CONFIG.REGISTRY_ID}`)
    process.exit(1)
  }

  // Check expiry
  const now = Math.floor(Date.now() / 1000)
  if (now > doc.expiresAt) {
    console.warn(`⚠ Document expired — renew it!`)
  }

  // Check document hash
  const savedHash = doc.documentHash
  const { signatures: _, ...body } = doc
  body.documentHash = ''
  const expected = computeDocumentHash(body)
  if (expected !== savedHash) {
    console.error(`✗ Document hash mismatch`)
    process.exit(1)
  }

  // Check signatures
  const result = verifyMultiSig(savedHash, doc.signatures, CONFIG.ADMIN_KEYS, CONFIG.MIN_SIGNATURES)
  if (!result.valid) {
    console.error(`✗ Signatures invalid: ${result.reason}`)
    process.exit(1)
  }

  console.log(`✓ Document is valid — ${doc.signatures.length} admin signatures verified`)
}

main()
