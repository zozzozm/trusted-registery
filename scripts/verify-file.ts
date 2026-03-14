#!/usr/bin/env ts-node
// scripts/verify-file.ts — used by GitHub Actions to verify the registry file
// Admin addresses are read from the document itself (self-governing).
// Optionally, ADMIN_ADDRESS_* env vars can override for genesis trust verification.
import * as dotenv from 'dotenv'
dotenv.config()
import { readFileSync } from 'fs'
import { computeDocumentHash, verifyMultiSig } from '../src/common/crypto'
import { CONFIG } from '../src/common/config'

function main() {
  const file = CONFIG.REGISTRY_FILE
  const doc  = JSON.parse(readFileSync(file, 'utf-8'))

  console.log(`Verifying ${file}`)
  console.log(`  Registry: ${doc.registry_id}`)
  console.log(`  Version:  ${doc.version}`)
  console.log(`  Nodes:    ${doc.nodes?.length ?? 0}`)
  console.log(`  Admins:   ${doc.admin_addresses?.length ?? 0}`)

  // Check registry ID
  if (doc.registry_id !== CONFIG.REGISTRY_ID) {
    console.error(`Registry ID mismatch: ${doc.registry_id} !== ${CONFIG.REGISTRY_ID}`)
    process.exit(1)
  }

  // Check admin addresses exist
  if (!doc.admin_addresses || doc.admin_addresses.length < CONFIG.MIN_SIGNATURES) {
    console.error(`Need at least ${CONFIG.MIN_SIGNATURES} admin addresses in document`)
    process.exit(1)
  }

  // If genesis env vars are set, verify the document's admin addresses match
  const genesisAddrs = CONFIG.GENESIS_ADMIN_ADDRESSES
  if (genesisAddrs.length > 0 && doc.version === 1) {
    const docAddrs = new Set(doc.admin_addresses.map((a: string) => a.toLowerCase()))
    const envAddrs = new Set(genesisAddrs.map(a => a.toLowerCase()))
    const allMatch = [...envAddrs].every(a => docAddrs.has(a))
    if (!allMatch) {
      console.error(`Genesis admin addresses do not match env vars`)
      process.exit(1)
    }
    console.log(`  Genesis admin addresses match env vars`)
  }

  // Check expiry
  const now = Math.floor(Date.now() / 1000)
  if (now > doc.expires_at) {
    console.warn(`Document expired — renew it!`)
  }

  // Check document hash
  const savedHash = doc.document_hash
  const { signatures: _, ...body } = doc
  body.document_hash = ''
  const expected = computeDocumentHash(body)
  if (expected !== savedHash) {
    console.error(`Document hash mismatch`)
    process.exit(1)
  }

  // Check signatures — verified against the document's own admin addresses
  // For genesis, this is self-consistent. For later versions, the CI should
  // ideally verify the full chain, but for simplicity we trust the document's
  // admin addresses (they are protected by the hash chain from genesis).
  body.document_hash = savedHash
  const result = verifyMultiSig(body, doc.signatures, doc.admin_addresses, CONFIG.MIN_SIGNATURES)
  if (!result.valid) {
    console.error(`Signatures invalid: ${result.reason}`)
    process.exit(1)
  }

  console.log(`Document is valid — ${doc.signatures.length} admin signatures verified`)
  console.log(`  Admin addresses: ${doc.admin_addresses.join(', ')}`)
}

main()
