#!/usr/bin/env ts-node
// scripts/setup.ts — creates the genesis (version 1) registry document
// Run: npm run setup

import * as dotenv from 'dotenv'
dotenv.config()

import { computeDocumentHash, computeMerkleRoot, signHex } from '../src/common/crypto'
import { UnsignedDocument, RegistryDocument } from '../src/common/types'
import { CONFIG } from '../src/common/config'
import { writeFileSync, mkdirSync, existsSync } from 'fs'
import { dirname } from 'path'

async function main() {
  console.log('\n=== MPC Registry Setup — Genesis Document ===\n')

  // Validate private keys exist
  if (!CONFIG.DEV_ADMIN_KEY_0_PRIV || !CONFIG.DEV_ADMIN_KEY_1_PRIV) {
    console.error('ERROR: DEV_ADMIN_KEY_0_PRIV and DEV_ADMIN_KEY_1_PRIV must be set in .env')
    console.error('       Run: npm run keygen')
    process.exit(1)
  }

  const now: number = Math.floor(Date.now() / 1000)

  // Build the unsigned genesis document
  const unsigned: UnsignedDocument = {
    registryId:       CONFIG.REGISTRY_ID,
    version:          1,
    issuedAt:         now,
    expiresAt:        now + CONFIG.EXPIRY_SECONDS,
    nodes:            [],   // empty — no nodes enrolled yet
    merkleRoot:       computeMerkleRoot([]),
    prevDocumentHash: null, // genesis has no parent
    documentHash:     '',
  }
  unsigned.documentHash = computeDocumentHash(unsigned)

  console.log('Unsigned document:')
  console.log(`  registryId:   ${unsigned.registryId}`)
  console.log(`  version:      ${unsigned.version}`)
  console.log(`  documentHash: ${unsigned.documentHash}`)
  console.log()

  // Sign with admin 0 and admin 1 (2-of-3 threshold met)
  console.log('Signing with admin 0...')
  const sig0 = await signHex(unsigned.documentHash, CONFIG.DEV_ADMIN_KEY_0_PRIV)
  console.log(`  signature: ${sig0.substring(0, 32)}...`)

  console.log('Signing with admin 1...')
  const sig1 = await signHex(unsigned.documentHash, CONFIG.DEV_ADMIN_KEY_1_PRIV)
  console.log(`  signature: ${sig1.substring(0, 32)}...`)

  // Assemble the final signed document
  const signed: RegistryDocument = {
    ...unsigned,
    signatures: [
      { adminIndex: 0, signature: sig0 },
      { adminIndex: 1, signature: sig1 },
    ]
  }

  // Save to disk
  const dir = dirname(CONFIG.REGISTRY_FILE)
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  writeFileSync(CONFIG.REGISTRY_FILE, JSON.stringify(signed, null, 2))

  console.log(`\n✓ Genesis document saved to ${CONFIG.REGISTRY_FILE}`)
  console.log(`\n=== NEXT STEPS ===`)
  console.log(`1. Start the server:    npm run start:dev`)
  console.log(`2. Check health:        curl http://localhost:3000/api/registry/health`)
  console.log(`3. Read the guide:      cat TESTING.md`)
  console.log()
}

main().catch(e => { console.error(e); process.exit(1) })
