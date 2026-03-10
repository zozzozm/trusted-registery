#!/usr/bin/env ts-node
// scripts/setup.ts — creates the genesis (version 1) registry document
// Run: npm run setup

import * as dotenv from 'dotenv'
dotenv.config()

import { ethers } from 'ethers'
import { computeDocumentHash, computeMerkleRoot, buildSignMessage } from '../src/common/crypto'
import { UnsignedDocument, RegistryDocument } from '../src/common/types'
import { CONFIG } from '../src/common/config'
import { writeFileSync, mkdirSync, existsSync } from 'fs'
import { dirname } from 'path'

async function main() {
  console.log('\n=== MPC Registry Setup — Genesis Document ===\n')

  // Validate private keys exist
  if (!CONFIG.DEV_ADMIN_PRIVKEY_0 || !CONFIG.DEV_ADMIN_PRIVKEY_1) {
    console.error('ERROR: DEV_ADMIN_PRIVKEY_0 and DEV_ADMIN_PRIVKEY_1 must be set in .env')
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

  const message = buildSignMessage(unsigned.documentHash)

  // Sign with admin 0 and admin 1 (2-of-3 threshold met)
  const wallet0 = new ethers.Wallet(CONFIG.DEV_ADMIN_PRIVKEY_0)
  const wallet1 = new ethers.Wallet(CONFIG.DEV_ADMIN_PRIVKEY_1)

  console.log(`Signing with admin 0 (${wallet0.address})...`)
  const sig0 = await wallet0.signMessage(message)
  console.log(`  signature: ${sig0.substring(0, 32)}...`)

  console.log(`Signing with admin 1 (${wallet1.address})...`)
  const sig1 = await wallet1.signMessage(message)
  console.log(`  signature: ${sig1.substring(0, 32)}...`)

  // Assemble the final signed document
  const signed: RegistryDocument = {
    ...unsigned,
    signatures: [
      { adminAddress: wallet0.address, signature: sig0 },
      { adminAddress: wallet1.address, signature: sig1 },
    ]
  }

  // Save to disk
  const dir = dirname(CONFIG.REGISTRY_FILE)
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  writeFileSync(CONFIG.REGISTRY_FILE, JSON.stringify(signed, null, 2))

  console.log(`\nGenesis document saved to ${CONFIG.REGISTRY_FILE}`)
  console.log(`\n=== NEXT STEPS ===`)
  console.log(`1. Start the server:    npm run start:dev`)
  console.log(`2. Check health:        curl http://localhost:3000/api/registry/health`)
  console.log(`3. Open signing page:   http://localhost:3000/sign.html`)
  console.log()
}

main().catch(e => { console.error(e); process.exit(1) })
