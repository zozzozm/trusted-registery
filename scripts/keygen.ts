#!/usr/bin/env ts-node
// scripts/keygen.ts — generates 3 admin keypairs and writes .env
// Run: npm run keygen

import { generateKeypair } from '../src/common/crypto'
import { writeFileSync, existsSync, readFileSync } from 'fs'

async function main() {
  console.log('\n=== MPC Registry Admin Key Generator ===\n')

  const keys = await Promise.all([generateKeypair(), generateKeypair(), generateKeypair()])

  for (let i = 0; i < 3; i++) {
    const label = ['A','B','C'][i]
    console.log(`Admin ${label} (index ${i}):`)
    console.log(`  Public  (safe to share): ${keys[i].pubKey}`)
    console.log(`  Private (hardware key in prod!): ${keys[i].privKey}`)
    console.log()
  }

  const envContent = [
    `# MPC Node Registry — Generated ${new Date().toISOString()}`,
    `# WARNING: DEV_ADMIN_KEY_*_PRIV are for development only`,
    ``,
    `PORT=3000`,
    `NODE_ENV=development`,
    `REGISTRY_ID=dev-custody-v1`,
    `EXPIRY_SECONDS=604800`,
    `MIN_SIGNATURES=2`,
    ``,
    `# Admin public keys — safe to store, hardcoded in node binaries`,
    `ADMIN_KEY_0_PUB=${keys[0].pubKey}`,
    `ADMIN_KEY_1_PUB=${keys[1].pubKey}`,
    `ADMIN_KEY_2_PUB=${keys[2].pubKey}`,
    ``,
    `# Admin private keys — DEV ONLY, never in production`,
    `DEV_ADMIN_KEY_0_PRIV=${keys[0].privKey}`,
    `DEV_ADMIN_KEY_1_PRIV=${keys[1].privKey}`,
    `DEV_ADMIN_KEY_2_PRIV=${keys[2].privKey}`,
    ``,
    `REGISTRY_FILE=./data/registry.json`,
  ].join('\n')

  if (existsSync('.env')) writeFileSync('.env.backup', readFileSync('.env'))
  writeFileSync('.env', envContent)

  console.log('✓ Written to .env')
  console.log('Next: npm run setup')
}

main().catch(e => { console.error(e); process.exit(1) })
