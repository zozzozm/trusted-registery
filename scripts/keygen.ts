#!/usr/bin/env ts-node
// scripts/keygen.ts — generates 3 admin Ethereum wallets and writes .env
// Run: npm run keygen

import { ethers } from 'ethers'
import { writeFileSync, existsSync, readFileSync } from 'fs'

async function main() {
  console.log('\n=== MPC Registry Admin Wallet Generator ===\n')

  const wallets = [
    ethers.Wallet.createRandom(),
    ethers.Wallet.createRandom(),
    ethers.Wallet.createRandom(),
  ]

  for (let i = 0; i < 3; i++) {
    const label = ['A','B','C'][i]
    console.log(`Admin ${label} (index ${i}):`)
    console.log(`  Address (safe to share): ${wallets[i].address}`)
    console.log(`  Private (hardware wallet in prod!): ${wallets[i].privateKey}`)
    console.log()
  }

  const envContent = [
    `# MPC Node Registry — Generated ${new Date().toISOString()}`,
    `# WARNING: DEV_ADMIN_PRIVKEY_* are for development only`,
    ``,
    `PORT=3000`,
    `NODE_ENV=development`,
    `REGISTRY_ID=dev-custody-v1`,
    `EXPIRY_SECONDS=604800`,
    `MIN_SIGNATURES=2`,
    ``,
    `# Admin Ethereum addresses — safe to store, hardcoded in node binaries`,
    `ADMIN_ADDRESS_0=${wallets[0].address}`,
    `ADMIN_ADDRESS_1=${wallets[1].address}`,
    `ADMIN_ADDRESS_2=${wallets[2].address}`,
    ``,
    `# Admin private keys — DEV ONLY, never in production`,
    `DEV_ADMIN_PRIVKEY_0=${wallets[0].privateKey}`,
    `DEV_ADMIN_PRIVKEY_1=${wallets[1].privateKey}`,
    `DEV_ADMIN_PRIVKEY_2=${wallets[2].privateKey}`,
    ``,
    `REGISTRY_FILE=./data/registry.json`,
  ].join('\n')

  if (existsSync('.env')) writeFileSync('.env.backup', readFileSync('.env'))
  writeFileSync('.env', envContent)

  console.log('Written to .env')
  console.log('Next: npm run setup')
}

main().catch(e => { console.error(e); process.exit(1) })
