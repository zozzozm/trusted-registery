#!/usr/bin/env ts-node
// scripts/setup.ts — creates an unsigned genesis (v1) registry document
//
// Reads admin addresses from ADMIN_ADDRESS_* env vars. No private keys needed.
// Signing happens via the web UI (MetaMask/Ledger).
//
// Usage: npm run setup

import * as dotenv from 'dotenv'
dotenv.config()

import { computeDocumentHash, computeMerkleRoot } from '../src/common/crypto'
import { UnsignedDocument } from '../src/common/types'
import { CONFIG } from '../src/common/config'
import { writeFileSync, mkdirSync, existsSync } from 'fs'
import { dirname } from 'path'

function main() {
  console.log('\n=== MPC Registry Setup — Genesis Document ===\n')

  const adminAddresses = CONFIG.GENESIS_ADMIN_ADDRESSES

  if (adminAddresses.length < CONFIG.SYSTEM_ADMIN_MIN_ADDRESSES) {
    console.error(
      `ERROR: Need at least ${CONFIG.SYSTEM_ADMIN_MIN_ADDRESSES} admin addresses in .env`,
    )
    console.error(`  Set ADMIN_ADDRESS_0, ADMIN_ADDRESS_1, ... in .env`)
    process.exit(1)
  }

  const now: number = Math.floor(Date.now() / 1000)
  const nowISO: string = new Date().toISOString()

  const unsigned: UnsignedDocument = {
    registry_metadata: {
      registry_id:        CONFIG.REGISTRY_ID,
      version:            1,
      issued_at:          now,
      expires_at:         now + CONFIG.EXPIRY_SECONDS,
      updated_at:         nowISO,
      document_hash:      '',
      merkle_root:        computeMerkleRoot([]),
      prev_document_hash: null,
      endpoints:          null,
    },
    governance: {
      roles: [
        {
          role:         'SYSTEM_ADMIN',
          display_name: 'System Administrators',
          addresses:    adminAddresses,
          quorum:       CONFIG.SYSTEM_ADMIN_QUORUM,
          features:     {},
        },
      ],
    },
    ceremony_config: {
      global_threshold_t:  2,
      max_participants_n:  9,
      allowed_protocols:   ['CGGMP21', 'FROST'],
      allowed_curves:      ['Secp256k1', 'Ed25519'],
    },
    trusted_infrastructure: {
      backoffice_pubkey: null,
      market_oracle_pubkey:      null,
      trusted_binary_hashes:      [],
    },
    nodes: [],
    immutable_policies: {
      max_withdrawal_usd_24h: 50000,
      require_oracle_price:   true,
      enforce_whitelist:      true,
    },
  }

  unsigned.registry_metadata.document_hash = computeDocumentHash(unsigned)

  const doc = { ...unsigned, signatures: [] }

  const dir = dirname(CONFIG.REGISTRY_FILE)
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  writeFileSync(CONFIG.REGISTRY_FILE, JSON.stringify(doc, null, 2))

  console.log('Unsigned genesis document created:')
  console.log(`  registry_id:    ${unsigned.registry_metadata.registry_id}`)
  console.log(`  version:        ${unsigned.registry_metadata.version}`)
  console.log(`  admins:         ${adminAddresses.length}`)
  adminAddresses.forEach((a, i) => console.log(`    [${i}] ${a}`))
  console.log(`  document_hash:  ${unsigned.registry_metadata.document_hash}`)
  console.log(`  merkle_root:    ${unsigned.registry_metadata.merkle_root}`)
  console.log()
  console.log(`Saved to ${CONFIG.REGISTRY_FILE}`)
  console.log()
  console.log('=== NEXT STEPS ===')
  console.log('1. Start the server:    npm run start:dev')
  console.log('2. Open signing page:   http://localhost:3000/sign.html')
  console.log('3. Connect MetaMask with admin wallets and sign the genesis document')
  console.log('4. Publish once 2-of-3 signatures are collected')
  console.log()
}

main()
