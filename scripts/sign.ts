#!/usr/bin/env ts-node
// scripts/sign.ts — signs a pending document draft fetched from the server
//
// Usage:
//   # Sign with admin 0:
//   ADMIN_INDEX=0 npm run sign
//
//   # Sign a specific draft file:
//   ADMIN_INDEX=1 DRAFT_FILE=./my-draft.json npm run sign
//
//   # Sign and immediately publish to the server:
//   ADMIN_INDEX=0 AUTO_SIGN_SECOND=true npm run sign

import * as dotenv from 'dotenv'
dotenv.config()

import { signHex, verifyHex } from '../src/common/crypto'
import { CONFIG } from '../src/common/config'
import { writeFileSync, readFileSync, existsSync } from 'fs'

async function main() {
  const adminIndex = parseInt(process.env.ADMIN_INDEX ?? '0')
  const draftFile  = process.env.DRAFT_FILE ?? `./data/draft-pending.json`
  const serverUrl  = process.env.SERVER_URL ?? `http://localhost:${CONFIG.PORT}/api`

  console.log(`\n=== Signing as Admin ${adminIndex} ===\n`)

  // Load private key
  const privKeys = [
    CONFIG.DEV_ADMIN_KEY_0_PRIV,
    CONFIG.DEV_ADMIN_KEY_1_PRIV,
    CONFIG.DEV_ADMIN_KEY_2_PRIV,
  ]
  const privKey = privKeys[adminIndex]
  if (!privKey) {
    console.error(`DEV_ADMIN_KEY_${adminIndex}_PRIV not set in .env`)
    process.exit(1)
  }

  // Fetch or load the draft
  let draft: any
  if (existsSync(draftFile)) {
    draft = JSON.parse(readFileSync(draftFile, 'utf-8'))
    console.log(`Loaded draft from ${draftFile}`)
  } else {
    console.log(`Fetching pending draft from ${serverUrl}/registry/pending...`)
    const res  = await fetch(`${serverUrl}/registry/pending`)
    draft      = await res.json()
    console.log(`Fetched draft v${draft.version}`)
  }

  console.log(`Document hash: ${draft.documentHash}`)
  console.log(`Registry ID:   ${draft.registryId}`)
  console.log(`Version:       ${draft.version}`)
  console.log(`Nodes:         ${draft.nodes?.length ?? 0}`)
  console.log()

  // Sign the documentHash
  const sig = await signHex(draft.documentHash, privKey)
  console.log(`Signature:  ${sig.substring(0,32)}...`)

  // Self-verify
  const pubKey = CONFIG.ADMIN_KEYS[adminIndex]
  const ok = verifyHex(draft.documentHash, sig, pubKey)
  console.log(`Self-verify: ${ok ? '✓ passed' : '✗ FAILED'}`)
  if (!ok) { console.error('Signature failed self-verification!'); process.exit(1) }

  // Merge signature into the draft
  const existing = draft.signatures ?? []
  if (existing.find((s: any) => s.adminIndex === adminIndex)) {
    console.log(`⚠️  Admin ${adminIndex} already signed this draft`)
  } else {
    existing.push({ adminIndex, signature: sig })
    draft.signatures = existing
  }

  // Save
  const outFile = draftFile.replace('.json', `-signed-${adminIndex}.json`)
  writeFileSync(outFile, JSON.stringify(draft, null, 2))
  console.log(`\n✓ Saved to ${outFile}`)
  console.log(`  Signatures so far: ${draft.signatures.length}/${CONFIG.MIN_SIGNATURES} required`)

  if (draft.signatures.length >= CONFIG.MIN_SIGNATURES) {
    console.log('\n✓ Threshold reached! Ready to publish.')
    console.log(`\nPublish with:`)
    console.log(`  curl -X POST ${serverUrl}/registry/publish \\`)
    console.log(`    -H "Content-Type: application/json" \\`)
    console.log(`    -d @${outFile}`)

    // Auto-publish if requested
    if (process.env.AUTO_PUBLISH === 'true') {
      console.log('\nAuto-publishing...')
      const res = await fetch(`${serverUrl}/registry/publish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(draft),
      })
      const result = await res.json()
      if (res.ok) {
        console.log(`✓ Published! Version ${result.version}`)
      } else {
        console.error('Publish failed:', result)
      }
    }
  } else {
    const needed = CONFIG.MIN_SIGNATURES - draft.signatures.length
    console.log(`\n${needed} more signature(s) needed. Share ${outFile} with another admin.`)
    console.log(`  ADMIN_INDEX=1 DRAFT_FILE=${outFile} npm run sign`)
  }
}

main().catch(e => { console.error(e); process.exit(1) })
