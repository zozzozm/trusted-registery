#!/usr/bin/env ts-node
// scripts/sign.ts — signs a pending document draft using an Ethereum wallet
//
// Usage:
//   # Sign with admin 0:
//   ADMIN_INDEX=0 npm run sign
//
//   # Sign a specific draft file:
//   ADMIN_INDEX=1 DRAFT_FILE=./my-draft.json npm run sign
//
//   # Sign and immediately publish to the server:
//   ADMIN_INDEX=0 AUTO_PUBLISH=true npm run sign

import * as dotenv from 'dotenv'
dotenv.config()

import { ethers } from 'ethers'
import { signDocument, verifySingleSig } from '../src/common/crypto'
import { CONFIG } from '../src/common/config'
import { writeFileSync, readFileSync, existsSync } from 'fs'

async function main() {
  const adminIndex = parseInt(process.env.ADMIN_INDEX ?? '0')
  const draftFile  = process.env.DRAFT_FILE ?? `./data/draft-pending.json`
  const serverUrl  = process.env.SERVER_URL ?? `http://localhost:${CONFIG.PORT}/api`

  console.log(`\n=== Signing as Admin ${adminIndex} ===\n`)

  // Load private key
  const privKeys = [
    CONFIG.DEV_ADMIN_PRIVKEY_0,
    CONFIG.DEV_ADMIN_PRIVKEY_1,
    CONFIG.DEV_ADMIN_PRIVKEY_2,
  ]
  const privKey = privKeys[adminIndex]
  if (!privKey) {
    console.error(`DEV_ADMIN_PRIVKEY_${adminIndex} not set in .env`)
    process.exit(1)
  }

  const wallet = new ethers.Wallet(privKey)
  console.log(`Wallet address: ${wallet.address}`)

  // Fetch or load the draft
  let draft: any
  if (existsSync(draftFile)) {
    draft = JSON.parse(readFileSync(draftFile, 'utf-8'))
    console.log(`Loaded draft from ${draftFile}`)
  } else {
    console.log(`Fetching pending draft from ${serverUrl}/registry/pending...`)
    const res  = await fetch(`${serverUrl}/registry/pending`)
    draft      = await res.json() as any
    console.log(`Fetched draft v${draft.version}`)
  }

  console.log(`Document hash: ${draft.document_hash}`)
  console.log(`Registry ID:   ${draft.registry_id}`)
  console.log(`Version:       ${draft.version}`)
  console.log(`Nodes:         ${draft.nodes?.length ?? 0}`)
  console.log()

  // Sign the document using EIP-712 typed data (full document details shown in MetaMask)
  const { signatures: _sigs, ...unsignedDraft } = draft
  const sig = await signDocument(unsignedDraft, privKey)
  console.log(`Signature:  ${sig.substring(0,32)}...`)

  // Self-verify
  const ok = verifySingleSig(unsignedDraft, sig, wallet.address)
  console.log(`Self-verify: ${ok ? 'passed' : 'FAILED'}`)
  if (!ok) { console.error('Signature failed self-verification!'); process.exit(1) }

  // Post signature to the server if running
  if (!existsSync(draftFile)) {
    console.log(`\nPosting signature to server...`)
    const signRes = await fetch(`${serverUrl}/registry/pending/sign`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ admin_address: wallet.address, signature: sig, document_hash: draft.document_hash }),
    })
    if (signRes.ok) {
      draft = await signRes.json() as any
      console.log(`Signature accepted by server`)
    } else {
      const err = await signRes.json() as any
      console.error(`Server rejected signature:`, err.message)
      process.exit(1)
    }
  } else {
    // Merge signature into the draft file
    const existing = draft.signatures ?? []
    if (existing.find((s: any) => s.admin_address?.toLowerCase() === wallet.address.toLowerCase())) {
      console.log(`Admin ${wallet.address} already signed this draft`)
    } else {
      existing.push({ admin_address: wallet.address, signature: sig })
      draft.signatures = existing
    }
  }

  // Save
  writeFileSync(draftFile, JSON.stringify(draft, null, 2))
  console.log(`\nSaved to ${draftFile}`)
  console.log(`  Signatures so far: ${draft.signatures.length}/${CONFIG.MIN_SIGNATURES} required`)

  if (draft.signatures.length >= CONFIG.MIN_SIGNATURES) {
    console.log('\nThreshold reached! Ready to publish.')
    console.log(`\nPublish with:`)
    console.log(`  curl -X POST ${serverUrl}/registry/publish \\`)
    console.log(`    -H "Content-Type: application/json" \\`)
    console.log(`    -d @${draftFile}`)

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
        console.log(`Published! Version ${(result as any).version}`)
      } else {
        console.error('Publish failed:', result)
      }
    }
  } else {
    const needed = CONFIG.MIN_SIGNATURES - draft.signatures.length
    console.log(`\n${needed} more signature(s) needed. Share ${draftFile} with another admin.`)
    console.log(`  ADMIN_INDEX=1 DRAFT_FILE=${draftFile} npm run sign`)
  }
}

main().catch(e => { console.error(e); process.exit(1) })
