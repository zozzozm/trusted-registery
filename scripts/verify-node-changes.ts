#!/usr/bin/env ts-node
// scripts/verify-node-changes.ts — CI script to validate node changes between versions
// Checks: status transitions, ik_rotations append-only, rotation proof validity
import * as dotenv from 'dotenv'
dotenv.config()
import { readFileSync, existsSync } from 'fs'
import { dirname, resolve } from 'path'
import { CONFIG } from '../src/common/config'
import { verifyRotationProof } from '../src/common/crypto'

// Valid status transitions
const VALID_TRANSITIONS: Record<string, string[]> = {
  ACTIVE:      ['MAINTENANCE', 'REVOKED'],
  MAINTENANCE: ['ACTIVE', 'REVOKED'],
  REVOKED:     [],  // terminal
}

function main() {
  const file = CONFIG.REGISTRY_FILE
  const doc  = JSON.parse(readFileSync(file, 'utf-8'))
  const version = doc.registry_metadata.version

  console.log(`Validating node changes for v${version}`)

  if (version <= 1) {
    console.log('  Genesis document — no previous version to compare')
    return
  }

  // Load previous version
  const versionsDir = resolve(dirname(file), 'versions')
  const prevFile = resolve(versionsDir, `${version - 1}.json`)
  if (!existsSync(prevFile)) {
    console.warn(`  Previous version file ${version - 1}.json not found — skipping node change validation`)
    return
  }

  const prevDoc = JSON.parse(readFileSync(prevFile, 'utf-8'))
  const prevNodes = new Map<string, any>()
  for (const node of (prevDoc.nodes ?? [])) {
    prevNodes.set(node.node_id, node)
  }

  let errors = 0

  for (const node of (doc.nodes ?? [])) {
    const prev = prevNodes.get(node.node_id)
    if (!prev) {
      // New node — must be ACTIVE
      if (node.status !== 'ACTIVE') {
        console.error(`  ERROR: New node ${node.node_id} has status ${node.status} (must be ACTIVE)`)
        errors++
      }
      continue
    }

    // Check status transition
    if (prev.status !== node.status) {
      const allowed = VALID_TRANSITIONS[prev.status] ?? []
      if (!allowed.includes(node.status)) {
        console.error(`  ERROR: Invalid status transition for ${node.node_id}: ${prev.status} -> ${node.status}`)
        errors++
      } else {
        console.log(`  Status transition: ${node.node_id} ${prev.status} -> ${node.status}`)
      }
    }

    // Check ik_rotations append-only
    const prevRotations = prev.ik_rotations ?? []
    const currRotations = node.ik_rotations ?? []

    if (currRotations.length < prevRotations.length) {
      console.error(`  ERROR: ik_rotations shrunk for ${node.node_id}: ${prevRotations.length} -> ${currRotations.length}`)
      errors++
    }

    // Verify existing entries haven't been modified
    for (let i = 0; i < prevRotations.length; i++) {
      if (i >= currRotations.length) break
      const a = prevRotations[i]
      const b = currRotations[i]
      if (a.prev_ik_pub !== b.prev_ik_pub || a.new_ik_pub !== b.new_ik_pub ||
          a.rotated_at !== b.rotated_at || a.proof !== b.proof) {
        console.error(`  ERROR: ik_rotations[${i}] was modified for ${node.node_id}`)
        errors++
      }
    }

    // Verify new rotation entries have valid proofs
    for (let i = prevRotations.length; i < currRotations.length; i++) {
      const entry = currRotations[i]
      console.log(`  New IK rotation for ${node.node_id}: ${entry.prev_ik_pub.substring(0, 16)}... -> ${entry.new_ik_pub.substring(0, 16)}...`)

      // Verify the chain: entry.prev_ik_pub should match the previous ik_pub
      const expectedPrev = i === 0 ? prev.ik_pub : currRotations[i - 1].new_ik_pub
      if (entry.prev_ik_pub !== expectedPrev) {
        console.error(`  ERROR: Rotation chain broken for ${node.node_id} at entry ${i}`)
        errors++
        continue
      }

      // Verify Ed25519 proof
      const valid = verifyRotationProof(entry.prev_ik_pub, entry.new_ik_pub, entry.rotated_at, entry.proof)
      if (!valid) {
        console.error(`  ERROR: Invalid rotation proof for ${node.node_id} at entry ${i}`)
        errors++
      } else {
        console.log(`    Rotation proof verified`)
      }
    }

    // Verify current ik_pub matches last rotation
    if (currRotations.length > 0) {
      const lastRotation = currRotations[currRotations.length - 1]
      if (node.ik_pub !== lastRotation.new_ik_pub) {
        console.error(`  ERROR: Node ${node.node_id} ik_pub doesn't match last rotation new_ik_pub`)
        errors++
      }
    }
  }

  // Check for deleted nodes (nodes in prev but not in current)
  for (const [nodeId, prev] of prevNodes) {
    const curr = (doc.nodes ?? []).find((n: any) => n.node_id === nodeId)
    if (!curr) {
      console.error(`  ERROR: Node ${nodeId} was deleted — nodes must never be removed, only revoked`)
      errors++
    }
  }

  if (errors > 0) {
    console.error(`\nNode change validation FAILED with ${errors} error(s)`)
    process.exit(1)
  }

  console.log(`Node change validation passed`)
}

main()
