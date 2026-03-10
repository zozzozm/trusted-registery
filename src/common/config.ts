// ─────────────────────────────────────────────────────────────────────────────
// Configuration
//
// Admin addresses are now stored in the registry document itself.
// Env vars ADMIN_ADDRESS_* are only used for genesis bootstrap.
// After genesis, the document is self-governing — admin rotation
// requires multi-sig approval from the current admins.
// ─────────────────────────────────────────────────────────────────────────────

import * as dotenv from 'dotenv'
import { ethers } from 'ethers'
dotenv.config()

function optional(key: string, fallback: string): string {
  return process.env[key] ?? fallback
}

export const CONFIG = {
  // ── Server ────────────────────────────────────────────────────────────────
  PORT:        parseInt(optional('PORT', '3000')),
  NODE_ENV:    optional('NODE_ENV', 'development'),

  // ── Registry identity ─────────────────────────────────────────────────────
  REGISTRY_ID:      optional('REGISTRY_ID', 'dev-custody-v1'),
  EXPIRY_SECONDS:   parseInt(optional('EXPIRY_SECONDS', String(30 * 24 * 3600))),

  // ── Genesis admin addresses (bootstrap only) ──────────────────────────────
  // Used only when creating the genesis document. After that, admin addresses
  // are read from the registry document itself.
  get GENESIS_ADMIN_ADDRESSES(): string[] {
    const addrs: string[] = []
    for (let i = 0; ; i++) {
      const v = process.env[`ADMIN_ADDRESS_${i}`]
      if (!v) break
      addrs.push(ethers.getAddress(v))
    }
    return addrs
  },

  // Minimum number of valid admin signatures to accept a document
  MIN_SIGNATURES: Math.max(2, parseInt(optional('MIN_SIGNATURES', '2')) || 2),

  // ── Dev-only: private keys for the sign script ────────────────────────────
  // NEVER set these in production. On prod, signing happens via MetaMask/Ledger.
  DEV_ADMIN_PRIVKEY_0: optional('DEV_ADMIN_PRIVKEY_0', ''),
  DEV_ADMIN_PRIVKEY_1: optional('DEV_ADMIN_PRIVKEY_1', ''),
  DEV_ADMIN_PRIVKEY_2: optional('DEV_ADMIN_PRIVKEY_2', ''),

  // ── Registry storage path ─────────────────────────────────────────────────
  REGISTRY_FILE: optional('REGISTRY_FILE', './data/registry.json'),
}
