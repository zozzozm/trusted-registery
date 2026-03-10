// ─────────────────────────────────────────────────────────────────────────────
// Configuration — admin Ethereum addresses are the TRUST ROOT of the system
//
// In production: these are hardcoded in every MPC node binary.
// In development: loaded from environment variables.
//
// The private keys NEVER touch this server.
// They live in hardware wallets (MetaMask / Ledger / Trezor).
// ─────────────────────────────────────────────────────────────────────────────

import * as dotenv from 'dotenv'
import { ethers } from 'ethers'
dotenv.config()

function required(key: string): string {
  const v = process.env[key]
  if (!v) throw new Error(`Missing required env var: ${key}`)
  return v
}

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

  // ── Admin Ethereum addresses (TRUST ROOT) ─────────────────────────────────
  // These are checksummed Ethereum addresses — safe to store anywhere.
  get ADMIN_ADDRESSES(): string[] {
    return [
      required('ADMIN_ADDRESS_0'),
      required('ADMIN_ADDRESS_1'),
      required('ADMIN_ADDRESS_2'),
    ].map(a => ethers.getAddress(a))
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
