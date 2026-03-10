// ─────────────────────────────────────────────────────────────────────────────
// Configuration — admin public keys are the TRUST ROOT of the system
//
// In production: these are hardcoded in every MPC node binary.
// In development: loaded from environment variables.
//
// The private keys NEVER touch this server.
// They live on hardware security keys (YubiKey / Ledger).
// ─────────────────────────────────────────────────────────────────────────────

import * as dotenv from 'dotenv'
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

  // ── Admin public keys (TRUST ROOT) ───────────────────────────────────────
  // These are Ed25519 public keys — safe to store anywhere.
  // The admin who runs `npm run keygen` produces these.
  get ADMIN_KEYS(): string[] {
    return [
      required('ADMIN_KEY_0_PUB'),
      required('ADMIN_KEY_1_PUB'),
      required('ADMIN_KEY_2_PUB'),
    ]
  },

  // Minimum number of valid admin signatures to accept a document
  MIN_SIGNATURES: parseInt(optional('MIN_SIGNATURES', '2')),

  // ── Dev-only: private keys for the sign script ────────────────────────────
  // NEVER set these in production. On prod, signing happens on hardware keys.
  DEV_ADMIN_KEY_0_PRIV: optional('DEV_ADMIN_KEY_0_PRIV', ''),
  DEV_ADMIN_KEY_1_PRIV: optional('DEV_ADMIN_KEY_1_PRIV', ''),
  DEV_ADMIN_KEY_2_PRIV: optional('DEV_ADMIN_KEY_2_PRIV', ''),

  // ── Registry storage path ─────────────────────────────────────────────────
  // In production: this is your GitHub repo path / IPFS content
  // In development: a local JSON file
  REGISTRY_FILE: optional('REGISTRY_FILE', './data/registry.json'),
}
