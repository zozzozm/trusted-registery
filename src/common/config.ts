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

  // ── Genesis role addresses (bootstrap / trust root) ─────────────────────
  // ADMIN_ADDRESS_* → SYSTEM_ADMIN role (required)
  // {ROLE_NAME}_ADDRESS_* → other roles (optional, e.g. POLICY_COMPLIANCE_ADDRESS_0)
  // Used for genesis bootstrap and CI verification trust root.
  get GENESIS_ADMIN_ADDRESSES(): string[] {
    return this.getGenesisRoleAddresses('ADMIN')
  },

  /** Read addresses for any role from env vars: {prefix}_ADDRESS_0, {prefix}_ADDRESS_1, ... */
  getGenesisRoleAddresses(prefix: string): string[] {
    const addrs: string[] = []
    for (let i = 0; ; i++) {
      const v = process.env[`${prefix}_ADDRESS_${i}`]
      if (!v) break
      addrs.push(ethers.getAddress(v))
    }
    return addrs
  },

  /** Map of role name → env var prefix for all genesis roles */
  GENESIS_ROLE_PREFIXES: {
    SYSTEM_ADMIN:       'ADMIN',
    POLICY_COMPLIANCE:  'POLICY_COMPLIANCE',
    TREASURY_OPS:       'TREASURY_OPS',
    AUDIT_OBSERVER:     'AUDIT_OBSERVER',
  } as Record<string, string>,

  // ── SYSTEM_ADMIN governance defaults ─────────────────────────────────────
  // Minimum number of addresses required for the SYSTEM_ADMIN role
  SYSTEM_ADMIN_MIN_ADDRESSES: 3,
  // Default quorum for SYSTEM_ADMIN role in the genesis document
  SYSTEM_ADMIN_QUORUM: 2,

  // ── Registry storage path ─────────────────────────────────────────────────
  REGISTRY_FILE: optional('REGISTRY_FILE', './data/registry.json'),

  // ── Versioned history directory (derived from REGISTRY_FILE) ─────────
  get VERSIONS_DIR(): string {
    const path = require('path')
    return path.resolve(path.dirname(this.REGISTRY_FILE), 'versions')
  },
}
