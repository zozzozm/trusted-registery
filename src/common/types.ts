// ─────────────────────────────────────────────────────────────────────────────
// Type definitions for the MPC Node Registry — v2 (role-based governance)
// ─────────────────────────────────────────────────────────────────────────────

// ── Node types ───────────────────────────────────────────────────────────────

export type NodeRole   = 'USER_COSIGNER' | 'PROVIDER_COSIGNER' | 'RECOVERY_GUARDIAN'
export type NodeStatus = 'ACTIVE' | 'REVOKED' | 'MAINTENANCE'

export interface IkRotationEntry {
  prev_ik_pub:  string
  new_ik_pub:   string
  rotated_at:   number
  reason:       string
  proof:        string
}

export interface NodeRecord {
  node_id:         string
  ik_pub:          string
  ek_pub:          string
  role:            NodeRole
  status:          NodeStatus
  enrolled_at:     number
  updated_at?:     number
  revoked_at?:     number | null
  ik_rotations?:   IkRotationEntry[]
}

// ── Governance ───────────────────────────────────────────────────────────────

/** Closed set of governance role names — no free-text */
export type GovernanceRoleName =
  | 'SYSTEM_ADMIN'
  | 'POLICY_COMPLIANCE'
  | 'TREASURY_OPS'
  | 'AUDIT_OBSERVER'

export const GOVERNANCE_ROLE_OPTIONS: { value: GovernanceRoleName; label: string }[] = [
  { value: 'POLICY_COMPLIANCE', label: 'Compliance & Policy Team' },
  { value: 'TREASURY_OPS',     label: 'Treasury Operations' },
  { value: 'AUDIT_OBSERVER',   label: 'Audit Observer' },
]

export interface GovernanceRole {
  role:          GovernanceRoleName
  display_name:  string
  addresses:     string[]
  quorum:        number
  features:      Record<string, any>
}

export interface Governance {
  roles: GovernanceRole[]
}

// ── Registry Metadata ────────────────────────────────────────────────────────

export interface RegistryEndpoints {
  primary: string
  mirrors: string[]
}

export interface RegistryMetadata {
  registry_id:        string
  version:            number
  issued_at:          number
  expires_at:         number
  updated_at:         string
  document_hash:      string
  merkle_root:        string
  prev_document_hash: string | null
  endpoints:          RegistryEndpoints | null
}

// ── Ceremony Config ──────────────────────────────────────────────────────────

export interface CeremonyConfig {
  global_threshold_t:   number
  max_participants_n:   number
  allowed_protocols:    string[]
  allowed_curves:       string[]
}

// ── Trusted Infrastructure ───────────────────────────────────────────────────

export interface TrustedInfrastructure {
  backoffice_pubkey: string | null
  market_oracle_pubkey:      string | null
  trusted_binary_hashes:      string[]
}

// ── Immutable Policies ───────────────────────────────────────────────────────

export interface ImmutablePolicies {
  max_withdrawal_usd_24h: number
  require_oracle_price:   boolean
  enforce_whitelist:       boolean
}

// ── Signatures ───────────────────────────────────────────────────────────────

export interface RoleSignature {
  role:       string
  signer:     string
  signature:  string
}

// ── Full Document ────────────────────────────────────────────────────────────

export interface RegistryDocument {
  registry_metadata:      RegistryMetadata
  governance:             Governance
  ceremony_config:        CeremonyConfig
  trusted_infrastructure: TrustedInfrastructure
  nodes:                  NodeRecord[]
  immutable_policies:     ImmutablePolicies
  signatures:             RoleSignature[]
}

export type UnsignedDocument = Omit<RegistryDocument, 'signatures'>

// ── Verification ─────────────────────────────────────────────────────────────

export interface VerifyResult {
  valid:   boolean
  reason?: string
}
