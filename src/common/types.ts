export type NodeRole   = 'USER_COSIGNER' | 'PROVIDER_COSIGNER' | 'RECOVERY_GUARDIAN'
export type NodeStatus = 'ACTIVE' | 'REVOKED'

export interface NodeRecord {
  node_id:      string
  ik_pub:       string
  ek_pub:       string
  role:        NodeRole
  status:      NodeStatus
  enrolled_at:  number
  revoked_at?:  number
}

export interface AdminSignature {
  admin_address: string
  signature:    string
}

export interface RegistryEndpoints {
  primary:    string
  mirrors:    string[]
  updated_at: string
}

export interface CeremonyBounds {
  min_signing_threshold: number
  max_signing_threshold: number
  min_participants:      number
  max_participants:      number
  allowed_protocols:     string[]
  allowed_curves:        string[]
}

export interface RegistryDocument {
  registry_id:            string
  version:               number
  issued_at:              number
  expires_at:             number
  admin_addresses:        string[]
  backoffice_service_pubkey: string | null
  ceremony_bounds:       CeremonyBounds
  endpoints:             RegistryEndpoints | null
  nodes:                 NodeRecord[]
  merkle_root:            string
  prev_document_hash:      string | null
  document_hash:          string
  signatures:            AdminSignature[]
}

export type UnsignedDocument = Omit<RegistryDocument, 'signatures'>

export interface HighWaterMark {
  registry_id:  string
  maxVersion:  number
  lastDocHash: string
  updatedAt:   number
}

export interface VerifyResult {
  valid:   boolean
  reason?: string
}
