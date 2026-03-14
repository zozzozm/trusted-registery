export type NodeRole   = 'USER_COSIGNER' | 'PROVIDER_COSIGNER' | 'RECOVERY_GUARDIAN'
export type NodeStatus = 'ACTIVE' | 'REVOKED'

export interface NodeRecord {
  nodeId:      string
  ikPub:       string
  ekPub:       string
  role:        NodeRole
  status:      NodeStatus
  enrolledAt:  number
  revokedAt?:  number
}

export interface AdminSignature {
  adminAddress: string
  signature:    string
}

export interface RegistryEndpoints {
  primary:    string
  mirrors:    string[]
  updated_at: string
}

export interface RegistryDocument {
  registryId:            string
  version:               number
  issuedAt:              number
  expiresAt:             number
  adminAddresses:        string[]
  backofficeServicePubkey: string | null
  allowedCurves:         string[]
  allowedProtocols:      string[]
  threshold:             number
  endpoints:             RegistryEndpoints | null
  nodes:                 NodeRecord[]
  merkleRoot:            string
  prevDocumentHash:      string | null
  documentHash:          string
  signatures:            AdminSignature[]
}

export type UnsignedDocument = Omit<RegistryDocument, 'signatures'>

export interface HighWaterMark {
  registryId:  string
  maxVersion:  number
  lastDocHash: string
  updatedAt:   number
}

export interface VerifyResult {
  valid:   boolean
  reason?: string
}
