export type NodeRole   = 'USER_COSIGNER' | 'PROVIDER_COSIGNER' | 'RECOVERY_GUARDIAN'
export type NodeStatus = 'ACTIVE' | 'REVOKED'

export interface NodeRecord {
  nodeId:      string
  ikPub:       string
  ekPub:       string
  role:        NodeRole
  walletScope: string[]
  status:      NodeStatus
  enrolledAt:  number
  revokedAt?:  number
}

export interface AdminSignature {
  adminAddress: string
  signature:    string
}

export interface RegistryDocument {
  registryId:            string
  version:               number
  issuedAt:              number
  expiresAt:             number
  adminAddresses:        string[]
  backofficeServicePubkey: string | null
  threshold:             number
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
