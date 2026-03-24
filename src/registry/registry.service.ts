// ─────────────────────────────────────────────────────────────────────────────
// Registry Service — role-based governance (v2)
// Manages the in-memory registry state and all verification logic
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, OnModuleInit, BadRequestException, NotFoundException, ConflictException } from '@nestjs/common'
import { readFileSync, writeFileSync, mkdirSync, renameSync, appendFileSync, readdirSync, existsSync } from 'fs'
import { dirname, resolve } from 'path'
import { ethers } from 'ethers'
import {
  RegistryDocument, UnsignedDocument, NodeRecord, RoleSignature,
  NodeRole, IkRotationEntry,
  GovernanceRole, GovernanceRoleName,
  CeremonyConfig, TrustedInfrastructure, ImmutablePolicies,
} from '../common/types'
import {
  computeDocumentHash, computeMerkleRoot,
  verifySingleSig, deriveNodeId, getEIP712Payload, verifyRotationProof,
  verifyRoleQuorum, verifyAllRoleQuorums,
} from '../common/crypto'
import { CONFIG } from '../common/config'

const VALID_ROLE_NAMES: GovernanceRoleName[] = [
  'SYSTEM_ADMIN', 'POLICY_COMPLIANCE', 'TREASURY_OPS', 'AUDIT_OBSERVER',
]

@Injectable()
export class RegistryService implements OnModuleInit {

  // ── In-memory state ───────────────────────────────────────────────────────
  private currentDoc: RegistryDocument | null = null
  private auditLog: Array<{ event: string; detail: object; at: number }> = []
  private stagedDraft: RegistryDocument | null = null
  private draftLocked = false

  onModuleInit() {
    this.loadFromDisk()
  }

  /**
   * Returns all governance roles from the current document.
   * If no published doc exists but a pending draft does, returns draft roles.
   * Falls back to a genesis SYSTEM_ADMIN role from env vars.
   */
  getActiveGovernanceRoles(): GovernanceRole[] {
    if (this.currentDoc?.governance?.roles?.length) {
      return this.currentDoc.governance.roles
    }
    if (this.stagedDraft?.governance?.roles?.length) {
      return this.stagedDraft.governance.roles
    }
    // Genesis fallback
    return [this._genesisSystemAdminRole()]
  }

  /**
   * Returns the SYSTEM_ADMIN role from the active governance.
   */
  getSystemAdminRole(): GovernanceRole {
    const roles = this.getActiveGovernanceRoles()
    const sa = roles.find(r => r.role === 'SYSTEM_ADMIN')
    if (!sa) {
      // Absolute fallback — should never happen with a well-formed document
      return this._genesisSystemAdminRole()
    }
    return sa
  }

  // ══════════════════════════════════════════════════════════════════════════
  // READ ENDPOINTS
  // ══════════════════════════════════════════════════════════════════════════

  /** GET /registry/current — returns the latest signed document */
  getCurrentDocument(): RegistryDocument {
    if (!this.currentDoc) throw new NotFoundException('Registry not initialized. Run the setup script first.')
    return this.currentDoc
  }

  /** GET /registry/pending — read-only, returns the staged draft */
  getPendingDocument(): RegistryDocument {
    if (!this.stagedDraft) throw new NotFoundException('No pending document. Create one with POST /registry/pending first.')
    return this.stagedDraft
  }

  /** POST /registry/pending — create a new pending draft from current published nodes */
  createPendingDocument(): RegistryDocument {
    if (this.stagedDraft) throw new ConflictException('A pending document already exists. DELETE /registry/pending first.')

    const nodes = this.currentDoc ? [...this.currentDoc.nodes] : []
    const draft = this._buildDraft(nodes)
    this.stagedDraft = { ...draft, signatures: [] }
    return this.stagedDraft
  }

  /** GET /registry/pending/message — returns the EIP-712 typed data payload for signing */
  getPendingSignPayload(): object {
    if (!this.stagedDraft) throw new NotFoundException('No pending document.')
    const { signatures: _, ...unsigned } = this.stagedDraft
    return getEIP712Payload(unsigned)
  }

  /** POST /registry/pending/sign — add one role signature to the staged draft */
  signPendingDocument(body: { role: string; signer: string; signature: string; document_hash?: string }): RegistryDocument {
    if (!this.stagedDraft) throw new NotFoundException('No pending document. Call GET /registry/pending first.')

    const { role, signer, signature, document_hash } = body

    // If caller provided document_hash, verify it matches the current draft
    if (document_hash && document_hash !== this.stagedDraft.registry_metadata.document_hash) {
      throw new ConflictException('document_hash does not match the current draft. The draft may have been modified.')
    }

    // Validate role name
    if (!role || !VALID_ROLE_NAMES.includes(role.toUpperCase() as GovernanceRoleName)) {
      throw new BadRequestException(`Invalid role: ${role}. Must be one of: ${VALID_ROLE_NAMES.join(', ')}`)
    }
    const normalizedRole = role.toUpperCase()

    // Determine whether this is genesis
    const isGenesis = this.stagedDraft.registry_metadata.version === 1 && !this.currentDoc

    // Find the role to verify the signer against
    let verifyRole: GovernanceRole | undefined

    if (isGenesis) {
      // For genesis, signers come from the draft's own roles
      verifyRole = this.stagedDraft.governance.roles.find(
        r => r.role.toUpperCase() === normalizedRole,
      )
    } else {
      // For post-genesis, signers come from the PREVIOUS (current published) version's roles
      verifyRole = this.currentDoc!.governance.roles.find(
        r => r.role.toUpperCase() === normalizedRole,
      )
      // Also allow signers from the draft's role (e.g. if new role added)
      if (!verifyRole) {
        verifyRole = this.stagedDraft.governance.roles.find(
          r => r.role.toUpperCase() === normalizedRole,
        )
      }
    }

    if (!verifyRole) {
      throw new BadRequestException(`Role ${normalizedRole} not found in ${isGenesis ? 'draft' : 'published'} governance`)
    }

    // Check signer is in the role's address list
    const isKnownSigner = verifyRole.addresses.some(
      a => a.toLowerCase() === signer.toLowerCase(),
    )
    if (!isKnownSigner) {
      throw new BadRequestException(`Signer ${signer} is not in the ${normalizedRole} address list`)
    }

    // Check for duplicate signer within the same role
    if (this.stagedDraft.signatures.some(
      s => s.role.toUpperCase() === normalizedRole && s.signer.toLowerCase() === signer.toLowerCase(),
    )) {
      throw new ConflictException(`Signer ${signer} has already signed for role ${normalizedRole}`)
    }

    // Validate signature format (0x + 130 hex chars)
    if (!/^0x[0-9a-f]{130}$/i.test(signature)) {
      throw new BadRequestException('Signature must be 0x-prefixed 65 bytes hex (132 chars)')
    }

    // Verify signature against full document using ecrecover
    const { signatures: _sigs, ...unsignedDraft } = this.stagedDraft
    const ok = verifySingleSig(unsignedDraft, signature, signer)
    if (!ok) throw new BadRequestException('Signature verification failed')

    this.stagedDraft.signatures.push({ role: normalizedRole, signer, signature })

    // Lock draft after first signature to prevent TOCTOU
    this.draftLocked = true

    return this.stagedDraft
  }

  /** POST /registry/governance/propose — add or modify a single governance role */
  proposeGovernanceRole(body: { role: GovernanceRoleName; display_name: string; addresses: string[]; quorum: number; features?: Record<string, any> }): RegistryDocument {
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    const roleName = body.role?.toUpperCase() as GovernanceRoleName
    if (!VALID_ROLE_NAMES.includes(roleName)) {
      throw new BadRequestException(`Invalid role name: ${body.role}. Must be one of: ${VALID_ROLE_NAMES.join(', ')}`)
    }

    // Validate addresses
    const addresses = body.addresses.map(a => {
      try { return ethers.getAddress(a) }
      catch { throw new BadRequestException(`Invalid Ethereum address: ${a}`) }
    })

    // Check for duplicate addresses within the role
    const unique = new Set(addresses.map(a => a.toLowerCase()))
    if (unique.size !== addresses.length) {
      throw new BadRequestException('Duplicate addresses within the role')
    }

    // SYSTEM_ADMIN specific validations
    if (roleName === 'SYSTEM_ADMIN') {
      if (addresses.length < CONFIG.SYSTEM_ADMIN_MIN_ADDRESSES) {
        throw new BadRequestException(`SYSTEM_ADMIN requires at least ${CONFIG.SYSTEM_ADMIN_MIN_ADDRESSES} addresses`)
      }
      if (!Number.isInteger(body.quorum) || body.quorum < CONFIG.SYSTEM_ADMIN_QUORUM) {
        throw new BadRequestException(`SYSTEM_ADMIN quorum must be >= ${CONFIG.SYSTEM_ADMIN_QUORUM}`)
      }
    }

    // General quorum validation
    if (!Number.isInteger(body.quorum) || body.quorum < 1) {
      throw new BadRequestException('Quorum must be an integer >= 1')
    }
    if (body.quorum > addresses.length) {
      throw new BadRequestException('Quorum cannot exceed number of addresses')
    }

    // Auto-create draft if none exists
    if (!this.stagedDraft) {
      const nodes = this.currentDoc ? [...this.currentDoc.nodes] : []
      const base = this._buildDraft(nodes)
      this.stagedDraft = { ...base, signatures: [] }
    }

    // Build the role object
    const newRole: GovernanceRole = {
      role: roleName,
      display_name: body.display_name || roleName,
      addresses,
      quorum: body.quorum,
      features: body.features ?? {},
    }

    // Replace existing role or add new one
    const existingIndex = this.stagedDraft.governance.roles.findIndex(
      r => r.role.toUpperCase() === roleName,
    )
    if (existingIndex >= 0) {
      this.stagedDraft.governance.roles[existingIndex] = newRole
    } else {
      this.stagedDraft.governance.roles.push(newRole)
    }

    this._refreshDraftHash()
    this.audit('GOVERNANCE_ROLE_PROPOSED', { role: roleName, addresses, quorum: body.quorum })
    return this.stagedDraft
  }

  /** POST /registry/infrastructure/propose — propose trusted infrastructure changes */
  proposeInfrastructure(body: Partial<TrustedInfrastructure>): RegistryDocument {
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    // Validate hex address formats if provided
    if (body.backoffice_pubkey !== undefined && body.backoffice_pubkey !== null) {
      if (!/^0x[0-9a-fA-F]{40}$/.test(body.backoffice_pubkey)) {
        throw new BadRequestException('backoffice_pubkey must be a valid Ethereum address (0x + 40 hex chars)')
      }
    }
    if (body.market_oracle_pubkey !== undefined && body.market_oracle_pubkey !== null) {
      if (!/^0x[0-9a-fA-F]{40}$/.test(body.market_oracle_pubkey)) {
        throw new BadRequestException('market_oracle_pubkey must be a valid Ethereum address (0x + 40 hex chars)')
      }
    }
    if (body.trusted_binary_hashes !== undefined) {
      if (!Array.isArray(body.trusted_binary_hashes)) {
        throw new BadRequestException('trusted_binary_hashes must be an array')
      }
      for (const h of body.trusted_binary_hashes) {
        if (!/^[0-9a-f]{64}$/i.test(h)) {
          throw new BadRequestException(`Invalid binary hash: ${h} (must be 64 hex chars)`)
        }
      }
    }

    // Auto-create draft if none exists
    if (!this.stagedDraft) {
      const nodes = this.currentDoc ? [...this.currentDoc.nodes] : []
      const base = this._buildDraft(nodes)
      this.stagedDraft = { ...base, signatures: [] }
    }

    // Apply partial updates
    if (body.backoffice_pubkey !== undefined) {
      this.stagedDraft.trusted_infrastructure.backoffice_pubkey = body.backoffice_pubkey
    }
    if (body.market_oracle_pubkey !== undefined) {
      this.stagedDraft.trusted_infrastructure.market_oracle_pubkey = body.market_oracle_pubkey
    }
    if (body.trusted_binary_hashes !== undefined) {
      this.stagedDraft.trusted_infrastructure.trusted_binary_hashes = body.trusted_binary_hashes
    }

    this._refreshDraftHash()
    this.audit('INFRASTRUCTURE_PROPOSED', { changes: body })
    return this.stagedDraft
  }

  /** POST /registry/ceremony-config/propose — propose ceremony configuration */
  proposeCeremonyConfig(body: { ceremony_config: CeremonyConfig }): RegistryDocument {
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    const cc = body.ceremony_config
    if (!cc || typeof cc !== 'object') {
      throw new BadRequestException('ceremony_config must be an object')
    }
    if (!Array.isArray(cc.allowed_curves) || cc.allowed_curves.length === 0) {
      throw new BadRequestException('ceremony_config.allowed_curves must be a non-empty array')
    }
    if (!Array.isArray(cc.allowed_protocols) || cc.allowed_protocols.length === 0) {
      throw new BadRequestException('ceremony_config.allowed_protocols must be a non-empty array')
    }
    if (!Number.isInteger(cc.global_threshold_t) || cc.global_threshold_t < 2) {
      throw new BadRequestException('ceremony_config.global_threshold_t must be an integer >= 2')
    }
    if (!Number.isInteger(cc.max_participants_n) || cc.max_participants_n < 2) {
      throw new BadRequestException('ceremony_config.max_participants_n must be an integer >= 2')
    }
    if (cc.max_participants_n < cc.global_threshold_t) {
      throw new BadRequestException('ceremony_config.max_participants_n must be >= global_threshold_t')
    }

    // Auto-create draft if none exists
    if (!this.stagedDraft) {
      const nodes = this.currentDoc ? [...this.currentDoc.nodes] : []
      const base = this._buildDraft(nodes)
      this.stagedDraft = { ...base, signatures: [] }
    }

    this.stagedDraft.ceremony_config = cc
    this._refreshDraftHash()

    this.audit('CEREMONY_CONFIG_PROPOSED', { ceremony_config: cc })
    return this.stagedDraft
  }

  /** POST /registry/immutable-policies/propose — propose immutable policies */
  proposeImmutablePolicies(body: { immutable_policies: ImmutablePolicies }): RegistryDocument {
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    const ip = body.immutable_policies
    if (!ip || typeof ip !== 'object') {
      throw new BadRequestException('immutable_policies must be an object')
    }
    if (typeof ip.max_withdrawal_usd_24h !== 'number' || ip.max_withdrawal_usd_24h < 0) {
      throw new BadRequestException('immutable_policies.max_withdrawal_usd_24h must be a non-negative number')
    }
    if (typeof ip.require_oracle_price !== 'boolean') {
      throw new BadRequestException('immutable_policies.require_oracle_price must be a boolean')
    }
    if (typeof ip.enforce_whitelist !== 'boolean') {
      throw new BadRequestException('immutable_policies.enforce_whitelist must be a boolean')
    }

    // Auto-create draft if none exists
    if (!this.stagedDraft) {
      const nodes = this.currentDoc ? [...this.currentDoc.nodes] : []
      const base = this._buildDraft(nodes)
      this.stagedDraft = { ...base, signatures: [] }
    }

    this.stagedDraft.immutable_policies = ip
    this._refreshDraftHash()

    this.audit('IMMUTABLE_POLICIES_PROPOSED', { immutable_policies: ip })
    return this.stagedDraft
  }

  /** POST /registry/endpoints/propose — propose registry endpoints */
  proposeEndpoints(body: { primary: string; mirrors?: string[] }): RegistryDocument {
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    const urlPattern = /^https?:\/\/.+/
    if (!urlPattern.test(body.primary)) {
      throw new BadRequestException('primary must be a valid HTTP(S) URL')
    }
    const mirrors = body.mirrors ?? []
    for (const m of mirrors) {
      if (!urlPattern.test(m)) {
        throw new BadRequestException(`Invalid mirror URL: ${m}`)
      }
    }

    // Check for duplicates between primary and mirrors
    const allUrls = [body.primary, ...mirrors]
    if (new Set(allUrls).size !== allUrls.length) {
      throw new BadRequestException('Duplicate URLs in primary/mirrors')
    }

    // Auto-create draft if none exists
    if (!this.stagedDraft) {
      const nodes = this.currentDoc ? [...this.currentDoc.nodes] : []
      const base = this._buildDraft(nodes)
      this.stagedDraft = { ...base, signatures: [] }
    }

    this.stagedDraft.registry_metadata.endpoints = {
      primary: body.primary,
      mirrors: mirrors,
    }
    this._refreshDraftHash()

    this.audit('ENDPOINTS_PROPOSED', { endpoints: this.stagedDraft.registry_metadata.endpoints })
    return this.stagedDraft
  }

  /** GET /registry/node/:nodeId */
  getNode(nodeId: string): NodeRecord {
    const node = this.currentDoc?.nodes.find(n => n.node_id === nodeId)
    if (!node) throw new NotFoundException(`Node ${nodeId} not found`)
    return node
  }

  /** GET /registry/nodes?role=yyy */
  getNodes(role?: string): NodeRecord[] {
    const nodes = this.currentDoc?.nodes ?? []
    return nodes.filter(n => {
      if (role && n.role !== role) return false
      return true
    })
  }

  /** GET /registry/health */
  getHealth() {
    const doc = this.currentDoc
    const hasPendingGenesis = !doc && !!this.stagedDraft
    const roles = this.getActiveGovernanceRoles()

    return {
      status:         'ok',
      initialized:    !!doc,
      pendingGenesis: hasPendingGenesis,
      registry_id:    CONFIG.REGISTRY_ID,
      version:        doc?.registry_metadata.version ?? (this.stagedDraft?.registry_metadata.version ?? 0),
      totalNodes:     doc?.nodes.length ?? 0,
      activeNodes:    doc?.nodes.filter(n => n.status === 'ACTIVE').length ?? 0,
      expires_at:     doc?.registry_metadata.expires_at ?? null,
      expired:        doc ? Math.floor(Date.now() / 1000) > doc.registry_metadata.expires_at : null,
      governance_roles: roles.map(r => ({
        role:         r.role,
        display_name: r.display_name,
        addresses:    r.addresses.map((a, i) => ({ index: i, address: a })),
        quorum:       r.quorum,
      })),
      governanceSource: doc?.governance?.roles?.length
        ? 'document'
        : hasPendingGenesis ? 'pending-genesis' : 'genesis-env',
    }
  }

  /** GET /registry/audit */
  getAuditLog() {
    return this.auditLog.slice().reverse()
  }

  /** GET /registry/versions — list available version numbers */
  getVersionList(): number[] {
    try {
      const files: string[] = readdirSync(CONFIG.VERSIONS_DIR)
      return files
        .filter(f => /^\d+\.json$/.test(f))
        .map(f => parseInt(f, 10))
        .sort((a, b) => a - b)
    } catch {
      return []
    }
  }

  /** GET /registry/versions/:version — fetch a specific historical version */
  getVersion(version: number): RegistryDocument {
    const versionFile = resolve(CONFIG.VERSIONS_DIR, `${version}.json`)
    if (!existsSync(versionFile)) {
      throw new NotFoundException(`Version ${version} not found`)
    }
    return JSON.parse(readFileSync(versionFile, 'utf-8'))
  }

  // ══════════════════════════════════════════════════════════════════════════
  // VERIFY ENDPOINT
  // ══════════════════════════════════════════════════════════════════════════

  verifyDocument(doc: any): object {
    const steps: Array<{ step: string; passed: boolean; detail: string }> = []

    const pass = (step: string, detail: string) => steps.push({ step, passed: true, detail })
    const fail = (step: string, detail: string) => steps.push({ step, passed: false, detail })

    // Step 1 — Structure
    const requiredSections = [
      'registry_metadata', 'governance', 'ceremony_config',
      'trusted_infrastructure', 'nodes', 'immutable_policies', 'signatures',
    ]
    const missingSections = requiredSections.filter(f => doc[f] === undefined)
    if (missingSections.length > 0) {
      fail('structure', `Missing sections: ${missingSections.join(', ')}`)
      return { valid: false, steps }
    }
    const requiredMetaFields = [
      'registry_id', 'version', 'issued_at', 'expires_at',
      'document_hash', 'merkle_root', 'prev_document_hash',
    ]
    const missingMeta = requiredMetaFields.filter(f => doc.registry_metadata[f] === undefined)
    if (missingMeta.length > 0) {
      fail('structure', `Missing registry_metadata fields: ${missingMeta.join(', ')}`)
      return { valid: false, steps }
    }
    pass('structure', 'All required sections and fields present')

    // Step 2 — Registry ID
    if (doc.registry_metadata.registry_id !== CONFIG.REGISTRY_ID) {
      fail('registry_id', `Got "${doc.registry_metadata.registry_id}", expected "${CONFIG.REGISTRY_ID}"`)
    } else {
      pass('registry_id', `Registry ID matches: "${doc.registry_metadata.registry_id}"`)
    }

    // Step 3 — Expiry
    const now = Math.floor(Date.now() / 1000)
    if (now > doc.registry_metadata.expires_at) {
      fail('expiry', `Document expired at ${new Date(doc.registry_metadata.expires_at * 1000).toISOString()}`)
    } else {
      const secsLeft = doc.registry_metadata.expires_at - now
      pass('expiry', `Valid for ${Math.floor(secsLeft / 3600)}h ${Math.floor((secsLeft % 3600) / 60)}m more`)
    }

    // Step 4 — Document hash integrity
    const { signatures: _sigs, ...unsignedDoc } = doc
    const expectedHash = computeDocumentHash(unsignedDoc as UnsignedDocument)
    if (expectedHash !== doc.registry_metadata.document_hash) {
      fail('document_hash', `Recomputed: ${expectedHash.substring(0, 16)}...\nDocument has: ${doc.registry_metadata.document_hash.substring(0, 16)}...`)
    } else {
      pass('document_hash', `Hash verified: ${doc.registry_metadata.document_hash.substring(0, 16)}...`)
    }

    // Step 5 — Merkle root
    const nodes = Array.isArray(doc.nodes) ? doc.nodes : []
    const sorted = [...nodes].sort((a: any, b: any) => a.node_id.localeCompare(b.node_id))
    const expectedRoot = computeMerkleRoot(sorted)
    if (expectedRoot !== doc.registry_metadata.merkle_root) {
      fail('merkle_root', `Recomputed: ${expectedRoot.substring(0, 16)}...\nDocument has: ${doc.registry_metadata.merkle_root.substring(0, 16)}...`)
    } else {
      pass('merkle_root', `Merkle root verified: ${doc.registry_metadata.merkle_root.substring(0, 16)}...`)
    }

    // Step 6 — Hash chain
    if (this.currentDoc) {
      if (doc.registry_metadata.version <= this.currentDoc.registry_metadata.version) {
        fail('hashChain', `Version ${doc.registry_metadata.version} <= current ${this.currentDoc.registry_metadata.version} — rollback`)
      } else if (doc.registry_metadata.prev_document_hash !== this.currentDoc.registry_metadata.document_hash) {
        fail('hashChain', `prev_document_hash does not match current document hash`)
      } else {
        pass('hashChain', `Chain intact: v${this.currentDoc.registry_metadata.version} -> v${doc.registry_metadata.version}`)
      }
    } else {
      pass('hashChain', 'No previous version — this is the genesis document')
    }

    // Step 7 — SYSTEM_ADMIN validation
    const docRoles: GovernanceRole[] = doc.governance?.roles ?? []
    const systemAdmin = docRoles.find((r: GovernanceRole) => r.role === 'SYSTEM_ADMIN')
    if (!systemAdmin) {
      fail('systemAdmin', 'SYSTEM_ADMIN role is missing from governance')
    } else if (!Array.isArray(systemAdmin.addresses) || systemAdmin.addresses.length < CONFIG.SYSTEM_ADMIN_MIN_ADDRESSES) {
      fail('systemAdmin', `SYSTEM_ADMIN needs >= ${CONFIG.SYSTEM_ADMIN_MIN_ADDRESSES} addresses, got ${systemAdmin.addresses?.length ?? 0}`)
    } else if (!Number.isInteger(systemAdmin.quorum) || systemAdmin.quorum < CONFIG.SYSTEM_ADMIN_QUORUM) {
      fail('systemAdmin', `SYSTEM_ADMIN quorum must be >= ${CONFIG.SYSTEM_ADMIN_QUORUM}, got ${systemAdmin.quorum}`)
    } else {
      pass('systemAdmin', `SYSTEM_ADMIN: ${systemAdmin.addresses.length} addresses, quorum ${systemAdmin.quorum}`)
    }

    // Step 8 — Per-role quorum verification
    const isGenesis = doc.registry_metadata.version === 1 && !this.currentDoc
    const docForSig = { ...unsignedDoc, registry_metadata: { ...doc.registry_metadata } }

    if (isGenesis) {
      // For genesis, verify all roles against the document's own roles
      const qResult = verifyAllRoleQuorums(docForSig, doc.signatures, docRoles)
      if (!qResult.valid) {
        fail('roleQuorum', qResult.reason!)
      } else {
        const sigSummary = (doc.signatures as RoleSignature[])
          .map(s => `${s.role}:${s.signer.substring(0, 10)}...`)
          .join(', ')
        pass('roleQuorum', `All role quorums met (genesis). Signers: ${sigSummary}`)
      }
    } else {
      // For post-genesis:
      // - SYSTEM_ADMIN: verify against PREVIOUS version's SYSTEM_ADMIN addresses
      // - All other roles from PREVIOUS version: verify against their previous addresses
      const prevRoles: GovernanceRole[] = this.currentDoc!.governance.roles
      let roleQuorumFailed = false

      for (const prevRole of prevRoles) {
        const result = verifyRoleQuorum(docForSig, doc.signatures, prevRole)
        if (!result.valid) {
          fail('roleQuorum', result.reason!)
          roleQuorumFailed = true
          break
        }
      }

      if (!roleQuorumFailed) {
        const sigSummary = (doc.signatures as RoleSignature[])
          .map(s => `${s.role}:${s.signer.substring(0, 10)}...`)
          .join(', ')
        pass('roleQuorum', `All role quorums met. Signers: ${sigSummary}`)
      }
    }

    // Step 9 — Ceremony config validation
    const cc = doc.ceremony_config
    if (!cc || typeof cc !== 'object') {
      fail('ceremonyConfig', 'ceremony_config must be an object')
    } else if (!Array.isArray(cc.allowed_curves) || cc.allowed_curves.length === 0) {
      fail('ceremonyConfig', 'ceremony_config.allowed_curves must be a non-empty array')
    } else if (!Array.isArray(cc.allowed_protocols) || cc.allowed_protocols.length === 0) {
      fail('ceremonyConfig', 'ceremony_config.allowed_protocols must be a non-empty array')
    } else if (!Number.isInteger(cc.global_threshold_t) || cc.global_threshold_t < 2) {
      fail('ceremonyConfig', 'ceremony_config.global_threshold_t must be an integer >= 2')
    } else if (!Number.isInteger(cc.max_participants_n) || cc.max_participants_n < 2) {
      fail('ceremonyConfig', 'ceremony_config.max_participants_n must be an integer >= 2')
    } else if (cc.max_participants_n < cc.global_threshold_t) {
      fail('ceremonyConfig', 'ceremony_config.max_participants_n must be >= global_threshold_t')
    } else {
      pass('ceremonyConfig', `Curves: [${cc.allowed_curves.join(', ')}], Protocols: [${cc.allowed_protocols.join(', ')}], Threshold: ${cc.global_threshold_t}, Max: ${cc.max_participants_n}`)
    }

    // Step 10 — Endpoints validation
    const endpoints = doc.registry_metadata.endpoints ?? null
    if (endpoints) {
      const urlPattern = /^https?:\/\/.+/
      if (!endpoints.primary || !urlPattern.test(endpoints.primary)) {
        fail('endpoints', `Invalid primary URL: ${endpoints.primary}`)
      } else if (!Array.isArray(endpoints.mirrors)) {
        fail('endpoints', 'mirrors must be an array')
      } else {
        const badMirror = endpoints.mirrors.find((m: string) => !urlPattern.test(m))
        if (badMirror) {
          fail('endpoints', `Invalid mirror URL: ${badMirror}`)
        } else {
          const allUrls = [endpoints.primary, ...endpoints.mirrors]
          if (new Set(allUrls).size !== allUrls.length) {
            fail('endpoints', 'Duplicate URLs in primary/mirrors')
          } else {
            pass('endpoints', `primary: ${endpoints.primary}, ${endpoints.mirrors.length} mirror(s)`)
          }
        }
      }
    } else {
      pass('endpoints', 'No endpoints configured')
    }

    // Step 11 — Immutable policies validation
    const ip = doc.immutable_policies
    if (!ip || typeof ip !== 'object') {
      fail('immutablePolicies', 'immutable_policies must be an object')
    } else if (typeof ip.max_withdrawal_usd_24h !== 'number' || ip.max_withdrawal_usd_24h < 0) {
      fail('immutablePolicies', 'immutable_policies.max_withdrawal_usd_24h must be a non-negative number')
    } else if (typeof ip.require_oracle_price !== 'boolean') {
      fail('immutablePolicies', 'immutable_policies.require_oracle_price must be a boolean')
    } else if (typeof ip.enforce_whitelist !== 'boolean') {
      fail('immutablePolicies', 'immutable_policies.enforce_whitelist must be a boolean')
    } else {
      pass('immutablePolicies', `max_withdrawal_usd_24h: ${ip.max_withdrawal_usd_24h}, oracle: ${ip.require_oracle_price}, whitelist: ${ip.enforce_whitelist}`)
    }

    // Step 12 — Trusted infrastructure validation
    const ti = doc.trusted_infrastructure
    if (!ti || typeof ti !== 'object') {
      fail('trustedInfrastructure', 'trusted_infrastructure must be an object')
    } else {
      let tiValid = true
      if (ti.backoffice_pubkey && !/^0x[0-9a-fA-F]{40}$/.test(ti.backoffice_pubkey)) {
        fail('trustedInfrastructure', `Invalid backoffice_pubkey format: ${ti.backoffice_pubkey}`)
        tiValid = false
      }
      if (tiValid && ti.market_oracle_pubkey && !/^0x[0-9a-fA-F]{40}$/.test(ti.market_oracle_pubkey)) {
        fail('trustedInfrastructure', `Invalid market_oracle_pubkey format: ${ti.market_oracle_pubkey}`)
        tiValid = false
      }
      if (tiValid && ti.trusted_binary_hashes) {
        if (!Array.isArray(ti.trusted_binary_hashes)) {
          fail('trustedInfrastructure', 'trusted_binary_hashes must be an array')
          tiValid = false
        } else {
          const badHash = ti.trusted_binary_hashes.find((h: string) => !/^[0-9a-f]{64}$/i.test(h))
          if (badHash) {
            fail('trustedInfrastructure', `Invalid binary hash: ${badHash}`)
            tiValid = false
          }
        }
      }
      if (tiValid) {
        pass('trustedInfrastructure', 'Trusted infrastructure validated')
      }
    }

    const allPassed = steps.every(s => s.passed)
    return { valid: allPassed, steps, summary: allPassed ? 'Document is valid' : 'Document failed verification' }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // WRITE ENDPOINTS (node operations)
  // ══════════════════════════════════════════════════════════════════════════

  proposeEnroll(body: {
    ik_pub: string
    ek_pub: string
    role: NodeRole
  }): { node_id: string; draft: RegistryDocument } {
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    const now    = Math.floor(Date.now() / 1000)
    const nodeId = deriveNodeId(body.ik_pub, body.role, now)

    // Validate
    if (!/^[0-9a-f]{64}$/i.test(body.ik_pub)) throw new BadRequestException('ik_pub must be 32 bytes (64 hex chars)')
    if (!/^[0-9a-f]{64}$/i.test(body.ek_pub)) throw new BadRequestException('ek_pub must be 32 bytes (64 hex chars)')
    if (!['USER_COSIGNER', 'PROVIDER_COSIGNER', 'RECOVERY_GUARDIAN'].includes(body.role)) {
      throw new BadRequestException('Invalid role')
    }
    // Check not already enrolled
    const draftNodes = this.stagedDraft?.nodes ?? this.currentDoc?.nodes ?? []
    if (draftNodes.some(n => n.ik_pub === body.ik_pub)) {
      throw new ConflictException('A node with this ik_pub already exists')
    }

    // Auto-create draft if none exists
    if (!this.stagedDraft) {
      const nodes = this.currentDoc ? [...this.currentDoc.nodes] : []
      const base = this._buildDraft(nodes)
      this.stagedDraft = { ...base, signatures: [] }
    }

    // Check node_id collision
    if (this.stagedDraft.nodes.some(n => n.node_id === nodeId)) {
      throw new ConflictException('node_id collision — try again')
    }

    // Add the node
    const newNode: NodeRecord = { ...body, node_id: nodeId, status: 'ACTIVE', enrolled_at: now }
    this.stagedDraft.nodes.push(newNode)
    this._refreshDraftHash()

    this.audit('ENROLL_PROPOSED', { node_id: nodeId, role: body.role })
    return { node_id: nodeId, draft: this.stagedDraft }
  }

  proposeRevoke(body: { node_id: string; reason: string }): RegistryDocument {
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    // Auto-create draft if none exists
    if (!this.stagedDraft) {
      if (!this.currentDoc) throw new NotFoundException(`Node ${body.node_id} not found`)
      const nodes = [...this.currentDoc.nodes]
      const base = this._buildDraft(nodes)
      this.stagedDraft = { ...base, signatures: [] }
    }

    const node = this.stagedDraft.nodes.find(n => n.node_id === body.node_id)
    if (!node) throw new NotFoundException(`Node ${body.node_id} not found`)
    if (node.status === 'REVOKED') throw new ConflictException('Node is already revoked')

    const now = Math.floor(Date.now() / 1000)
    node.status = 'REVOKED'
    node.revoked_at = now
    this._refreshDraftHash()

    this.audit('REVOKE_PROPOSED', { node_id: body.node_id, reason: body.reason })
    return this.stagedDraft
  }

  /** POST /registry/nodes/rotate-ik — propose an identity key rotation for a node */
  proposeIkRotation(body: { node_id: string; new_ik_pub: string; reason: string; proof: string }): RegistryDocument {
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    // Auto-create draft if none exists
    if (!this.stagedDraft) {
      if (!this.currentDoc) throw new NotFoundException(`Node ${body.node_id} not found`)
      const nodes = [...this.currentDoc.nodes]
      const base = this._buildDraft(nodes)
      this.stagedDraft = { ...base, signatures: [] }
    }

    const node = this.stagedDraft.nodes.find(n => n.node_id === body.node_id)
    if (!node) throw new NotFoundException(`Node ${body.node_id} not found`)
    if (node.status === 'REVOKED') throw new ConflictException('Cannot rotate IK of a revoked node')

    // Validate new_ik_pub format
    if (!/^[0-9a-f]{64}$/i.test(body.new_ik_pub)) {
      throw new BadRequestException('new_ik_pub must be 32 bytes (64 hex chars)')
    }

    // Check new_ik_pub isn't already used
    if (this.stagedDraft.nodes.some(n => n.ik_pub === body.new_ik_pub)) {
      throw new ConflictException('new_ik_pub already in use by another node')
    }

    // Verify Ed25519 rotation proof
    const now = Math.floor(Date.now() / 1000)
    const ok = verifyRotationProof(node.ik_pub, body.new_ik_pub, now, body.proof)
    // Allow 60-second tolerance window for timestamp mismatch
    const okWithTolerance = ok ||
      verifyRotationProof(node.ik_pub, body.new_ik_pub, now - 1, body.proof) ||
      verifyRotationProof(node.ik_pub, body.new_ik_pub, now + 1, body.proof) ||
      verifyRotationProof(node.ik_pub, body.new_ik_pub, now - 30, body.proof) ||
      verifyRotationProof(node.ik_pub, body.new_ik_pub, now + 30, body.proof) ||
      verifyRotationProof(node.ik_pub, body.new_ik_pub, now - 60, body.proof) ||
      verifyRotationProof(node.ik_pub, body.new_ik_pub, now + 60, body.proof)
    if (!okWithTolerance) {
      throw new BadRequestException('Rotation proof verification failed — Ed25519 signature invalid')
    }

    // Append rotation entry
    const entry: IkRotationEntry = {
      prev_ik_pub: node.ik_pub,
      new_ik_pub: body.new_ik_pub,
      rotated_at: now,
      reason: body.reason,
      proof: body.proof,
    }
    if (!node.ik_rotations) node.ik_rotations = []
    node.ik_rotations.push(entry)
    node.ik_pub = body.new_ik_pub
    this._refreshDraftHash()

    this.audit('IK_ROTATION_PROPOSED', { node_id: body.node_id, new_ik_pub: body.new_ik_pub, reason: body.reason })
    return this.stagedDraft
  }

  /** POST /registry/nodes/maintenance — set a node to MAINTENANCE status */
  proposeNodeMaintenance(body: { node_id: string; reason: string }): RegistryDocument {
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    // Auto-create draft if none exists
    if (!this.stagedDraft) {
      if (!this.currentDoc) throw new NotFoundException(`Node ${body.node_id} not found`)
      const nodes = [...this.currentDoc.nodes]
      const base = this._buildDraft(nodes)
      this.stagedDraft = { ...base, signatures: [] }
    }

    const node = this.stagedDraft.nodes.find(n => n.node_id === body.node_id)
    if (!node) throw new NotFoundException(`Node ${body.node_id} not found`)
    if (node.status !== 'ACTIVE') {
      throw new ConflictException(`Cannot set maintenance — node status is ${node.status} (must be ACTIVE)`)
    }

    node.status = 'MAINTENANCE'
    this._refreshDraftHash()

    this.audit('NODE_MAINTENANCE_PROPOSED', { node_id: body.node_id, reason: body.reason })
    return this.stagedDraft
  }

  /** POST /registry/nodes/reactivate — reactivate a MAINTENANCE node */
  proposeNodeReactivate(body: { node_id: string }): RegistryDocument {
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    // Auto-create draft if none exists
    if (!this.stagedDraft) {
      if (!this.currentDoc) throw new NotFoundException(`Node ${body.node_id} not found`)
      const nodes = [...this.currentDoc.nodes]
      const base = this._buildDraft(nodes)
      this.stagedDraft = { ...base, signatures: [] }
    }

    const node = this.stagedDraft.nodes.find(n => n.node_id === body.node_id)
    if (!node) throw new NotFoundException(`Node ${body.node_id} not found`)
    if (node.status !== 'MAINTENANCE') {
      throw new ConflictException(`Cannot reactivate — node status is ${node.status} (must be MAINTENANCE)`)
    }

    node.status = 'ACTIVE'
    this._refreshDraftHash()

    this.audit('NODE_REACTIVATE_PROPOSED', { node_id: body.node_id })
    return this.stagedDraft
  }

  clearStagedDraft() {
    this.stagedDraft = null
    this.draftLocked = false
    return { cleared: true }
  }

  publishDocument(doc: RegistryDocument): { published: boolean; version: number } {
    // Full verification
    const result = this.verifyDocument(doc) as any
    if (!result.valid) {
      const failed = result.steps.filter((s: any) => !s.passed).map((s: any) => s.detail).join('; ')
      throw new BadRequestException(`Document invalid: ${failed}`)
    }

    // Construct clean document from known fields
    const clean: RegistryDocument = {
      registry_metadata: {
        registry_id:        doc.registry_metadata.registry_id,
        version:            doc.registry_metadata.version,
        issued_at:          doc.registry_metadata.issued_at,
        expires_at:         doc.registry_metadata.expires_at,
        updated_at:         doc.registry_metadata.updated_at,
        document_hash:      doc.registry_metadata.document_hash,
        merkle_root:        doc.registry_metadata.merkle_root,
        prev_document_hash: doc.registry_metadata.prev_document_hash,
        endpoints:          doc.registry_metadata.endpoints ?? null,
      },
      governance: {
        roles: doc.governance.roles.map(r => ({
          role:         r.role,
          display_name: r.display_name,
          addresses:    r.addresses,
          quorum:       r.quorum,
          features:     r.features ?? {},
        })),
      },
      ceremony_config: {
        global_threshold_t:  doc.ceremony_config.global_threshold_t,
        max_participants_n:  doc.ceremony_config.max_participants_n,
        allowed_protocols:   doc.ceremony_config.allowed_protocols,
        allowed_curves:      doc.ceremony_config.allowed_curves,
      },
      trusted_infrastructure: {
        backoffice_pubkey: doc.trusted_infrastructure.backoffice_pubkey ?? null,
        market_oracle_pubkey:      doc.trusted_infrastructure.market_oracle_pubkey ?? null,
        trusted_binary_hashes:      doc.trusted_infrastructure.trusted_binary_hashes ?? [],
      },
      nodes: doc.nodes.map(n => {
        const node: NodeRecord = {
          node_id: n.node_id, ik_pub: n.ik_pub, ek_pub: n.ek_pub,
          role: n.role, status: n.status, enrolled_at: n.enrolled_at,
        }
        if (n.updated_at) node.updated_at = n.updated_at
        if (n.revoked_at) node.revoked_at = n.revoked_at
        if (n.ik_rotations?.length) node.ik_rotations = n.ik_rotations
        return node
      }),
      immutable_policies: {
        max_withdrawal_usd_24h: doc.immutable_policies.max_withdrawal_usd_24h,
        require_oracle_price:   doc.immutable_policies.require_oracle_price,
        enforce_whitelist:       doc.immutable_policies.enforce_whitelist,
      },
      signatures: doc.signatures.map(s => ({
        role:      s.role,
        signer:    s.signer,
        signature: s.signature,
      })),
    }

    // Persist
    this.currentDoc = clean
    this.stagedDraft = null
    this.draftLocked = false
    this.saveToDisk()
    this.audit('DOCUMENT_PUBLISHED', {
      version: doc.registry_metadata.version,
      nodes: doc.nodes.length,
      roles: doc.governance.roles.length,
    })

    return { published: true, version: doc.registry_metadata.version }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // INTERNAL HELPERS
  // ══════════════════════════════════════════════════════════════════════════

  /** Build the default genesis SYSTEM_ADMIN role from env vars */
  private _genesisSystemAdminRole(): GovernanceRole {
    return {
      role: 'SYSTEM_ADMIN',
      display_name: 'System Administrators',
      addresses: CONFIG.GENESIS_ADMIN_ADDRESSES,
      quorum: CONFIG.SYSTEM_ADMIN_QUORUM,
      features: {},
    }
  }

  /** Re-sort nodes, recompute merkle_root + document_hash, clear signatures */
  private _refreshDraftHash() {
    if (!this.stagedDraft) return
    this.stagedDraft.nodes.sort((a, b) => a.node_id.localeCompare(b.node_id))
    this.stagedDraft.registry_metadata.merkle_root = computeMerkleRoot(this.stagedDraft.nodes)
    this.stagedDraft.registry_metadata.document_hash = ''
    const { signatures: _, ...unsigned } = this.stagedDraft
    this.stagedDraft.registry_metadata.document_hash = computeDocumentHash(unsigned as UnsignedDocument)
    this.stagedDraft.signatures = []
  }

  private _buildDraft(nodes: NodeRecord[]): UnsignedDocument {
    // Deep-copy nodes to avoid mutating currentDoc's node objects
    const sorted = JSON.parse(JSON.stringify(nodes)).sort((a: any, b: any) => a.node_id.localeCompare(b.node_id))
    const now    = Math.floor(Date.now() / 1000)
    const nextV  = (this.currentDoc?.registry_metadata.version ?? 0) + 1

    // Carry forward governance roles, or use genesis default
    const governanceRoles: GovernanceRole[] = this.currentDoc?.governance?.roles?.length
      ? this.currentDoc.governance.roles.map(r => ({ ...r }))
      : [this._genesisSystemAdminRole()]

    const draft: UnsignedDocument = {
      registry_metadata: {
        registry_id:        CONFIG.REGISTRY_ID,
        version:            nextV,
        issued_at:          now,
        expires_at:         now + CONFIG.EXPIRY_SECONDS,
        updated_at:         new Date().toISOString(),
        document_hash:      '',
        merkle_root:        computeMerkleRoot(sorted),
        prev_document_hash: this.currentDoc?.registry_metadata.document_hash ?? null,
        endpoints:          this.currentDoc?.registry_metadata.endpoints ?? null,
      },
      governance: {
        roles: governanceRoles,
      },
      ceremony_config: this.currentDoc?.ceremony_config ?? {
        global_threshold_t: 2,
        max_participants_n: 9,
        allowed_protocols: ['CGGMP21', 'FROST'],
        allowed_curves: ['Secp256k1', 'Ed25519'],
      },
      trusted_infrastructure: this.currentDoc?.trusted_infrastructure ?? {
        backoffice_pubkey: null,
        market_oracle_pubkey: null,
        trusted_binary_hashes: [],
      },
      nodes: sorted,
      immutable_policies: this.currentDoc?.immutable_policies ?? {
        max_withdrawal_usd_24h: 100000,
        require_oracle_price: true,
        enforce_whitelist: true,
      },
    }
    draft.registry_metadata.document_hash = computeDocumentHash(draft)
    return draft
  }

  private audit(event: string, detail: object) {
    const entry = { event, detail, at: Math.floor(Date.now() / 1000) }
    this.auditLog.push(entry)
    if (this.auditLog.length > 200) this.auditLog.shift()
    this.appendAuditToDisk(entry)
  }

  private appendAuditToDisk(entry: { event: string; detail: object; at: number }) {
    try {
      const auditFile = resolve(dirname(CONFIG.REGISTRY_FILE), 'registry.audit.jsonl')
      appendFileSync(auditFile, JSON.stringify(entry) + '\n')
    } catch {
      // Best-effort — don't crash if audit file write fails
    }
  }

  private loadFromDisk() {
    try {
      const raw = readFileSync(CONFIG.REGISTRY_FILE, 'utf-8')
      const doc = JSON.parse(raw)

      // Only load as published if the document has signatures.
      // Unsigned documents (created by setup) are loaded as a staged draft
      // so admins can sign them via the UI.
      if (!doc.signatures || doc.signatures.length === 0) {
        console.log(`[Registry] Loaded unsigned v${doc.registry_metadata?.version ?? '?'} as pending draft — sign via UI`)
        this.stagedDraft = doc
      } else {
        this.currentDoc = doc
        console.log(`[Registry] Loaded version ${this.currentDoc?.registry_metadata?.version} from disk`)
      }
    } catch (e: any) {
      if (e.code === 'ENOENT') {
        console.log('[Registry] No registry file found — starting empty')
      } else {
        console.error('[Registry] Failed to load from disk:', e)
      }
    }
  }

  private saveToDisk() {
    const dir = dirname(CONFIG.REGISTRY_FILE)
    try { mkdirSync(dir, { recursive: true }) } catch {}

    // Write registry.json
    const json = JSON.stringify(this.currentDoc, null, 2)
    const tmpFile = CONFIG.REGISTRY_FILE + '.tmp'
    writeFileSync(tmpFile, json)
    renameSync(tmpFile, CONFIG.REGISTRY_FILE)

    // Write version file: versions/{N}.json
    const versionDir = CONFIG.VERSIONS_DIR
    try { mkdirSync(versionDir, { recursive: true }) } catch {}
    const versionFile = resolve(versionDir, `${this.currentDoc?.registry_metadata.version}.json`)
    writeFileSync(versionFile, json)

    console.log(`[Registry] Saved version ${this.currentDoc?.registry_metadata.version} to disk`)
  }
}
