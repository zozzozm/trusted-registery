// ─────────────────────────────────────────────────────────────────────────────
// Registry Service — the heart of the system
// Manages the in-memory registry state and all verification logic
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, OnModuleInit, BadRequestException, NotFoundException, ConflictException } from '@nestjs/common'
import { readFileSync, writeFileSync, mkdirSync, renameSync, appendFileSync } from 'fs'
import { dirname, resolve } from 'path'
import { ethers } from 'ethers'
import {
  RegistryDocument, UnsignedDocument, NodeRecord, AdminSignature,
  NodeRole, RegistryEndpoints
} from '../common/types'
import {
  computeDocumentHash, computeMerkleRoot, verifyMultiSig,
  verifySingleSig, deriveNodeId, getEIP712Payload
} from '../common/crypto'
import { CONFIG } from '../common/config'

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
   * Returns the current admin addresses.
   * If a document is published, uses its admin_addresses.
   * Otherwise falls back to genesis env vars.
   */
  getActiveAdminAddresses(): string[] {
    if (this.currentDoc?.admin_addresses?.length) {
      return this.currentDoc.admin_addresses
    }
    return CONFIG.GENESIS_ADMIN_ADDRESSES
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

  /** POST /registry/pending/sign — add one admin signature to the staged draft */
  signPendingDocument(body: { admin_address: string; signature: string; document_hash?: string }): RegistryDocument {
    if (!this.stagedDraft) throw new NotFoundException('No pending document. Call GET /registry/pending first.')

    const { admin_address, signature, document_hash } = body

    // If caller provided document_hash, verify it matches the current draft
    if (document_hash && document_hash !== this.stagedDraft.document_hash) {
      throw new ConflictException('document_hash does not match the current draft. The draft may have been modified.')
    }

    // Signatures must come from the CURRENT admins (not the draft's proposed admins)
    const activeAdmins = this.getActiveAdminAddresses()
    const isKnownAdmin = activeAdmins.some(a => a.toLowerCase() === admin_address.toLowerCase())
    if (!isKnownAdmin) throw new BadRequestException(`Unknown admin address: ${admin_address}`)

    // Check for duplicate
    if (this.stagedDraft.signatures.some(s => s.admin_address.toLowerCase() === admin_address.toLowerCase())) {
      throw new ConflictException(`Admin ${admin_address} has already signed this draft`)
    }

    // Validate signature format (0x + 130 hex chars)
    if (!/^0x[0-9a-f]{130}$/i.test(signature)) {
      throw new BadRequestException('Signature must be 0x-prefixed 65 bytes hex (132 chars)')
    }

    // Verify signature against full document using ecrecover
    const { signatures: _sigs, ...unsignedDraft } = this.stagedDraft
    const ok = verifySingleSig(unsignedDraft, signature, admin_address)
    if (!ok) throw new BadRequestException('Signature verification failed')

    this.stagedDraft.signatures.push({ admin_address, signature })

    // Lock draft after first signature to prevent TOCTOU
    this.draftLocked = true

    return this.stagedDraft
  }

  /** POST /registry/admins/propose — propose new admin addresses for the next version */
  proposeAdminChange(body: { admin_addresses: string[] }): RegistryDocument {
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    // Validate addresses
    const addresses = body.admin_addresses.map(a => {
      try { return ethers.getAddress(a) }
      catch { throw new BadRequestException(`Invalid Ethereum address: ${a}`) }
    })

    if (addresses.length < CONFIG.MIN_SIGNATURES) {
      throw new BadRequestException(`Need at least ${CONFIG.MIN_SIGNATURES} admin addresses`)
    }

    // Check for duplicates
    const unique = new Set(addresses.map(a => a.toLowerCase()))
    if (unique.size !== addresses.length) {
      throw new BadRequestException('Duplicate admin addresses')
    }

    // Auto-create draft if none exists
    if (!this.stagedDraft) {
      const nodes = this.currentDoc ? [...this.currentDoc.nodes] : []
      const base = this._buildDraft(nodes)
      this.stagedDraft = { ...base, signatures: [] }
    }

    // Update admin addresses and refresh hash
    this.stagedDraft.admin_addresses = addresses
    this._refreshDraftHash()

    this.audit('ADMIN_CHANGE_PROPOSED', { newAdmins: addresses })
    return this.stagedDraft
  }

  /** POST /registry/backoffice-pubkey/propose — propose a new backoffice service public key */
  proposeBackofficePubkey(body: { backoffice_service_pubkey: string }): RegistryDocument {
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    const pubkey = body.backoffice_service_pubkey
    if (!/^[0-9a-f]{64}$/i.test(pubkey)) {
      throw new BadRequestException('backoffice_service_pubkey must be 32 bytes (64 hex chars)')
    }

    // Auto-create draft if none exists
    if (!this.stagedDraft) {
      const nodes = this.currentDoc ? [...this.currentDoc.nodes] : []
      const base = this._buildDraft(nodes)
      this.stagedDraft = { ...base, signatures: [] }
    }

    this.stagedDraft.backoffice_service_pubkey = pubkey
    this._refreshDraftHash()

    this.audit('BACKOFFICE_PUBKEY_PROPOSED', { backoffice_service_pubkey: pubkey })
    return this.stagedDraft
  }

  /** POST /registry/mpc-policy/propose — propose MPC policy (curves, protocols, admin_quorum) */
  proposeMpcPolicy(body: { allowed_curves: string[]; allowed_protocols: string[]; admin_quorum: number }): RegistryDocument {
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    const { allowed_curves, allowed_protocols, admin_quorum } = body
    if (!Array.isArray(allowed_curves) || allowed_curves.length === 0) {
      throw new BadRequestException('allowed_curves must be a non-empty array')
    }
    if (!Array.isArray(allowed_protocols) || allowed_protocols.length === 0) {
      throw new BadRequestException('allowed_protocols must be a non-empty array')
    }
    if (!Number.isInteger(admin_quorum) || admin_quorum < 2) {
      throw new BadRequestException('admin_quorum must be an integer >= 2')
    }

    // Auto-create draft if none exists
    if (!this.stagedDraft) {
      const nodes = this.currentDoc ? [...this.currentDoc.nodes] : []
      const base = this._buildDraft(nodes)
      this.stagedDraft = { ...base, signatures: [] }
    }

    this.stagedDraft.allowed_curves = allowed_curves
    this.stagedDraft.allowed_protocols = allowed_protocols
    this.stagedDraft.admin_quorum = admin_quorum
    this._refreshDraftHash()

    this.audit('MPC_POLICY_PROPOSED', { allowed_curves, allowed_protocols, admin_quorum })
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

    this.stagedDraft.endpoints = {
      primary:    body.primary,
      mirrors:    mirrors,
      updated_at: new Date().toISOString(),
    }
    this._refreshDraftHash()

    this.audit('ENDPOINTS_PROPOSED', { endpoints: this.stagedDraft.endpoints })
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
    const admins = this.getActiveAdminAddresses()
    return {
      status:      'ok',
      registry_id:  CONFIG.REGISTRY_ID,
      version:     doc?.version ?? 0,
      totalNodes:  doc?.nodes.length ?? 0,
      activeNodes: doc?.nodes.filter(n => n.status === 'ACTIVE').length ?? 0,
      expires_at:   doc?.expires_at ?? null,
      expired:     doc ? Math.floor(Date.now() / 1000) > doc.expires_at : null,
      admin_addresses: admins.map((a, i) => ({
        index:   i,
        address: a,
      })),
      adminSource: doc?.admin_addresses?.length ? 'document' : 'genesis-env',
    }
  }

  /** GET /registry/audit */
  getAuditLog() {
    return this.auditLog.slice().reverse()
  }

  // ══════════════════════════════════════════════════════════════════════════
  // VERIFY ENDPOINT
  // ══════════════════════════════════════════════════════════════════════════

  verifyDocument(doc: any): object {
    const steps: Array<{ step: string; passed: boolean; detail: string }> = []

    const pass = (step: string, detail: string) => steps.push({ step, passed: true,  detail })
    const fail = (step: string, detail: string) => steps.push({ step, passed: false, detail })

    // Step 1 — Structure
    const requiredFields = ['registry_id','version','issued_at','expires_at','admin_addresses','nodes','merkle_root','prev_document_hash','document_hash','allowed_curves','allowed_protocols','admin_quorum']
    const missing  = requiredFields.filter(f => doc[f] === undefined)
    if (missing.length > 0) {
      fail('structure', `Missing fields: ${missing.join(', ')}`)
      return { valid: false, steps }
    }
    pass('structure', 'All required fields present')

    // Step 2 — Registry ID
    if (doc.registry_id !== CONFIG.REGISTRY_ID) {
      fail('registry_id', `Got "${doc.registry_id}", expected "${CONFIG.REGISTRY_ID}"`)
    } else {
      pass('registry_id', `Registry ID matches: "${doc.registry_id}"`)
    }

    // Step 3 — Expiry
    const now = Math.floor(Date.now() / 1000)
    if (now > doc.expires_at) {
      fail('expiry', `Document expired at ${new Date(doc.expires_at * 1000).toISOString()}`)
    } else {
      const secsLeft = doc.expires_at - now
      pass('expiry', `Valid for ${Math.floor(secsLeft / 3600)}h ${Math.floor((secsLeft % 3600) / 60)}m more`)
    }

    // Step 4 — Document hash integrity (whitelist known fields only)
    const unsignedClean: UnsignedDocument = {
      registry_id:            doc.registry_id,
      version:               doc.version,
      issued_at:              doc.issued_at,
      expires_at:             doc.expires_at,
      admin_addresses:        doc.admin_addresses,
      backoffice_service_pubkey: doc.backoffice_service_pubkey ?? null,
      allowed_curves:         doc.allowed_curves ?? [],
      allowed_protocols:      doc.allowed_protocols ?? [],
      admin_quorum:             doc.admin_quorum ?? 2,
      endpoints:             doc.endpoints ?? null,
      nodes:                 doc.nodes,
      merkle_root:            doc.merkle_root,
      prev_document_hash:      doc.prev_document_hash,
      document_hash:          '',
    }
    const expectedHash = computeDocumentHash(unsignedClean)
    if (expectedHash !== doc.document_hash) {
      fail('document_hash', `Recomputed: ${expectedHash.substring(0,16)}...\nDocument has: ${doc.document_hash.substring(0,16)}...`)
    } else {
      pass('document_hash', `Hash verified: ${doc.document_hash.substring(0,16)}...`)
    }

    // Step 5 — Merkle root
    const nodes = Array.isArray(doc.nodes) ? doc.nodes : []
    const sorted = [...nodes].sort((a: any, b: any) => a.node_id.localeCompare(b.node_id))
    const expectedRoot = computeMerkleRoot(sorted)
    if (expectedRoot !== doc.merkle_root) {
      fail('merkle_root', `Recomputed: ${expectedRoot.substring(0,16)}...\nDocument has: ${doc.merkle_root.substring(0,16)}...`)
    } else {
      pass('merkle_root', `Merkle root verified: ${doc.merkle_root.substring(0,16)}...`)
    }

    // Step 6 — Hash chain
    if (this.currentDoc) {
      if (doc.version <= this.currentDoc.version) {
        fail('hashChain', `Version ${doc.version} <= current ${this.currentDoc.version} — rollback`)
      } else if (doc.prev_document_hash !== this.currentDoc.document_hash) {
        fail('hashChain', `prev_document_hash does not match current document hash`)
      } else {
        pass('hashChain', `Chain intact: v${this.currentDoc.version} -> v${doc.version}`)
      }
    } else {
      pass('hashChain', 'No previous version — this is the genesis document')
    }

    // Step 7 — Multi-signature verification
    // Signatures must be from the CURRENT admins (who authorize the new version)
    const signingAdmins = this.getActiveAdminAddresses()
    const docForSig = { ...unsignedClean, document_hash: doc.document_hash }
    const sigResult = verifyMultiSig(
      docForSig,
      doc.signatures,
      signingAdmins,
      CONFIG.MIN_SIGNATURES
    )
    if (!sigResult.valid) {
      fail('signatures', sigResult.reason!)
    } else {
      const signers = (doc.signatures as AdminSignature[]).map(s => s.admin_address.substring(0, 10) + '...').join(', ')
      pass('signatures', `${doc.signatures.length} valid signatures from: ${signers}`)
    }

    // Step 8 — Admin addresses validation
    if (!Array.isArray(doc.admin_addresses) || doc.admin_addresses.length < CONFIG.MIN_SIGNATURES) {
      fail('admin_addresses', `Need at least ${CONFIG.MIN_SIGNATURES} admin addresses, got ${doc.admin_addresses?.length ?? 0}`)
    } else {
      const adminChanged = this.currentDoc
        ? JSON.stringify(doc.admin_addresses.map((a: string) => a.toLowerCase()).sort())
          !== JSON.stringify(this.currentDoc.admin_addresses.map((a: string) => a.toLowerCase()).sort())
        : false
      if (adminChanged) {
        pass('admin_addresses', `Admin rotation: ${doc.admin_addresses.length} new admins proposed`)
      } else {
        pass('admin_addresses', `${doc.admin_addresses.length} admin addresses (unchanged)`)
      }
    }

    // Step 9 — MPC policy validation (curves, protocols, admin_quorum)
    const allowedCurves = doc.allowed_curves ?? []
    const allowedProtocols = doc.allowed_protocols ?? []
    const adminQuorum = doc.admin_quorum ?? 2
    if (!Array.isArray(allowedCurves) || allowedCurves.length === 0) {
      fail('mpcPolicy', 'allowed_curves must be a non-empty array')
    } else if (!Array.isArray(allowedProtocols) || allowedProtocols.length === 0) {
      fail('mpcPolicy', 'allowed_protocols must be a non-empty array')
    } else if (!Number.isInteger(adminQuorum) || adminQuorum < 2) {
      fail('mpcPolicy', 'admin_quorum must be an integer >= 2')
    } else {
      pass('mpcPolicy', `Curves: [${allowedCurves.join(', ')}], Protocols: [${allowedProtocols.join(', ')}], Quorum: ${adminQuorum}`)
    }

    // Step 11 — Endpoints validation
    const endpoints = doc.endpoints ?? null
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

    const allPassed = steps.every(s => s.passed)
    return { valid: allPassed, steps, summary: allPassed ? 'Document is valid' : 'Document failed verification' }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // WRITE ENDPOINTS (require signed document)
  // ══════════════════════════════════════════════════════════════════════════

  proposeEnroll(body: {
    ik_pub: string
    ek_pub: string
    role: NodeRole
  }): { node_id: string; draft: RegistryDocument } {
    // Reject if draft is locked (has signatures)
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    const now    = Math.floor(Date.now() / 1000)
    const nodeId = deriveNodeId(body.ik_pub, body.role, now)

    // Validate
    if (!/^[0-9a-f]{64}$/i.test(body.ik_pub)) throw new BadRequestException('ik_pub must be 32 bytes (64 hex chars)')
    if (!/^[0-9a-f]{64}$/i.test(body.ek_pub)) throw new BadRequestException('ek_pub must be 32 bytes (64 hex chars)')
    if (!['USER_COSIGNER','PROVIDER_COSIGNER','RECOVERY_GUARDIAN'].includes(body.role)) {
      throw new BadRequestException('Invalid role')
    }
    // Check not already enrolled (active OR revoked — block re-enrollment of revoked keys)
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
    // Reject if draft is locked (has signatures)
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

    // Find node in the draft
    const node = this.stagedDraft.nodes.find(n => n.node_id === body.node_id)
    if (!node) throw new NotFoundException(`Node ${body.node_id} not found`)
    if (node.status === 'REVOKED') throw new ConflictException('Node is already revoked')

    // Revoke and refresh hash
    const now = Math.floor(Date.now() / 1000)
    node.status = 'REVOKED'
    node.revoked_at = now
    this._refreshDraftHash()

    this.audit('REVOKE_PROPOSED', { node_id: body.node_id, reason: body.reason })
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

    // Construct clean document from known fields only
    const clean: RegistryDocument = {
      registry_id:            doc.registry_id,
      version:               doc.version,
      issued_at:              doc.issued_at,
      expires_at:             doc.expires_at,
      admin_addresses:        doc.admin_addresses,
      backoffice_service_pubkey: doc.backoffice_service_pubkey ?? null,
      allowed_curves:         doc.allowed_curves ?? [],
      allowed_protocols:      doc.allowed_protocols ?? [],
      admin_quorum:             doc.admin_quorum ?? 2,
      endpoints:             doc.endpoints ?? null,
      nodes:                 doc.nodes,
      merkle_root:            doc.merkle_root,
      prev_document_hash:      doc.prev_document_hash,
      document_hash:          doc.document_hash,
      signatures:            doc.signatures,
    }

    // Persist
    this.currentDoc = clean
    this.stagedDraft = null
    this.draftLocked = false
    this.saveToDisk()
    this.audit('DOCUMENT_PUBLISHED', { version: doc.version, nodes: doc.nodes.length, admins: doc.admin_addresses.length })

    return { published: true, version: doc.version }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // INTERNAL HELPERS
  // ══════════════════════════════════════════════════════════════════════════

  /** Re-sort nodes, recompute merkle_root + document_hash, clear signatures */
  private _refreshDraftHash() {
    if (!this.stagedDraft) return
    this.stagedDraft.nodes.sort((a, b) => a.node_id.localeCompare(b.node_id))
    this.stagedDraft.merkle_root = computeMerkleRoot(this.stagedDraft.nodes)
    this.stagedDraft.document_hash = ''
    const { signatures: _, ...unsigned } = this.stagedDraft
    this.stagedDraft.document_hash = computeDocumentHash(unsigned as UnsignedDocument)
    this.stagedDraft.signatures = []
  }

  private _buildDraft(nodes: NodeRecord[]): UnsignedDocument {
    const sorted  = [...nodes].sort((a, b) => a.node_id.localeCompare(b.node_id))
    const now     = Math.floor(Date.now() / 1000)
    const nextV   = (this.currentDoc?.version ?? 0) + 1
    // Carry forward current admin addresses, or use genesis
    const admins  = this.getActiveAdminAddresses()
    const draft: UnsignedDocument = {
      registry_id:            CONFIG.REGISTRY_ID,
      version:               nextV,
      issued_at:              now,
      expires_at:             now + CONFIG.EXPIRY_SECONDS,
      admin_addresses:        admins,
      backoffice_service_pubkey: this.currentDoc?.backoffice_service_pubkey ?? null,
      allowed_curves:         this.currentDoc?.allowed_curves ?? ['secp256k1', 'ed25519'],
      allowed_protocols:      this.currentDoc?.allowed_protocols ?? ['cggmp21', 'frost'],
      admin_quorum:             this.currentDoc?.admin_quorum ?? 2,
      endpoints:             this.currentDoc?.endpoints ?? null,
      nodes:                 sorted,
      merkle_root:            computeMerkleRoot(sorted),
      prev_document_hash:      this.currentDoc?.document_hash ?? null,
      document_hash:          '',
    }
    draft.document_hash = computeDocumentHash(draft)
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
      this.currentDoc = JSON.parse(raw)
      console.log(`[Registry] Loaded version ${this.currentDoc?.version} from disk`)
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
    const tmpFile = CONFIG.REGISTRY_FILE + '.tmp'
    writeFileSync(tmpFile, JSON.stringify(this.currentDoc, null, 2))
    renameSync(tmpFile, CONFIG.REGISTRY_FILE)
    console.log(`[Registry] Saved version ${this.currentDoc?.version} to disk`)
  }
}
