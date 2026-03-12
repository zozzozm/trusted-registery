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
   * If a document is published, uses its adminAddresses.
   * Otherwise falls back to genesis env vars.
   */
  getActiveAdminAddresses(): string[] {
    if (this.currentDoc?.adminAddresses?.length) {
      return this.currentDoc.adminAddresses
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
  signPendingDocument(body: { adminAddress: string; signature: string; documentHash?: string }): RegistryDocument {
    if (!this.stagedDraft) throw new NotFoundException('No pending document. Call GET /registry/pending first.')

    const { adminAddress, signature, documentHash } = body

    // If caller provided documentHash, verify it matches the current draft
    if (documentHash && documentHash !== this.stagedDraft.documentHash) {
      throw new ConflictException('documentHash does not match the current draft. The draft may have been modified.')
    }

    // Signatures must come from the CURRENT admins (not the draft's proposed admins)
    const adminAddresses = this.getActiveAdminAddresses()
    const isKnownAdmin = adminAddresses.some(a => a.toLowerCase() === adminAddress.toLowerCase())
    if (!isKnownAdmin) throw new BadRequestException(`Unknown admin address: ${adminAddress}`)

    // Check for duplicate
    if (this.stagedDraft.signatures.some(s => s.adminAddress.toLowerCase() === adminAddress.toLowerCase())) {
      throw new ConflictException(`Admin ${adminAddress} has already signed this draft`)
    }

    // Validate signature format (0x + 130 hex chars)
    if (!/^0x[0-9a-f]{130}$/i.test(signature)) {
      throw new BadRequestException('Signature must be 0x-prefixed 65 bytes hex (132 chars)')
    }

    // Verify signature against full document using ecrecover
    const { signatures: _sigs, ...unsignedDraft } = this.stagedDraft
    const ok = verifySingleSig(unsignedDraft, signature, adminAddress)
    if (!ok) throw new BadRequestException('Signature verification failed')

    this.stagedDraft.signatures.push({ adminAddress, signature })

    // Lock draft after first signature to prevent TOCTOU
    this.draftLocked = true

    return this.stagedDraft
  }

  /** POST /registry/admins/propose — propose new admin addresses for the next version */
  proposeAdminChange(body: { adminAddresses: string[] }): RegistryDocument {
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    // Validate addresses
    const addresses = body.adminAddresses.map(a => {
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
    this.stagedDraft.adminAddresses = addresses
    this._refreshDraftHash()

    this.audit('ADMIN_CHANGE_PROPOSED', { newAdmins: addresses })
    return this.stagedDraft
  }

  /** POST /registry/threshold/propose — propose a new threshold value */
  proposeThreshold(body: { threshold: number }): RegistryDocument {
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    const threshold = body.threshold
    if (!Number.isInteger(threshold) || threshold < 0) {
      throw new BadRequestException('threshold must be a non-negative integer')
    }

    // Auto-create draft if none exists
    if (!this.stagedDraft) {
      const nodes = this.currentDoc ? [...this.currentDoc.nodes] : []
      const base = this._buildDraft(nodes)
      this.stagedDraft = { ...base, signatures: [] }
    }

    const activeNodes = this.stagedDraft.nodes.filter(n => n.status === 'ACTIVE').length
    if (threshold > activeNodes) {
      throw new BadRequestException(`threshold (${threshold}) exceeds active node count (${activeNodes})`)
    }

    this.stagedDraft.threshold = threshold
    this._refreshDraftHash()

    this.audit('THRESHOLD_PROPOSED', { threshold })
    return this.stagedDraft
  }

  /** POST /registry/backoffice-pubkey/propose — propose a new backoffice service public key */
  proposeBackofficePubkey(body: { backofficeServicePubkey: string }): RegistryDocument {
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    const pubkey = body.backofficeServicePubkey
    if (!/^[0-9a-f]{64}$/i.test(pubkey)) {
      throw new BadRequestException('backofficeServicePubkey must be 32 bytes (64 hex chars)')
    }

    // Auto-create draft if none exists
    if (!this.stagedDraft) {
      const nodes = this.currentDoc ? [...this.currentDoc.nodes] : []
      const base = this._buildDraft(nodes)
      this.stagedDraft = { ...base, signatures: [] }
    }

    this.stagedDraft.backofficeServicePubkey = pubkey
    this._refreshDraftHash()

    this.audit('BACKOFFICE_PUBKEY_PROPOSED', { backofficeServicePubkey: pubkey })
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
    const node = this.currentDoc?.nodes.find(n => n.nodeId === nodeId)
    if (!node) throw new NotFoundException(`Node ${nodeId} not found`)
    return node
  }

  /** GET /registry/nodes?wallet=xxx&role=yyy */
  getNodes(wallet?: string, role?: string): NodeRecord[] {
    const nodes = this.currentDoc?.nodes ?? []
    return nodes.filter(n => {
      if (wallet && !n.walletScope.includes(wallet)) return false
      if (role   && n.role !== role) return false
      return true
    })
  }

  /** GET /registry/health */
  getHealth() {
    const doc = this.currentDoc
    const admins = this.getActiveAdminAddresses()
    return {
      status:      'ok',
      registryId:  CONFIG.REGISTRY_ID,
      version:     doc?.version ?? 0,
      totalNodes:  doc?.nodes.length ?? 0,
      activeNodes: doc?.nodes.filter(n => n.status === 'ACTIVE').length ?? 0,
      expiresAt:   doc?.expiresAt ?? null,
      expired:     doc ? Math.floor(Date.now() / 1000) > doc.expiresAt : null,
      adminAddresses: admins.map((a, i) => ({
        index:   i,
        address: a,
      })),
      adminSource: doc?.adminAddresses?.length ? 'document' : 'genesis-env',
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
    const requiredFields = ['registryId','version','issuedAt','expiresAt','adminAddresses','nodes','merkleRoot','prevDocumentHash','documentHash','threshold']
    const missing  = requiredFields.filter(f => doc[f] === undefined)
    if (missing.length > 0) {
      fail('structure', `Missing fields: ${missing.join(', ')}`)
      return { valid: false, steps }
    }
    pass('structure', 'All required fields present')

    // Step 2 — Registry ID
    if (doc.registryId !== CONFIG.REGISTRY_ID) {
      fail('registryId', `Got "${doc.registryId}", expected "${CONFIG.REGISTRY_ID}"`)
    } else {
      pass('registryId', `Registry ID matches: "${doc.registryId}"`)
    }

    // Step 3 — Expiry
    const now = Math.floor(Date.now() / 1000)
    if (now > doc.expiresAt) {
      fail('expiry', `Document expired at ${new Date(doc.expiresAt * 1000).toISOString()}`)
    } else {
      const secsLeft = doc.expiresAt - now
      pass('expiry', `Valid for ${Math.floor(secsLeft / 3600)}h ${Math.floor((secsLeft % 3600) / 60)}m more`)
    }

    // Step 4 — Document hash integrity (whitelist known fields only)
    const unsignedClean: UnsignedDocument = {
      registryId:            doc.registryId,
      version:               doc.version,
      issuedAt:              doc.issuedAt,
      expiresAt:             doc.expiresAt,
      adminAddresses:        doc.adminAddresses,
      backofficeServicePubkey: doc.backofficeServicePubkey ?? null,
      threshold:             doc.threshold ?? 0,
      endpoints:             doc.endpoints ?? null,
      nodes:                 doc.nodes,
      merkleRoot:            doc.merkleRoot,
      prevDocumentHash:      doc.prevDocumentHash,
      documentHash:          '',
    }
    const expectedHash = computeDocumentHash(unsignedClean)
    if (expectedHash !== doc.documentHash) {
      fail('documentHash', `Recomputed: ${expectedHash.substring(0,16)}...\nDocument has: ${doc.documentHash.substring(0,16)}...`)
    } else {
      pass('documentHash', `Hash verified: ${doc.documentHash.substring(0,16)}...`)
    }

    // Step 5 — Merkle root
    const nodes = Array.isArray(doc.nodes) ? doc.nodes : []
    const sorted = [...nodes].sort((a: any, b: any) => a.nodeId.localeCompare(b.nodeId))
    const expectedRoot = computeMerkleRoot(sorted)
    if (expectedRoot !== doc.merkleRoot) {
      fail('merkleRoot', `Recomputed: ${expectedRoot.substring(0,16)}...\nDocument has: ${doc.merkleRoot.substring(0,16)}...`)
    } else {
      pass('merkleRoot', `Merkle root verified: ${doc.merkleRoot.substring(0,16)}...`)
    }

    // Step 6 — Hash chain
    if (this.currentDoc) {
      if (doc.version <= this.currentDoc.version) {
        fail('hashChain', `Version ${doc.version} <= current ${this.currentDoc.version} — rollback`)
      } else if (doc.prevDocumentHash !== this.currentDoc.documentHash) {
        fail('hashChain', `prevDocumentHash does not match current document hash`)
      } else {
        pass('hashChain', `Chain intact: v${this.currentDoc.version} -> v${doc.version}`)
      }
    } else {
      pass('hashChain', 'No previous version — this is the genesis document')
    }

    // Step 7 — Multi-signature verification
    // Signatures must be from the CURRENT admins (who authorize the new version)
    const signingAdmins = this.getActiveAdminAddresses()
    const docForSig = { ...unsignedClean, documentHash: doc.documentHash }
    const sigResult = verifyMultiSig(
      docForSig,
      doc.signatures,
      signingAdmins,
      CONFIG.MIN_SIGNATURES
    )
    if (!sigResult.valid) {
      fail('signatures', sigResult.reason!)
    } else {
      const signers = (doc.signatures as AdminSignature[]).map(s => s.adminAddress.substring(0, 10) + '...').join(', ')
      pass('signatures', `${doc.signatures.length} valid signatures from: ${signers}`)
    }

    // Step 8 — Admin addresses validation
    if (!Array.isArray(doc.adminAddresses) || doc.adminAddresses.length < CONFIG.MIN_SIGNATURES) {
      fail('adminAddresses', `Need at least ${CONFIG.MIN_SIGNATURES} admin addresses, got ${doc.adminAddresses?.length ?? 0}`)
    } else {
      const adminChanged = this.currentDoc
        ? JSON.stringify(doc.adminAddresses.map((a: string) => a.toLowerCase()).sort())
          !== JSON.stringify(this.currentDoc.adminAddresses.map((a: string) => a.toLowerCase()).sort())
        : false
      if (adminChanged) {
        pass('adminAddresses', `Admin rotation: ${doc.adminAddresses.length} new admins proposed`)
      } else {
        pass('adminAddresses', `${doc.adminAddresses.length} admin addresses (unchanged)`)
      }
    }

    // Step 9 — Threshold validation
    const threshold = doc.threshold ?? 0
    const activeNodes = Array.isArray(doc.nodes) ? doc.nodes.filter((n: any) => n.status === 'ACTIVE').length : 0
    if (threshold < 0) {
      fail('threshold', 'Threshold must be non-negative')
    } else if (threshold > activeNodes) {
      fail('threshold', `Threshold (${threshold}) exceeds active node count (${activeNodes})`)
    } else {
      pass('threshold', `Threshold ${threshold} <= ${activeNodes} active nodes`)
    }

    // Step 10 — Endpoints validation
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
    ikPub: string
    ekPub: string
    role: NodeRole
    walletScope: string[]
  }): { nodeId: string; draft: RegistryDocument } {
    // Reject if draft is locked (has signatures)
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    const now    = Math.floor(Date.now() / 1000)
    const nodeId = deriveNodeId(body.ikPub, body.role, now)

    // Validate
    if (!/^[0-9a-f]{64}$/i.test(body.ikPub)) throw new BadRequestException('ikPub must be 32 bytes (64 hex chars)')
    if (!/^[0-9a-f]{64}$/i.test(body.ekPub)) throw new BadRequestException('ekPub must be 32 bytes (64 hex chars)')
    if (!['USER_COSIGNER','PROVIDER_COSIGNER','RECOVERY_GUARDIAN'].includes(body.role)) {
      throw new BadRequestException('Invalid role')
    }
    if (!body.walletScope?.length) throw new BadRequestException('walletScope cannot be empty')

    // Check not already enrolled (active OR revoked — block re-enrollment of revoked keys)
    const draftNodes = this.stagedDraft?.nodes ?? this.currentDoc?.nodes ?? []
    if (draftNodes.some(n => n.ikPub === body.ikPub)) {
      throw new ConflictException('A node with this ikPub already exists')
    }

    // Auto-create draft if none exists
    if (!this.stagedDraft) {
      const nodes = this.currentDoc ? [...this.currentDoc.nodes] : []
      const base = this._buildDraft(nodes)
      this.stagedDraft = { ...base, signatures: [] }
    }

    // Check nodeId collision
    if (this.stagedDraft.nodes.some(n => n.nodeId === nodeId)) {
      throw new ConflictException('nodeId collision — try again')
    }

    // Add the node and auto-increment threshold
    const newNode: NodeRecord = { ...body, nodeId, status: 'ACTIVE', enrolledAt: now }
    this.stagedDraft.nodes.push(newNode)
    this.stagedDraft.threshold += 1
    this._refreshDraftHash()

    this.audit('ENROLL_PROPOSED', { nodeId, role: body.role })
    return { nodeId, draft: this.stagedDraft }
  }

  proposeRevoke(body: { nodeId: string; reason: string }): RegistryDocument {
    // Reject if draft is locked (has signatures)
    if (this.draftLocked) {
      throw new ConflictException('Draft is locked — it already has signatures. DELETE /registry/pending first.')
    }

    // Auto-create draft if none exists
    if (!this.stagedDraft) {
      if (!this.currentDoc) throw new NotFoundException(`Node ${body.nodeId} not found`)
      const nodes = [...this.currentDoc.nodes]
      const base = this._buildDraft(nodes)
      this.stagedDraft = { ...base, signatures: [] }
    }

    // Find node in the draft
    const node = this.stagedDraft.nodes.find(n => n.nodeId === body.nodeId)
    if (!node) throw new NotFoundException(`Node ${body.nodeId} not found`)
    if (node.status === 'REVOKED') throw new ConflictException('Node is already revoked')

    // Revoke, decrement threshold, and refresh hash
    const now = Math.floor(Date.now() / 1000)
    node.status = 'REVOKED'
    node.revokedAt = now
    if (this.stagedDraft.threshold > 0) {
      this.stagedDraft.threshold -= 1
    }
    this._refreshDraftHash()

    this.audit('REVOKE_PROPOSED', { nodeId: body.nodeId, reason: body.reason })
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
      registryId:            doc.registryId,
      version:               doc.version,
      issuedAt:              doc.issuedAt,
      expiresAt:             doc.expiresAt,
      adminAddresses:        doc.adminAddresses,
      backofficeServicePubkey: doc.backofficeServicePubkey ?? null,
      threshold:             doc.threshold ?? 0,
      endpoints:             doc.endpoints ?? null,
      nodes:                 doc.nodes,
      merkleRoot:            doc.merkleRoot,
      prevDocumentHash:      doc.prevDocumentHash,
      documentHash:          doc.documentHash,
      signatures:            doc.signatures,
    }

    // Persist
    this.currentDoc = clean
    this.stagedDraft = null
    this.draftLocked = false
    this.saveToDisk()
    this.audit('DOCUMENT_PUBLISHED', { version: doc.version, nodes: doc.nodes.length, admins: doc.adminAddresses.length })

    return { published: true, version: doc.version }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // INTERNAL HELPERS
  // ══════════════════════════════════════════════════════════════════════════

  /** Re-sort nodes, recompute merkleRoot + documentHash, clear signatures */
  private _refreshDraftHash() {
    if (!this.stagedDraft) return
    this.stagedDraft.nodes.sort((a, b) => a.nodeId.localeCompare(b.nodeId))
    this.stagedDraft.merkleRoot = computeMerkleRoot(this.stagedDraft.nodes)
    this.stagedDraft.documentHash = ''
    const { signatures: _, ...unsigned } = this.stagedDraft
    this.stagedDraft.documentHash = computeDocumentHash(unsigned as UnsignedDocument)
    this.stagedDraft.signatures = []
  }

  private _buildDraft(nodes: NodeRecord[]): UnsignedDocument {
    const sorted  = [...nodes].sort((a, b) => a.nodeId.localeCompare(b.nodeId))
    const now     = Math.floor(Date.now() / 1000)
    const nextV   = (this.currentDoc?.version ?? 0) + 1
    // Carry forward current admin addresses, or use genesis
    const admins  = this.getActiveAdminAddresses()
    const draft: UnsignedDocument = {
      registryId:            CONFIG.REGISTRY_ID,
      version:               nextV,
      issuedAt:              now,
      expiresAt:             now + CONFIG.EXPIRY_SECONDS,
      adminAddresses:        admins,
      backofficeServicePubkey: this.currentDoc?.backofficeServicePubkey ?? null,
      threshold:             this.currentDoc?.threshold ?? 0,
      endpoints:             this.currentDoc?.endpoints ?? null,
      nodes:                 sorted,
      merkleRoot:            computeMerkleRoot(sorted),
      prevDocumentHash:      this.currentDoc?.documentHash ?? null,
      documentHash:          '',
    }
    draft.documentHash = computeDocumentHash(draft)
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
