// ─────────────────────────────────────────────────────────────────────────────
// Registry Service — the heart of the system
// Manages the in-memory registry state and all verification logic
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, OnModuleInit, BadRequestException, NotFoundException, ConflictException } from '@nestjs/common'
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs'
import { dirname } from 'path'
import {
  RegistryDocument, UnsignedDocument, NodeRecord, AdminSignature,
  NodeRole, VerifyResult
} from '../common/types'
import {
  computeDocumentHash, computeMerkleRoot, verifyMultiSig,
  verifyHex, deriveNodeId, hashObject
} from '../common/crypto'
import { CONFIG } from '../common/config'

@Injectable()
export class RegistryService implements OnModuleInit {

  // ── In-memory state ───────────────────────────────────────────────────────
  private currentDoc: RegistryDocument | null = null
  private pendingNodes: Map<string, NodeRecord> = new Map()  // nodeId → record
  private auditLog: Array<{ event: string; detail: object; at: number }> = []
  private stagedDraft: RegistryDocument | null = null

  onModuleInit() {
    this.loadFromDisk()
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

  /** POST /registry/pending/sign — add one admin signature to the staged draft */
  signPendingDocument(body: { adminIndex: number; signature: string }): RegistryDocument {
    if (!this.stagedDraft) throw new NotFoundException('No pending document. Call GET /registry/pending first.')

    const { adminIndex, signature } = body

    // Validate adminIndex
    const pubKey = CONFIG.ADMIN_KEYS[adminIndex]
    if (pubKey === undefined) throw new BadRequestException(`Unknown adminIndex: ${adminIndex}`)

    // Check for duplicate
    if (this.stagedDraft.signatures.some(s => s.adminIndex === adminIndex)) {
      throw new ConflictException(`Admin ${adminIndex} has already signed this draft`)
    }

    // Validate signature format
    if (!/^[0-9a-f]{128}$/i.test(signature)) {
      throw new BadRequestException('Signature must be 128 hex chars (64 bytes)')
    }

    // Verify signature against documentHash
    const ok = verifyHex(this.stagedDraft.documentHash, signature, pubKey)
    if (!ok) throw new BadRequestException('Signature verification failed')

    this.stagedDraft.signatures.push({ adminIndex, signature })
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
    return {
      status:      'ok',
      registryId:  CONFIG.REGISTRY_ID,
      version:     doc?.version ?? 0,
      totalNodes:  doc?.nodes.length ?? 0,
      activeNodes: doc?.nodes.filter(n => n.status === 'ACTIVE').length ?? 0,
      expiresAt:   doc?.expiresAt ?? null,
      expired:     doc ? Math.floor(Date.now() / 1000) > doc.expiresAt : null,
      adminKeys:   CONFIG.ADMIN_KEYS.map((k, i) => ({
        index:       i,
        pubKey:      k.substring(0, 16) + '...',  // show first 8 bytes for debug
      })),
    }
  }

  /** GET /registry/audit */
  getAuditLog() {
    return this.auditLog.slice().reverse()  // newest first
  }

  // ══════════════════════════════════════════════════════════════════════════
  // VERIFY ENDPOINT — the main learning/testing endpoint
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * POST /registry/verify
   * Accepts any registry document and runs every verification step,
   * returning a detailed report of what passed and what failed.
   * This is the endpoint you use to learn and test the system.
   */
  verifyDocument(doc: any): object {
    const steps: Array<{ step: string; passed: boolean; detail: string }> = []

    const pass = (step: string, detail: string) => steps.push({ step, passed: true,  detail })
    const fail = (step: string, detail: string) => steps.push({ step, passed: false, detail })

    // Step 1 — Structure
    const required = ['registryId','version','issuedAt','expiresAt','nodes','merkleRoot','prevDocumentHash','documentHash']
    const missing  = required.filter(f => doc[f] === undefined)
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

    // Step 4 — Document hash integrity
const { signatures: _s, ...bodyWithHash } = doc
const bodyForHash = { ...bodyWithHash, documentHash: '' }
const expectedHash = computeDocumentHash(bodyForHash as UnsignedDocument)
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
        fail('hashChain', `Version ${doc.version} ≤ current ${this.currentDoc.version} — rollback`)
      } else if (doc.prevDocumentHash !== this.currentDoc.documentHash) {
        fail('hashChain', `prevDocumentHash does not match current document hash`)
      } else {
        pass('hashChain', `Chain intact: v${this.currentDoc.version} → v${doc.version}`)
      }
    } else {
      pass('hashChain', 'No previous version — this is the genesis document')
    }

    // Step 7 — Multi-signature verification
    const sigResult = verifyMultiSig(
      doc.documentHash,
      doc.signatures,
      CONFIG.ADMIN_KEYS,
      CONFIG.MIN_SIGNATURES
    )
    if (!sigResult.valid) {
      fail('signatures', sigResult.reason!)
    } else {
      const signers = (doc.signatures as AdminSignature[]).map(s => `admin[${s.adminIndex}]`).join(', ')
      pass('signatures', `${doc.signatures.length} valid signatures from: ${signers}`)
    }

    const allPassed = steps.every(s => s.passed)
    return { valid: allPassed, steps, summary: allPassed ? '✓ Document is valid' : '✗ Document failed verification' }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // WRITE ENDPOINTS (require signed document)
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * POST /registry/nodes/enroll
   * Upsert a new node into the staged pending draft.
   * Creates a draft if none exists. Recomputes hash and clears signatures.
   */
  proposeEnroll(body: {
    ikPub: string
    ekPub: string
    role: NodeRole
    walletScope: string[]
  }): { nodeId: string; draft: RegistryDocument } {
    const now    = Math.floor(Date.now() / 1000)
    const nodeId = deriveNodeId(body.ikPub, body.role, now)

    // Validate
    if (!/^[0-9a-f]{64}$/i.test(body.ikPub)) throw new BadRequestException('ikPub must be 32 bytes (64 hex chars)')
    if (!/^[0-9a-f]{64}$/i.test(body.ekPub)) throw new BadRequestException('ekPub must be 32 bytes (64 hex chars)')
    if (!['USER_COSIGNER','PROVIDER_COSIGNER','RECOVERY_GUARDIAN'].includes(body.role)) {
      throw new BadRequestException('Invalid role')
    }
    if (!body.walletScope?.length) throw new BadRequestException('walletScope cannot be empty')

    // Check not already enrolled (in published doc or in the draft)
    const draftNodes = this.stagedDraft?.nodes ?? this.currentDoc?.nodes ?? []
    if (draftNodes.some(n => n.ikPub === body.ikPub && n.status === 'ACTIVE')) {
      throw new ConflictException('A node with this ikPub is already active')
    }

    // Auto-create draft if none exists
    if (!this.stagedDraft) {
      const nodes = this.currentDoc ? [...this.currentDoc.nodes] : []
      const base = this._buildDraft(nodes)
      this.stagedDraft = { ...base, signatures: [] }
    }

    // Add the node and refresh hash
    const newNode: NodeRecord = { ...body, nodeId, status: 'ACTIVE', enrolledAt: now }
    this.stagedDraft.nodes.push(newNode)
    this._refreshDraftHash()

    this.audit('ENROLL_PROPOSED', { nodeId, role: body.role })
    return { nodeId, draft: this.stagedDraft }
  }

  /**
   * POST /registry/nodes/revoke
   * Mark a node as REVOKED in the staged pending draft.
   * Creates a draft if none exists. Recomputes hash and clears signatures.
   */
  proposeRevoke(body: { nodeId: string; reason: string }): RegistryDocument {
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

    // Revoke and refresh hash
    const now = Math.floor(Date.now() / 1000)
    node.status = 'REVOKED'
    node.revokedAt = now
    this._refreshDraftHash()

    this.audit('REVOKE_PROPOSED', { nodeId: body.nodeId, reason: body.reason })
    return this.stagedDraft
  }

  clearStagedDraft() {
    this.stagedDraft = null
    return { cleared: true }
  }
  /**
   * POST /registry/publish
   * Submit a fully signed document. This becomes the new current registry.
   * This is the only way to change the registry state.
   */
  publishDocument(doc: RegistryDocument): { published: boolean; version: number } {
    // Full verification
    const result = this.verifyDocument(doc) as any
    if (!result.valid) {
      const failed = result.steps.filter((s: any) => !s.passed).map((s: any) => s.detail).join('; ')
      throw new BadRequestException(`Document invalid: ${failed}`)
    }

    // Persist
    this.currentDoc = doc
    this.stagedDraft = null  // ← clear so next pending is fresh
    this.saveToDisk()
    this.audit('DOCUMENT_PUBLISHED', { version: doc.version, nodes: doc.nodes.length })

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
    const draft: UnsignedDocument = {
      registryId:       CONFIG.REGISTRY_ID,
      version:          nextV,
      issuedAt:         now,
      expiresAt:        now + CONFIG.EXPIRY_SECONDS,
      nodes:            sorted,
      merkleRoot:       computeMerkleRoot(sorted),
      prevDocumentHash: this.currentDoc?.documentHash ?? null,
      documentHash:     '',
    }
    draft.documentHash = computeDocumentHash(draft)
    return draft
  }

  private audit(event: string, detail: object) {
    this.auditLog.push({ event, detail, at: Math.floor(Date.now() / 1000) })
    if (this.auditLog.length > 200) this.auditLog.shift()
  }

  private loadFromDisk() {
    try {
      if (existsSync(CONFIG.REGISTRY_FILE)) {
        const raw = readFileSync(CONFIG.REGISTRY_FILE, 'utf-8')
        this.currentDoc = JSON.parse(raw)
        console.log(`[Registry] Loaded version ${this.currentDoc?.version} from disk`)
      } else {
        console.log('[Registry] No registry file found — starting empty')
      }
    } catch (e) {
      console.error('[Registry] Failed to load from disk:', e)
    }
  }

  private saveToDisk() {
    const dir = dirname(CONFIG.REGISTRY_FILE)
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
    writeFileSync(CONFIG.REGISTRY_FILE, JSON.stringify(this.currentDoc, null, 2))
    console.log(`[Registry] Saved version ${this.currentDoc?.version} to disk`)
  }
}
