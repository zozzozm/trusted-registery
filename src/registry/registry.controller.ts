import {
  Controller, Get, Post, Body, Param, Query,
  HttpCode, HttpStatus,
  Delete
} from '@nestjs/common'
import { RegistryService } from './registry.service'

@Controller('registry')
export class RegistryController {
  constructor(private readonly svc: RegistryService) {}

  // ── READ ──────────────────────────────────────────────────────────────────

  /** GET /registry/health — server status + admin key fingerprints */
  @Get('health')
  health() { return this.svc.getHealth() }

  /** GET /registry/current — the active signed registry document */
  @Get('current')
  current() { return this.svc.getCurrentDocument() }

  /**
   * GET /registry/pending
   * Returns the currently staged pending draft (read-only).
   */
  @Get('pending')
  pending() { return this.svc.getPendingDocument() }

  /**
   * POST /registry/pending
   * Create a new pending draft from the current published nodes.
   * Fails if a draft already exists — DELETE /registry/pending first.
   */
  @Post('pending')
  @HttpCode(HttpStatus.CREATED)
  createPending() { return this.svc.createPendingDocument() }

  /** GET /registry/nodes — list nodes, optionally filter by wallet or role */
  @Get('nodes')
  nodes(
    @Query('wallet') wallet?: string,
    @Query('role')   role?: string
  ) { return this.svc.getNodes(wallet, role) }

  /** GET /registry/nodes/:nodeId — get one node record */
  @Get('nodes/:nodeId')
  node(@Param('nodeId') nodeId: string) { return this.svc.getNode(nodeId) }

  /** GET /registry/audit — audit event log (newest first) */
  @Get('audit')
  audit() { return this.svc.getAuditLog() }

  // ── VERIFY ────────────────────────────────────────────────────────────────

  /**
   * POST /registry/verify
   * ⭐ THE MAIN LEARNING ENDPOINT
   * Submit any document and get a step-by-step verification report.
   * Use this with Postman/curl to understand exactly what the system checks.
   */
  @Post('verify')
  @HttpCode(HttpStatus.OK)
  verify(@Body() doc: any) { return this.svc.verifyDocument(doc) }

  // ── WRITE (requires signed document) ─────────────────────────────────────

  /**
   * POST /registry/nodes/enroll
   * Propose enrolling a new node.
   * Returns: { nodeId, draft } — sign the draft offline, then publish.
   */
  @Post('nodes/enroll')
  @HttpCode(HttpStatus.OK)
  enroll(@Body() body: {
    ikPub: string
    ekPub: string
    role: 'USER_COSIGNER' | 'PROVIDER_COSIGNER' | 'RECOVERY_GUARDIAN'
    walletScope: string[]
  }) { return this.svc.proposeEnroll(body) }

  /**
   * POST /registry/nodes/revoke
   * Propose revoking a node.
   * Returns: draft — sign it offline, then publish.
   */
  @Post('nodes/revoke')
  @HttpCode(HttpStatus.OK)
  revoke(@Body() body: { nodeId: string; reason: string }) {
    return this.svc.proposeRevoke(body)
  }

  /**
   * POST /registry/publish
   * Submit a fully signed registry document.
   * This is the ONLY way to change the registry state.
   * The document must have >= 2 valid admin signatures.
   */
  @Post('publish')
  @HttpCode(HttpStatus.OK)
  publish(@Body() doc: any) { return this.svc.publishDocument(doc) }

  /**
   * POST /registry/pending/sign
   * Add one admin signature to the staged draft.
   * Call GET /pending first to get the draft and its documentHash.
   */
  @Post('pending/sign')
  @HttpCode(HttpStatus.OK)
  sign(@Body() body: { adminIndex: number; signature: string }) {
    return this.svc.signPendingDocument(body)
  }

  @Delete('pending')
  clearPending() { return this.svc.clearStagedDraft() }
}
