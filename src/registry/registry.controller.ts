import {
  Controller, Get, Post, Body, Param, Query,
  HttpCode, HttpStatus,
  Delete
} from '@nestjs/common'
import { RegistryService } from './registry.service'
import {
  EnrollNodeDto, RevokeNodeDto, SignPendingDto,
  VerifyDocumentDto, PublishDocumentDto
} from './dto'

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

  @Post('verify')
  @HttpCode(HttpStatus.OK)
  verify(@Body() doc: VerifyDocumentDto) { return this.svc.verifyDocument(doc) }

  // ── WRITE (requires signed document) ─────────────────────────────────────

  @Post('nodes/enroll')
  @HttpCode(HttpStatus.OK)
  enroll(@Body() body: EnrollNodeDto) { return this.svc.proposeEnroll(body) }

  @Post('nodes/revoke')
  @HttpCode(HttpStatus.OK)
  revoke(@Body() body: RevokeNodeDto) {
    return this.svc.proposeRevoke(body)
  }

  @Post('publish')
  @HttpCode(HttpStatus.OK)
  publish(@Body() doc: PublishDocumentDto) { return this.svc.publishDocument(doc as any) }

  @Post('pending/sign')
  @HttpCode(HttpStatus.OK)
  sign(@Body() body: SignPendingDto) {
    return this.svc.signPendingDocument(body)
  }

  @Delete('pending')
  clearPending() { return this.svc.clearStagedDraft() }
}
