import {
  Controller, Get, Post, Body, Param, Query,
  HttpCode, HttpStatus,
  Delete
} from '@nestjs/common'
import { RegistryService } from './registry.service'
import {
  EnrollNodeDto, RevokeNodeDto, SignPendingDto,
  ProposeAdminsDto, VerifyDocumentDto, PublishDocumentDto
} from './dto'

@Controller('registry')
export class RegistryController {
  constructor(private readonly svc: RegistryService) {}

  // ── READ ──────────────────────────────────────────────────────────────────

  @Get('health')
  health() { return this.svc.getHealth() }

  @Get('current')
  current() { return this.svc.getCurrentDocument() }

  @Get('pending')
  pending() { return this.svc.getPendingDocument() }

  @Post('pending')
  @HttpCode(HttpStatus.CREATED)
  createPending() { return this.svc.createPendingDocument() }

  @Get('nodes')
  nodes(
    @Query('wallet') wallet?: string,
    @Query('role')   role?: string
  ) { return this.svc.getNodes(wallet, role) }

  @Get('nodes/:nodeId')
  node(@Param('nodeId') nodeId: string) { return this.svc.getNode(nodeId) }

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
  revoke(@Body() body: RevokeNodeDto) { return this.svc.proposeRevoke(body) }

  @Post('admins/propose')
  @HttpCode(HttpStatus.OK)
  proposeAdmins(@Body() body: ProposeAdminsDto) { return this.svc.proposeAdminChange(body) }

  @Post('publish')
  @HttpCode(HttpStatus.OK)
  publish(@Body() doc: PublishDocumentDto) { return this.svc.publishDocument(doc as any) }

  @Get('pending/message')
  pendingMessage() { return this.svc.getPendingSignPayload() }

  @Post('pending/sign')
  @HttpCode(HttpStatus.OK)
  sign(@Body() body: SignPendingDto) { return this.svc.signPendingDocument(body) }

  @Delete('pending')
  clearPending() { return this.svc.clearStagedDraft() }
}
