import {
  Controller, Get, Post, Body, Param, Query,
  HttpCode, HttpStatus,
  Delete
} from '@nestjs/common'
import { RegistryService } from './registry.service'
import {
  EnrollNodeDto, RevokeNodeDto, SignPendingDto,
  ProposeRoleDto, ProposeInfrastructureDto,
  ProposeEndpointsDto, ProposeCeremonyConfigDto,
  ProposeImmutablePoliciesDto, VerifyDocumentDto,
  PublishDocumentDto, RotateIkDto, MaintenanceNodeDto,
  ReactivateNodeDto
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
    @Query('role') role?: string
  ) { return this.svc.getNodes(role) }

  @Get('nodes/:nodeId')
  node(@Param('nodeId') nodeId: string) { return this.svc.getNode(nodeId) }

  @Get('audit')
  audit() { return this.svc.getAuditLog() }

  @Get('versions')
  versions() { return this.svc.getVersionList() }

  @Get('versions/:version')
  version(@Param('version') version: string) {
    return this.svc.getVersion(parseInt(version, 10))
  }

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

  @Post('nodes/rotate-ik')
  @HttpCode(HttpStatus.OK)
  rotateIk(@Body() body: RotateIkDto) { return this.svc.proposeIkRotation(body) }

  @Post('nodes/maintenance')
  @HttpCode(HttpStatus.OK)
  maintenance(@Body() body: MaintenanceNodeDto) { return this.svc.proposeNodeMaintenance(body) }

  @Post('nodes/reactivate')
  @HttpCode(HttpStatus.OK)
  reactivate(@Body() body: ReactivateNodeDto) { return this.svc.proposeNodeReactivate(body) }

  @Post('governance/role')
  @HttpCode(HttpStatus.OK)
  proposeGovernanceRole(@Body() body: ProposeRoleDto) { return this.svc.proposeGovernanceRole(body) }

  @Post('infrastructure/propose')
  @HttpCode(HttpStatus.OK)
  proposeInfrastructure(@Body() body: ProposeInfrastructureDto) { return this.svc.proposeInfrastructure(body) }

  @Post('ceremony-config/propose')
  @HttpCode(HttpStatus.OK)
  proposeCeremonyConfig(@Body() body: ProposeCeremonyConfigDto) { return this.svc.proposeCeremonyConfig({ ceremony_config: body }) }

  @Post('immutable-policies/propose')
  @HttpCode(HttpStatus.OK)
  proposeImmutablePolicies(@Body() body: ProposeImmutablePoliciesDto) { return this.svc.proposeImmutablePolicies({ immutable_policies: body }) }

  @Post('endpoints/propose')
  @HttpCode(HttpStatus.OK)
  proposeEndpoints(@Body() body: ProposeEndpointsDto) { return this.svc.proposeEndpoints(body) }

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
