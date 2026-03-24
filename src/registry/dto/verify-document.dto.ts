import { IsString, IsNumber, IsArray, ValidateNested, IsIn, IsOptional, IsBoolean, Matches, ArrayNotEmpty, Min } from 'class-validator'
import { Type } from 'class-transformer'

class IkRotationEntryDto {
  @IsString()
  prev_ik_pub: string

  @IsString()
  new_ik_pub: string

  @IsNumber()
  rotated_at: number

  @IsString()
  reason: string

  @IsString()
  proof: string
}

class NodeRecordDto {
  @IsString()
  node_id: string

  @IsString()
  ik_pub: string

  @IsString()
  ek_pub: string

  @IsIn(['USER_COSIGNER', 'PROVIDER_COSIGNER', 'RECOVERY_GUARDIAN'])
  role: string

  @IsIn(['ACTIVE', 'REVOKED', 'MAINTENANCE'])
  status: string

  @IsNumber()
  enrolled_at: number

  @IsOptional()
  @IsNumber()
  updated_at?: number

  @IsOptional()
  @IsNumber()
  revoked_at?: number

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => IkRotationEntryDto)
  ik_rotations?: IkRotationEntryDto[]
}

class RoleSignatureDto {
  @IsString()
  role: string

  @Matches(/^0x[0-9a-fA-F]{40}$/, { message: 'signer must be a valid Ethereum address' })
  signer: string

  @IsString()
  signature: string
}

class EndpointsDto {
  @IsString()
  primary: string

  @IsArray()
  @IsString({ each: true })
  mirrors: string[]
}

class CeremonyConfigDto {
  @IsNumber() @Min(2)
  global_threshold_t: number

  @IsNumber() @Min(2)
  max_participants_n: number

  @IsArray() @ArrayNotEmpty() @IsString({ each: true })
  allowed_protocols: string[]

  @IsArray() @ArrayNotEmpty() @IsString({ each: true })
  allowed_curves: string[]
}

class GovernanceRoleDto {
  @IsIn(['SYSTEM_ADMIN', 'POLICY_COMPLIANCE', 'TREASURY_OPS', 'AUDIT_OBSERVER'])
  role: string

  @IsString()
  display_name: string

  @IsArray()
  @Matches(/^0x[0-9a-fA-F]{40}$/, { each: true })
  addresses: string[]

  @IsNumber() @Min(1)
  quorum: number

  @IsOptional()
  features?: Record<string, any>
}

class GovernanceDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => GovernanceRoleDto)
  roles: GovernanceRoleDto[]
}

class RegistryMetadataDto {
  @IsString()
  registry_id: string

  @IsNumber()
  version: number

  @IsNumber()
  issued_at: number

  @IsNumber()
  expires_at: number

  @IsString()
  updated_at: string

  @IsString()
  document_hash: string

  @IsString()
  merkle_root: string

  @IsOptional()
  prev_document_hash: string | null

  @IsOptional()
  @ValidateNested()
  @Type(() => EndpointsDto)
  endpoints: EndpointsDto | null
}

class TrustedInfrastructureDto {
  @IsOptional()
  @IsString()
  backoffice_pubkey: string | null

  @IsOptional()
  @IsString()
  market_oracle_pubkey: string | null

  @IsArray()
  @IsString({ each: true })
  trusted_binary_hashes: string[]
}

class ImmutablePoliciesDto {
  @IsNumber() @Min(0)
  max_withdrawal_usd_24h: number

  @IsBoolean()
  require_oracle_price: boolean

  @IsBoolean()
  enforce_whitelist: boolean
}

export class VerifyDocumentDto {
  @ValidateNested()
  @Type(() => RegistryMetadataDto)
  registry_metadata: RegistryMetadataDto

  @ValidateNested()
  @Type(() => GovernanceDto)
  governance: GovernanceDto

  @ValidateNested()
  @Type(() => CeremonyConfigDto)
  ceremony_config: CeremonyConfigDto

  @ValidateNested()
  @Type(() => TrustedInfrastructureDto)
  trusted_infrastructure: TrustedInfrastructureDto

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => NodeRecordDto)
  nodes: NodeRecordDto[]

  @ValidateNested()
  @Type(() => ImmutablePoliciesDto)
  immutable_policies: ImmutablePoliciesDto

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => RoleSignatureDto)
  signatures: RoleSignatureDto[]
}
