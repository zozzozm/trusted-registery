import { IsString, IsNumber, IsArray, ValidateNested, IsIn, IsOptional, Matches, ArrayNotEmpty, Min } from 'class-validator'
import { Type } from 'class-transformer'

class NodeRecordDto {
  @IsString()
  node_id: string

  @IsString()
  ik_pub: string

  @IsString()
  ek_pub: string

  @IsIn(['USER_COSIGNER', 'PROVIDER_COSIGNER', 'RECOVERY_GUARDIAN'])
  role: string

  @IsIn(['ACTIVE', 'REVOKED'])
  status: string

  @IsNumber()
  enrolled_at: number

  @IsOptional()
  @IsNumber()
  revoked_at?: number
}

class AdminSignatureDto {
  @Matches(/^0x[0-9a-fA-F]{40}$/, { message: 'admin_address must be a valid Ethereum address' })
  admin_address: string

  @IsString()
  signature: string
}

class EndpointsDto {
  @IsString()
  primary: string

  @IsArray()
  @IsString({ each: true })
  mirrors: string[]

  @IsString()
  updated_at: string
}

class CeremonyBoundsDto {
  @IsNumber() @Min(2)
  min_signing_threshold: number

  @IsArray() @ArrayNotEmpty() @IsString({ each: true })
  allowed_protocols: string[]

  @IsArray() @ArrayNotEmpty() @IsString({ each: true })
  allowed_curves: string[]
}

export class VerifyDocumentDto {
  @IsString()
  registry_id: string

  @IsNumber()
  version: number

  @IsNumber()
  issued_at: number

  @IsNumber()
  expires_at: number

  @IsArray()
  @IsString({ each: true })
  admin_addresses: string[]

  @IsOptional()
  @IsString()
  backoffice_service_pubkey: string | null

  @ValidateNested()
  @Type(() => CeremonyBoundsDto)
  ceremony_bounds: CeremonyBoundsDto

  @IsOptional()
  @ValidateNested()
  @Type(() => EndpointsDto)
  endpoints: EndpointsDto | null

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => NodeRecordDto)
  nodes: NodeRecordDto[]

  @IsString()
  merkle_root: string

  @IsOptional()
  prev_document_hash: string | null

  @IsString()
  document_hash: string

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => AdminSignatureDto)
  signatures: AdminSignatureDto[]
}
