import { IsString, IsNumber, IsArray, ValidateNested, IsIn, IsOptional, Matches } from 'class-validator'
import { Type } from 'class-transformer'

class NodeRecordDto {
  @IsString()
  nodeId: string

  @IsString()
  ikPub: string

  @IsString()
  ekPub: string

  @IsIn(['USER_COSIGNER', 'PROVIDER_COSIGNER', 'RECOVERY_GUARDIAN'])
  role: string

  @IsArray()
  @IsString({ each: true })
  walletScope: string[]

  @IsIn(['ACTIVE', 'REVOKED'])
  status: string

  @IsNumber()
  enrolledAt: number

  @IsOptional()
  @IsNumber()
  revokedAt?: number
}

class AdminSignatureDto {
  @Matches(/^0x[0-9a-fA-F]{40}$/, { message: 'adminAddress must be a valid Ethereum address' })
  adminAddress: string

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

export class VerifyDocumentDto {
  @IsString()
  registryId: string

  @IsNumber()
  version: number

  @IsNumber()
  issuedAt: number

  @IsNumber()
  expiresAt: number

  @IsArray()
  @IsString({ each: true })
  adminAddresses: string[]

  @IsOptional()
  @IsString()
  backofficeServicePubkey: string | null

  @IsNumber()
  threshold: number

  @IsOptional()
  @ValidateNested()
  @Type(() => EndpointsDto)
  endpoints: EndpointsDto | null

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => NodeRecordDto)
  nodes: NodeRecordDto[]

  @IsString()
  merkleRoot: string

  @IsOptional()
  prevDocumentHash: string | null

  @IsString()
  documentHash: string

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => AdminSignatureDto)
  signatures: AdminSignatureDto[]
}
