import {
  IsArray,
  IsString,
  IsNumber,
  IsOptional,
  IsIn,
  ValidateNested,
  ArrayNotEmpty,
  Min,
  Matches,
  ArrayMinSize,
} from 'class-validator'
import { Type } from 'class-transformer'

class GovernanceRoleDto {
  @IsIn(['SYSTEM_ADMIN', 'POLICY_COMPLIANCE', 'TREASURY_OPS', 'AUDIT_OBSERVER'])
  role: string

  @IsString()
  display_name: string

  @IsArray()
  @ArrayMinSize(1)
  @Matches(/^0x[0-9a-fA-F]{40}$/, { each: true, message: 'Each address must be a valid Ethereum address' })
  addresses: string[]

  @IsNumber()
  @Min(1)
  quorum: number

  @IsOptional()
  features?: Record<string, any>
}

class GovernanceDto {
  @IsArray()
  @ArrayNotEmpty()
  @ValidateNested({ each: true })
  @Type(() => GovernanceRoleDto)
  roles: GovernanceRoleDto[]
}

export class ProposeGovernanceDto {
  @ValidateNested()
  @Type(() => GovernanceDto)
  governance: GovernanceDto
}
