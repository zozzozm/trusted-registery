import {
  IsArray,
  IsString,
  IsNumber,
  IsOptional,
  IsIn,
  ArrayMinSize,
  Min,
  Matches,
} from 'class-validator'
import type { GovernanceRoleName } from '../../common/types'

export class ProposeRoleDto {
  @IsIn(['SYSTEM_ADMIN', 'POLICY_COMPLIANCE', 'TREASURY_OPS', 'AUDIT_OBSERVER'])
  role: GovernanceRoleName

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
