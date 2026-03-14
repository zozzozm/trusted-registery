import { Matches, IsIn } from 'class-validator'

export class EnrollNodeDto {
  @Matches(/^[0-9a-f]{64}$/, { message: 'ik_pub must be 32 bytes (64 hex chars)' })
  ik_pub: string

  @Matches(/^[0-9a-f]{64}$/, { message: 'ek_pub must be 32 bytes (64 hex chars)' })
  ek_pub: string

  @IsIn(['USER_COSIGNER', 'PROVIDER_COSIGNER', 'RECOVERY_GUARDIAN'])
  role: 'USER_COSIGNER' | 'PROVIDER_COSIGNER' | 'RECOVERY_GUARDIAN'
}
