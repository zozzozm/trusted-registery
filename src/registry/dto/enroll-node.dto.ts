import { IsString, Matches, IsIn, ArrayNotEmpty, IsArray } from 'class-validator'

export class EnrollNodeDto {
  @Matches(/^[0-9a-f]{64}$/, { message: 'ikPub must be 32 bytes (64 hex chars)' })
  ikPub: string

  @Matches(/^[0-9a-f]{64}$/, { message: 'ekPub must be 32 bytes (64 hex chars)' })
  ekPub: string

  @IsIn(['USER_COSIGNER', 'PROVIDER_COSIGNER', 'RECOVERY_GUARDIAN'])
  role: 'USER_COSIGNER' | 'PROVIDER_COSIGNER' | 'RECOVERY_GUARDIAN'

  @IsArray()
  @ArrayNotEmpty()
  @IsString({ each: true })
  walletScope: string[]
}
