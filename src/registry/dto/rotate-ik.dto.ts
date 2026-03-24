import { IsString, Matches } from 'class-validator'

export class RotateIkDto {
  @IsString()
  node_id: string

  @Matches(/^[0-9a-fA-F]{64}$/, { message: 'new_ik_pub must be 32 bytes (64 hex chars)' })
  new_ik_pub: string

  @IsString()
  reason: string

  @Matches(/^[0-9a-fA-F]+$/, { message: 'proof must be hex-encoded Ed25519 signature' })
  proof: string
}
