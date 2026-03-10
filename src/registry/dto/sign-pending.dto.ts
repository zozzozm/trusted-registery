import { Matches, IsOptional, IsString } from 'class-validator'

export class SignPendingDto {
  @Matches(/^0x[0-9a-fA-F]{40}$/, { message: 'adminAddress must be a valid Ethereum address' })
  adminAddress: string

  @Matches(/^0x[0-9a-f]{130}$/i, { message: 'Signature must be 65 bytes hex (0x-prefixed)' })
  signature: string

  @IsOptional()
  @IsString()
  documentHash?: string
}
