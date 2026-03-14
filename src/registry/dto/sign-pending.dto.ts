import { Matches, IsOptional, IsString } from 'class-validator'

export class SignPendingDto {
  @Matches(/^0x[0-9a-fA-F]{40}$/, { message: 'admin_address must be a valid Ethereum address' })
  admin_address: string

  @Matches(/^0x[0-9a-f]{130}$/i, { message: 'Signature must be 65 bytes hex (0x-prefixed)' })
  signature: string

  @IsOptional()
  @IsString()
  document_hash?: string
}
