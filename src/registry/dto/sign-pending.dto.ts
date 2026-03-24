import { IsString, IsOptional, Matches } from 'class-validator'

export class SignPendingDto {
  @IsString()
  role: string

  @Matches(/^0x[0-9a-fA-F]{40}$/, { message: 'signer must be a valid Ethereum address' })
  signer: string

  @Matches(/^0x[0-9a-f]{130}$/i, { message: 'Signature must be 65 bytes hex (0x-prefixed)' })
  signature: string

  @IsOptional()
  @IsString()
  document_hash?: string
}
