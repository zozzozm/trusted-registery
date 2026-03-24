import { IsOptional, IsString, IsArray, Matches } from 'class-validator'

export class ProposeInfrastructureDto {
  @IsOptional()
  @IsString()
  @Matches(/^0x[0-9a-fA-F]{40}$/, { message: 'backoffice_pubkey must be a valid Ethereum address' })
  backoffice_pubkey?: string

  @IsOptional()
  @IsString()
  @Matches(/^0x[0-9a-fA-F]{40}$/, { message: 'market_oracle_pubkey must be a valid Ethereum address' })
  market_oracle_pubkey?: string

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  trusted_binary_hashes?: string[]
}
