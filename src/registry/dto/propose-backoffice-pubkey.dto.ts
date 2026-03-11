import { IsString, Matches } from 'class-validator'

export class ProposeBackofficePubkeyDto {
  @IsString()
  @Matches(/^[0-9a-fA-F]{64}$/, { message: 'backofficeServicePubkey must be 32 bytes (64 hex chars)' })
  backofficeServicePubkey: string
}
