import { IsInt, Min, Max, Matches, IsOptional, IsString } from 'class-validator'

export class SignPendingDto {
  @IsInt()
  @Min(0)
  @Max(2)
  adminIndex: number

  @Matches(/^[0-9a-f]{128}$/, { message: 'Signature must be 128 hex chars (64 bytes)' })
  signature: string

  @IsOptional()
  @IsString()
  documentHash?: string
}
