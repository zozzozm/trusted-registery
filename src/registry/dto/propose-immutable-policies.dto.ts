import { IsNumber, IsBoolean, Min } from 'class-validator'

export class ProposeImmutablePoliciesDto {
  @IsNumber()
  @Min(0)
  max_withdrawal_usd_24h: number

  @IsBoolean()
  require_oracle_price: boolean

  @IsBoolean()
  enforce_whitelist: boolean
}
