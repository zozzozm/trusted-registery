import { IsArray, Matches, ArrayMinSize } from 'class-validator'

export class ProposeAdminsDto {
  @IsArray()
  @ArrayMinSize(2)
  @Matches(/^0x[0-9a-fA-F]{40}$/, { each: true, message: 'Each address must be a valid Ethereum address' })
  admin_addresses: string[]
}
