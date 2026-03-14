import { IsArray, IsString, IsNumber, ArrayNotEmpty, Min } from 'class-validator'

export class ProposeMpcPolicyDto {
  @IsArray()
  @ArrayNotEmpty()
  @IsString({ each: true })
  allowed_curves: string[]

  @IsArray()
  @ArrayNotEmpty()
  @IsString({ each: true })
  allowed_protocols: string[]

  @IsNumber()
  @Min(2)
  admin_quorum: number
}
