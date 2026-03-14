import { IsArray, IsString, IsNumber, ArrayNotEmpty, Min } from 'class-validator'

export class ProposeMpcPolicyDto {
  @IsArray()
  @ArrayNotEmpty()
  @IsString({ each: true })
  allowedCurves: string[]

  @IsArray()
  @ArrayNotEmpty()
  @IsString({ each: true })
  allowedProtocols: string[]

  @IsNumber()
  @Min(2)
  threshold: number
}
