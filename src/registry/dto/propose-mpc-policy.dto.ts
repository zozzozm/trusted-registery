import { IsArray, IsString, IsNumber, ArrayNotEmpty, Min, ValidateNested } from 'class-validator'
import { Type } from 'class-transformer'

class CeremonyBoundsDto {
  @IsNumber() @Min(2)
  min_signing_threshold: number

  @IsArray() @ArrayNotEmpty() @IsString({ each: true })
  allowed_protocols: string[]

  @IsArray() @ArrayNotEmpty() @IsString({ each: true })
  allowed_curves: string[]
}

export class ProposeMpcPolicyDto {
  @ValidateNested()
  @Type(() => CeremonyBoundsDto)
  ceremony_bounds: CeremonyBoundsDto
}
