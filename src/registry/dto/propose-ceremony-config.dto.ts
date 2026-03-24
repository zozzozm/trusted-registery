import { IsArray, IsString, IsNumber, ArrayNotEmpty, Min } from 'class-validator'

export class ProposeCeremonyConfigDto {
  @IsNumber()
  @Min(2)
  global_threshold_t: number

  @IsNumber()
  @Min(2)
  max_participants_n: number

  @IsArray()
  @ArrayNotEmpty()
  @IsString({ each: true })
  allowed_protocols: string[]

  @IsArray()
  @ArrayNotEmpty()
  @IsString({ each: true })
  allowed_curves: string[]
}
