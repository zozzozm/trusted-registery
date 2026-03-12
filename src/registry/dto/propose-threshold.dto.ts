import { IsInt, Min } from 'class-validator'

export class ProposeThresholdDto {
  @IsInt()
  @Min(0)
  threshold: number
}
