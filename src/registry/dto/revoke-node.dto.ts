import { IsString, IsNotEmpty } from 'class-validator'

export class RevokeNodeDto {
  @IsString()
  @IsNotEmpty()
  nodeId: string

  @IsString()
  @IsNotEmpty()
  reason: string
}
