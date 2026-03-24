import { IsString, IsNotEmpty } from 'class-validator'

export class RevokeNodeDto {
  @IsString()
  @IsNotEmpty()
  node_id: string

  @IsString()
  @IsNotEmpty()
  reason: string
}
