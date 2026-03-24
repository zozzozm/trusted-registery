import { IsString } from 'class-validator'

export class ReactivateNodeDto {
  @IsString()
  node_id: string
}
