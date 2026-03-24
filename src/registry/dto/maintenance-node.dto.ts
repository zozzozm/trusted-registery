import { IsString } from 'class-validator'

export class MaintenanceNodeDto {
  @IsString()
  node_id: string

  @IsString()
  reason: string
}
