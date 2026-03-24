import { IsString, IsArray, IsOptional, IsUrl } from 'class-validator'

export class ProposeEndpointsDto {
  @IsString()
  @IsUrl({ protocols: ['http', 'https'], require_protocol: true }, { message: 'primary must be a valid HTTP(S) URL' })
  primary: string

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  mirrors?: string[]
}
