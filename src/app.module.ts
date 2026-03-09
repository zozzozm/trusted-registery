import { Module } from '@nestjs/common'
import { RegistryModule } from './registry/registry.module'

@Module({ imports: [RegistryModule] })
export class AppModule {}
