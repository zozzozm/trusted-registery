import 'reflect-metadata'
import { NestFactory } from '@nestjs/core'
import { ValidationPipe } from '@nestjs/common'
import { AppModule } from './app.module'
import { CONFIG } from './common/config'
import helmet from 'helmet'

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { logger: ['log','warn','error'] })

  app.use(helmet())
  app.enableCors()
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }))
  app.setGlobalPrefix('api')

  await app.listen(CONFIG.PORT)
  console.log(`\n🚀 Registry running at http://localhost:${CONFIG.PORT}/api`)
  console.log(`   Health:  GET  /api/registry/health`)
  console.log(`   Current: GET  /api/registry/current`)
  console.log(`   Pending: GET  /api/registry/pending`)
  console.log(`   Verify:  POST /api/registry/verify`)
  console.log(`   Enroll:  POST /api/registry/nodes/enroll`)
  console.log(`   Revoke:  POST /api/registry/nodes/revoke`)
  console.log(`   Publish: POST /api/registry/publish\n`)
}

bootstrap().catch(console.error)
