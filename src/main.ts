import 'reflect-metadata'
import { NestFactory } from '@nestjs/core'
import { NestExpressApplication } from '@nestjs/platform-express'
import { ValidationPipe } from '@nestjs/common'
import { json } from 'express'
import { join } from 'path'
import { AppModule } from './app.module'
import { CONFIG } from './common/config'
import helmet from 'helmet'

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { logger: ['log','warn','error'] })

  app.use(helmet({
    contentSecurityPolicy: CONFIG.NODE_ENV === 'production' ? undefined : false,
  }))
  app.enableCors({
    origin: CONFIG.NODE_ENV === 'production'
      ? (process.env.CORS_ORIGINS?.split(',') ?? [])
      : true,
  })
  app.use(json({ limit: '1mb' }))
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }))
  app.setGlobalPrefix('api')

  // Serve static files (signing page)
  app.useStaticAssets(join(__dirname, '..', 'public'))

  await app.listen(CONFIG.PORT)
  console.log(`\nRegistry running at http://localhost:${CONFIG.PORT}/api`)
  console.log(`   Signing page: http://localhost:${CONFIG.PORT}/sign.html`)
  console.log(`   Health:  GET  /api/registry/health`)
  console.log(`   Current: GET  /api/registry/current`)
  console.log(`   Pending: GET  /api/registry/pending`)
  console.log(`   Verify:  POST /api/registry/verify\n`)
}

bootstrap().catch(console.error)
