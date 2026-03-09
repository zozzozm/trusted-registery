import * as dotenv from 'dotenv'
dotenv.config({ path: '.env.test' })
import { Test } from '@nestjs/testing'
import { INestApplication, ValidationPipe } from '@nestjs/common'
import * as request from 'supertest'
import { AppModule } from '../src/app.module'
import { generateKeypair, signHex, computeDocumentHash, computeMerkleRoot } from '../src/common/crypto'
import { RegistryDocument, UnsignedDocument } from '../src/common/types'

let adminKeys: Array<{ pubKey: string; privKey: string }> = []
let app: INestApplication

beforeAll(async () => {
  adminKeys = await Promise.all([generateKeypair(), generateKeypair(), generateKeypair()])
  process.env.ADMIN_KEY_0_PUB      = adminKeys[0].pubKey
  process.env.ADMIN_KEY_1_PUB      = adminKeys[1].pubKey
  process.env.ADMIN_KEY_2_PUB      = adminKeys[2].pubKey
  process.env.DEV_ADMIN_KEY_0_PRIV = adminKeys[0].privKey
  process.env.DEV_ADMIN_KEY_1_PRIV = adminKeys[1].privKey
  process.env.DEV_ADMIN_KEY_2_PRIV = adminKeys[2].privKey
  process.env.REGISTRY_ID   = 'test-registry-v1'
  process.env.MIN_SIGNATURES = '2'
  process.env.REGISTRY_FILE  = '/tmp/test-registry-jest.json'

  const mod = await Test.createTestingModule({ imports: [AppModule] }).compile()
  app = mod.createNestApplication()
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }))
  app.setGlobalPrefix('api')
  await app.init()
})
afterAll(() => app.close())

async function buildDoc(overrides: Partial<UnsignedDocument> = {}): Promise<RegistryDocument> {
  const now = Math.floor(Date.now() / 1000)
  const u: UnsignedDocument = {
    registryId: 'test-registry-v1', version: 1,
    issuedAt: now, expiresAt: now + 3600,
    nodes: [], merkleRoot: computeMerkleRoot([]),
    prevDocumentHash: null, documentHash: '',
    ...overrides,
  }
  u.documentHash = computeDocumentHash(u)
  return {
    ...u,
    signatures: [
      { adminIndex: 0, signature: await signHex(u.documentHash, adminKeys[0].privKey) },
      { adminIndex: 1, signature: await signHex(u.documentHash, adminKeys[1].privKey) },
    ]
  }
}

describe('Health', () => {
  it('returns ok', async () => {
    const r = await request(app.getHttpServer()).get('/api/registry/health')
    expect(r.status).toBe(200)
    expect(r.body.status).toBe('ok')
  })
})

describe('Verify — each failure case', () => {
  it('missing fields', async () => {
    const r = await request(app.getHttpServer()).post('/api/registry/verify').send({ registryId: 'x' })
    expect(r.body.steps.find((s:any) => s.step==='structure').passed).toBe(false)
  })
  it('expired', async () => {
    const d = await buildDoc({ expiresAt: Math.floor(Date.now()/1000) - 1 })
    const { signatures:_, documentHash:__, ...body } = d
    d.documentHash = computeDocumentHash(body as any)
    d.signatures = [
      { adminIndex:0, signature: await signHex(d.documentHash, adminKeys[0].privKey) },
      { adminIndex:1, signature: await signHex(d.documentHash, adminKeys[1].privKey) },
    ]
    const r = await request(app.getHttpServer()).post('/api/registry/verify').send(d)
    expect(r.body.steps.find((s:any) => s.step==='expiry').passed).toBe(false)
  })
  it('tampered content', async () => {
    const d = await buildDoc()
    d.nodes = [{ nodeId:'hack', ikPub:'a'.repeat(64), ekPub:'b'.repeat(64), role:'RECOVERY_GUARDIAN', walletScope:['evil'], status:'ACTIVE', enrolledAt:1 }]
    const r = await request(app.getHttpServer()).post('/api/registry/verify').send(d)
    expect(r.body.steps.find((s:any) => s.step==='documentHash').passed).toBe(false)
  })
  it('only 1 signature', async () => {
    const d = await buildDoc()
    d.signatures = [d.signatures[0]]
    const r = await request(app.getHttpServer()).post('/api/registry/verify').send(d)
    expect(r.body.steps.find((s:any) => s.step==='signatures').passed).toBe(false)
  })
  it('valid document passes all steps', async () => {
    const d = await buildDoc()
    const r = await request(app.getHttpServer()).post('/api/registry/verify').send(d)
    expect(r.body.valid).toBe(true)
    expect(r.body.steps.every((s:any) => s.passed)).toBe(true)
  })
})

describe('Full publish flow', () => {
  it('publishes genesis', async () => {
    const d = await buildDoc()
    const r = await request(app.getHttpServer()).post('/api/registry/publish').send(d)
    expect(r.status).toBe(200)
    expect(r.body.version).toBe(1)
  })
  it('current returns v1', async () => {
    const r = await request(app.getHttpServer()).get('/api/registry/current')
    expect(r.body.version).toBe(1)
  })
  it('enroll proposes a draft', async () => {
    const r = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ikPub: 'a'.repeat(64), ekPub: 'b'.repeat(64),
      role: 'PROVIDER_COSIGNER', walletScope: ['wallet-001'],
    })
    expect(r.status).toBe(200)
    expect(r.body.draft.version).toBe(2)
    expect(r.body.draft.nodes.length).toBe(1)
  })
  it('sign and publish enrollment', async () => {
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body
    const signed: RegistryDocument = {
      ...pending,
      signatures: [
        { adminIndex:0, signature: await signHex(pending.documentHash, adminKeys[0].privKey) },
        { adminIndex:1, signature: await signHex(pending.documentHash, adminKeys[1].privKey) },
      ]
    }
    const r = await request(app.getHttpServer()).post('/api/registry/publish').send(signed)
    expect(r.body.version).toBe(2)
  })
  it('node appears in list', async () => {
    const r = await request(app.getHttpServer()).get('/api/registry/nodes')
    expect(r.body.length).toBe(1)
    expect(r.body[0].status).toBe('ACTIVE')
  })
})
