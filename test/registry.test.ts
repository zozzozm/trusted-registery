import * as dotenv from 'dotenv'
dotenv.config({ path: '.env.test' })
import { Test } from '@nestjs/testing'
import { INestApplication, ValidationPipe } from '@nestjs/common'
import request from 'supertest'
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
    const r = await request(app.getHttpServer()).post('/api/registry/verify').send({ registryId: 'x', version: 1, issuedAt: 1, expiresAt: 1, nodes: [], merkleRoot: 'x', prevDocumentHash: null, documentHash: 'x', signatures: [] })
    expect(r.status).toBe(200)
  })
  it('expired', async () => {
    const d = await buildDoc({ expiresAt: Math.floor(Date.now()/1000) - 1 })
    // Rebuild hash with new expiresAt
    const unsigned: UnsignedDocument = {
      registryId: d.registryId, version: d.version,
      issuedAt: d.issuedAt, expiresAt: d.expiresAt,
      nodes: d.nodes, merkleRoot: d.merkleRoot,
      prevDocumentHash: d.prevDocumentHash, documentHash: '',
    }
    d.documentHash = computeDocumentHash(unsigned)
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

describe('Security', () => {
  it('draft locked during signing — rejects enroll after sign', async () => {
    // Clear any existing draft
    await request(app.getHttpServer()).delete('/api/registry/pending')
    // Enroll a node to create a draft
    await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ikPub: 'c'.repeat(64), ekPub: 'd'.repeat(64),
      role: 'USER_COSIGNER', walletScope: ['wallet-002'],
    })
    // Sign with admin 0
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body
    const sig = await signHex(pending.documentHash, adminKeys[0].privKey)
    await request(app.getHttpServer()).post('/api/registry/pending/sign').send({
      adminIndex: 0, signature: sig,
    })
    // Now try to enroll another node — should be rejected (draft locked)
    const r = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ikPub: 'e'.repeat(64), ekPub: 'f'.repeat(64),
      role: 'USER_COSIGNER', walletScope: ['wallet-003'],
    })
    expect(r.status).toBe(409)
    // Clean up
    await request(app.getHttpServer()).delete('/api/registry/pending')
  })

  it('revoked node re-enrollment blocked', async () => {
    // Clear draft
    await request(app.getHttpServer()).delete('/api/registry/pending')
    // The node from the publish flow is 'a'.repeat(64) — revoke it
    const currentNodes = (await request(app.getHttpServer()).get('/api/registry/nodes')).body
    const activeNode = currentNodes.find((n: any) => n.status === 'ACTIVE')
    if (!activeNode) throw new Error('No active node to revoke')

    await request(app.getHttpServer()).post('/api/registry/nodes/revoke').send({
      nodeId: activeNode.nodeId, reason: 'test revocation',
    })
    // Sign and publish the revocation
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body
    const signed: RegistryDocument = {
      ...pending,
      signatures: [
        { adminIndex: 0, signature: await signHex(pending.documentHash, adminKeys[0].privKey) },
        { adminIndex: 1, signature: await signHex(pending.documentHash, adminKeys[1].privKey) },
      ]
    }
    await request(app.getHttpServer()).post('/api/registry/publish').send(signed)

    // Now try to re-enroll the same ikPub — should be blocked
    const r = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ikPub: activeNode.ikPub, ekPub: activeNode.ekPub,
      role: activeNode.role, walletScope: activeNode.walletScope,
    })
    expect(r.status).toBe(409)
  })

  it('replay attack — re-publishing same doc fails', async () => {
    const current = (await request(app.getHttpServer()).get('/api/registry/current')).body
    const r = await request(app.getHttpServer()).post('/api/registry/publish').send(current)
    expect(r.status).toBe(400)
  })

  it('field injection stripped — extra fields not persisted', async () => {
    // Clear draft
    await request(app.getHttpServer()).delete('/api/registry/pending')
    // Create a draft via pending
    await request(app.getHttpServer()).post('/api/registry/pending')
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body
    const docWithExtra = {
      ...pending,
      malicious: 'data',
      signatures: [
        { adminIndex: 0, signature: await signHex(pending.documentHash, adminKeys[0].privKey) },
        { adminIndex: 1, signature: await signHex(pending.documentHash, adminKeys[1].privKey) },
      ]
    }
    const r = await request(app.getHttpServer()).post('/api/registry/publish').send(docWithExtra)
    expect(r.status).toBe(200)

    const current = (await request(app.getHttpServer()).get('/api/registry/current')).body
    expect(current.malicious).toBeUndefined()
  })

  it('nodeId collision check', async () => {
    // This is hard to trigger naturally since nodeId includes timestamp,
    // but we verify the service rejects it via the duplicate ikPub check
    await request(app.getHttpServer()).delete('/api/registry/pending')
    const r1 = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ikPub: '1'.repeat(64), ekPub: '2'.repeat(64),
      role: 'RECOVERY_GUARDIAN', walletScope: ['wallet-x'],
    })
    expect(r1.status).toBe(200)
    // Same ikPub — should fail
    const r2 = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ikPub: '1'.repeat(64), ekPub: '3'.repeat(64),
      role: 'RECOVERY_GUARDIAN', walletScope: ['wallet-y'],
    })
    expect(r2.status).toBe(409)
    await request(app.getHttpServer()).delete('/api/registry/pending')
  })

  it('adminIndex validation — rejects invalid values', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    await request(app.getHttpServer()).post('/api/registry/pending')
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body

    // Negative index
    const r1 = await request(app.getHttpServer()).post('/api/registry/pending/sign').send({
      adminIndex: -1, signature: 'a'.repeat(128),
    })
    expect(r1.status).toBe(400)

    // Float
    const r2 = await request(app.getHttpServer()).post('/api/registry/pending/sign').send({
      adminIndex: 1.5, signature: 'a'.repeat(128),
    })
    expect(r2.status).toBe(400)

    // String
    const r3 = await request(app.getHttpServer()).post('/api/registry/pending/sign').send({
      adminIndex: 'abc', signature: 'a'.repeat(128),
    })
    expect(r3.status).toBe(400)

    await request(app.getHttpServer()).delete('/api/registry/pending')
  })

  it('walletScope validation — rejects invalid values', async () => {
    // Array of numbers
    const r1 = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ikPub: '5'.repeat(64), ekPub: '6'.repeat(64),
      role: 'USER_COSIGNER', walletScope: [123],
    })
    expect(r1.status).toBe(400)

    // Empty array
    const r2 = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ikPub: '5'.repeat(64), ekPub: '6'.repeat(64),
      role: 'USER_COSIGNER', walletScope: [],
    })
    expect(r2.status).toBe(400)
  })

  it('documentHash mismatch on sign — rejects stale hash', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    await request(app.getHttpServer()).post('/api/registry/pending')
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body

    const sig = await signHex(pending.documentHash, adminKeys[0].privKey)
    const r = await request(app.getHttpServer()).post('/api/registry/pending/sign').send({
      adminIndex: 0, signature: sig, documentHash: 'wrong_hash_value',
    })
    expect(r.status).toBe(409)

    await request(app.getHttpServer()).delete('/api/registry/pending')
  })
})
