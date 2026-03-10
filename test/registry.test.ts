// Set env vars BEFORE any imports that read config
import { unlinkSync } from 'fs'

const TEST_REGISTRY_FILE = '/tmp/test-registry-jest.json'
try { unlinkSync(TEST_REGISTRY_FILE) } catch {}
process.env.REGISTRY_FILE = TEST_REGISTRY_FILE
process.env.REGISTRY_ID = 'test-registry-v1'
process.env.MIN_SIGNATURES = '2'

import * as dotenv from 'dotenv'
dotenv.config({ path: '.env.test' })
import { Test } from '@nestjs/testing'
import { INestApplication, ValidationPipe } from '@nestjs/common'
import request from 'supertest'
import { ethers } from 'ethers'
import { AppModule } from '../src/app.module'
import { signDocument, computeDocumentHash, computeMerkleRoot, buildSignMessage } from '../src/common/crypto'
import { RegistryDocument, UnsignedDocument } from '../src/common/types'

let wallets: ethers.HDNodeWallet[] = []
let app: INestApplication

beforeAll(async () => {
  wallets = [
    ethers.Wallet.createRandom(),
    ethers.Wallet.createRandom(),
    ethers.Wallet.createRandom(),
  ]
  process.env.ADMIN_ADDRESS_0      = wallets[0].address
  process.env.ADMIN_ADDRESS_1      = wallets[1].address
  process.env.ADMIN_ADDRESS_2      = wallets[2].address
  process.env.DEV_ADMIN_PRIVKEY_0  = wallets[0].privateKey
  process.env.DEV_ADMIN_PRIVKEY_1  = wallets[1].privateKey
  process.env.DEV_ADMIN_PRIVKEY_2  = wallets[2].privateKey

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
  const message = buildSignMessage(u.documentHash)
  return {
    ...u,
    signatures: [
      { adminAddress: wallets[0].address, signature: await wallets[0].signMessage(message) },
      { adminAddress: wallets[1].address, signature: await wallets[1].signMessage(message) },
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
    const message = buildSignMessage(d.documentHash)
    d.signatures = [
      { adminAddress: wallets[0].address, signature: await wallets[0].signMessage(message) },
      { adminAddress: wallets[1].address, signature: await wallets[1].signMessage(message) },
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
    const message = buildSignMessage(pending.documentHash)
    const signed: RegistryDocument = {
      ...pending,
      signatures: [
        { adminAddress: wallets[0].address, signature: await wallets[0].signMessage(message) },
        { adminAddress: wallets[1].address, signature: await wallets[1].signMessage(message) },
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
    await request(app.getHttpServer()).delete('/api/registry/pending')
    await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ikPub: 'c'.repeat(64), ekPub: 'd'.repeat(64),
      role: 'USER_COSIGNER', walletScope: ['wallet-002'],
    })
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body
    const sig = await signDocument(pending.documentHash, wallets[0].privateKey)
    await request(app.getHttpServer()).post('/api/registry/pending/sign').send({
      adminAddress: wallets[0].address, signature: sig,
    })
    const r = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ikPub: 'e'.repeat(64), ekPub: 'f'.repeat(64),
      role: 'USER_COSIGNER', walletScope: ['wallet-003'],
    })
    expect(r.status).toBe(409)
    await request(app.getHttpServer()).delete('/api/registry/pending')
  })

  it('revoked node re-enrollment blocked', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    const currentNodes = (await request(app.getHttpServer()).get('/api/registry/nodes')).body
    const activeNode = currentNodes.find((n: any) => n.status === 'ACTIVE')
    if (!activeNode) throw new Error('No active node to revoke')

    await request(app.getHttpServer()).post('/api/registry/nodes/revoke').send({
      nodeId: activeNode.nodeId, reason: 'test revocation',
    })
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body
    const message = buildSignMessage(pending.documentHash)
    const signed: RegistryDocument = {
      ...pending,
      signatures: [
        { adminAddress: wallets[0].address, signature: await wallets[0].signMessage(message) },
        { adminAddress: wallets[1].address, signature: await wallets[1].signMessage(message) },
      ]
    }
    await request(app.getHttpServer()).post('/api/registry/publish').send(signed)

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
    await request(app.getHttpServer()).delete('/api/registry/pending')
    await request(app.getHttpServer()).post('/api/registry/pending')
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body
    const message = buildSignMessage(pending.documentHash)
    const docWithExtra = {
      ...pending,
      malicious: 'data',
      signatures: [
        { adminAddress: wallets[0].address, signature: await wallets[0].signMessage(message) },
        { adminAddress: wallets[1].address, signature: await wallets[1].signMessage(message) },
      ]
    }
    const r = await request(app.getHttpServer()).post('/api/registry/publish').send(docWithExtra)
    expect(r.status).toBe(200)

    const current = (await request(app.getHttpServer()).get('/api/registry/current')).body
    expect(current.malicious).toBeUndefined()
  })

  it('nodeId collision check', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    const r1 = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ikPub: '1'.repeat(64), ekPub: '2'.repeat(64),
      role: 'RECOVERY_GUARDIAN', walletScope: ['wallet-x'],
    })
    expect(r1.status).toBe(200)
    const r2 = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ikPub: '1'.repeat(64), ekPub: '3'.repeat(64),
      role: 'RECOVERY_GUARDIAN', walletScope: ['wallet-y'],
    })
    expect(r2.status).toBe(409)
    await request(app.getHttpServer()).delete('/api/registry/pending')
  })

  it('adminAddress validation — rejects invalid values', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    await request(app.getHttpServer()).post('/api/registry/pending')

    // Invalid address format
    const r1 = await request(app.getHttpServer()).post('/api/registry/pending/sign').send({
      adminAddress: 'not-an-address', signature: '0x' + 'a'.repeat(130),
    })
    expect(r1.status).toBe(400)

    // Missing 0x prefix on address
    const r2 = await request(app.getHttpServer()).post('/api/registry/pending/sign').send({
      adminAddress: 'a'.repeat(40), signature: '0x' + 'a'.repeat(130),
    })
    expect(r2.status).toBe(400)

    await request(app.getHttpServer()).delete('/api/registry/pending')
  })

  it('walletScope validation — rejects invalid values', async () => {
    const r1 = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ikPub: '5'.repeat(64), ekPub: '6'.repeat(64),
      role: 'USER_COSIGNER', walletScope: [123],
    })
    expect(r1.status).toBe(400)

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

    const sig = await signDocument(pending.documentHash, wallets[0].privateKey)
    const r = await request(app.getHttpServer()).post('/api/registry/pending/sign').send({
      adminAddress: wallets[0].address, signature: sig, documentHash: 'wrong_hash_value',
    })
    expect(r.status).toBe(409)

    await request(app.getHttpServer()).delete('/api/registry/pending')
  })
})
