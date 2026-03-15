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
import { signDocument, computeDocumentHash, computeMerkleRoot, EIP712_DOMAIN, EIP712_TYPES, buildTypedDataValue } from '../src/common/crypto'
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

function adminAddresses(): string[] {
  return wallets.map(w => w.address)
}

/** Helper: sign a document with EIP-712 using a wallet */
async function signWithWallet(wallet: ethers.HDNodeWallet, doc: UnsignedDocument): Promise<string> {
  const value = buildTypedDataValue(doc)
  return wallet.signTypedData(EIP712_DOMAIN, EIP712_TYPES, value)
}

async function buildDoc(overrides: Partial<UnsignedDocument> = {}): Promise<RegistryDocument> {
  const now = Math.floor(Date.now() / 1000)
  const u: UnsignedDocument = {
    registry_id: 'test-registry-v1', version: 1,
    issued_at: now, expires_at: now + 3600,
    admin_addresses: adminAddresses(),
    backoffice_service_pubkey: null,
    ceremony_bounds: { min_signing_threshold: 2, max_signing_threshold: 9, min_participants: 2, max_participants: 9, allowed_protocols: ['cggmp21', 'frost'], allowed_curves: ['secp256k1', 'ed25519'] },
    endpoints: null,
    nodes: [], merkle_root: computeMerkleRoot([]),
    prev_document_hash: null, document_hash: '',
    ...overrides,
  }
  u.document_hash = computeDocumentHash(u)
  return {
    ...u,
    signatures: [
      { admin_address: wallets[0].address, signature: await signWithWallet(wallets[0], u) },
      { admin_address: wallets[1].address, signature: await signWithWallet(wallets[1], u) },
    ]
  }
}

/** Helper: sign a pending draft fetched from the server */
async function signPending(pending: any): Promise<RegistryDocument> {
  const { signatures: _, ...unsigned } = pending
  return {
    ...pending,
    signatures: [
      { admin_address: wallets[0].address, signature: await signWithWallet(wallets[0], unsigned) },
      { admin_address: wallets[1].address, signature: await signWithWallet(wallets[1], unsigned) },
    ]
  }
}

describe('Health', () => {
  it('returns ok', async () => {
    const r = await request(app.getHttpServer()).get('/api/registry/health')
    expect(r.status).toBe(200)
    expect(r.body.status).toBe('ok')
    expect(r.body.adminSource).toBe('genesis-env')
  })
})

describe('Verify — each failure case', () => {
  it('missing fields', async () => {
    const r = await request(app.getHttpServer()).post('/api/registry/verify').send({
      registry_id: 'x', version: 1, issued_at: 1, expires_at: 1,
      admin_addresses: adminAddresses(),
      backoffice_service_pubkey: null,
      ceremony_bounds: { min_signing_threshold: 2, max_signing_threshold: 9, min_participants: 2, max_participants: 9, allowed_protocols: ['cggmp21', 'frost'], allowed_curves: ['secp256k1', 'ed25519'] },
      endpoints: null,
      nodes: [], merkle_root: 'x', prev_document_hash: null, document_hash: 'x', signatures: []
    })
    expect(r.status).toBe(200)
  })
  it('expired', async () => {
    const d = await buildDoc({ expires_at: Math.floor(Date.now()/1000) - 1 })
    const unsigned: UnsignedDocument = {
      registry_id: d.registry_id, version: d.version,
      issued_at: d.issued_at, expires_at: d.expires_at,
      admin_addresses: d.admin_addresses,
      backoffice_service_pubkey: d.backoffice_service_pubkey,
      ceremony_bounds: d.ceremony_bounds,
      endpoints: d.endpoints,
      nodes: d.nodes, merkle_root: d.merkle_root,
      prev_document_hash: d.prev_document_hash, document_hash: '',
    }
    unsigned.document_hash = computeDocumentHash(unsigned)
    d.document_hash = unsigned.document_hash
    d.signatures = [
      { admin_address: wallets[0].address, signature: await signWithWallet(wallets[0], unsigned) },
      { admin_address: wallets[1].address, signature: await signWithWallet(wallets[1], unsigned) },
    ]
    const r = await request(app.getHttpServer()).post('/api/registry/verify').send(d)
    expect(r.body.steps.find((s:any) => s.step==='expiry').passed).toBe(false)
  })
  it('tampered content', async () => {
    const d = await buildDoc()
    d.nodes = [{ node_id:'hack', ik_pub:'a'.repeat(64), ek_pub:'b'.repeat(64), role:'RECOVERY_GUARDIAN', status:'ACTIVE', enrolled_at:1 }]
    const r = await request(app.getHttpServer()).post('/api/registry/verify').send(d)
    expect(r.body.steps.find((s:any) => s.step==='document_hash').passed).toBe(false)
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
  it('current returns v1 with embedded admin addresses', async () => {
    const r = await request(app.getHttpServer()).get('/api/registry/current')
    expect(r.body.version).toBe(1)
    expect(r.body.admin_addresses).toHaveLength(3)
    expect(r.body.admin_addresses[0].toLowerCase()).toBe(wallets[0].address.toLowerCase())
  })
  it('health shows admin source as document', async () => {
    const r = await request(app.getHttpServer()).get('/api/registry/health')
    expect(r.body.adminSource).toBe('document')
  })
  it('enroll proposes a draft', async () => {
    const r = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ik_pub: 'a'.repeat(64), ek_pub: 'b'.repeat(64),
      role: 'PROVIDER_COSIGNER',    })
    expect(r.status).toBe(200)
    expect(r.body.draft.version).toBe(2)
    expect(r.body.draft.nodes.length).toBe(1)
    expect(r.body.draft.admin_addresses).toEqual(adminAddresses())
  })
  it('sign and publish enrollment', async () => {
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body
    const signed = await signPending(pending)
    const r = await request(app.getHttpServer()).post('/api/registry/publish').send(signed)
    expect(r.body.version).toBe(2)
  })
  it('node appears in list', async () => {
    const r = await request(app.getHttpServer()).get('/api/registry/nodes')
    expect(r.body.length).toBe(1)
    expect(r.body[0].status).toBe('ACTIVE')
  })
})

describe('Admin rotation', () => {
  it('proposes new admin addresses', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    const newWallet = ethers.Wallet.createRandom()
    const newAdmins = [wallets[0].address, wallets[1].address, newWallet.address]
    const r = await request(app.getHttpServer()).post('/api/registry/admins/propose').send({
      admin_addresses: newAdmins,
    })
    expect(r.status).toBe(200)
    expect(r.body.admin_addresses).toEqual(newAdmins)
  })
  it('current admins sign the admin change', async () => {
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body
    const signed = await signPending(pending)
    const r = await request(app.getHttpServer()).post('/api/registry/publish').send(signed)
    expect(r.status).toBe(200)
    expect(r.body.version).toBe(3)
  })
  it('new admin addresses are now active', async () => {
    const r = await request(app.getHttpServer()).get('/api/registry/current')
    expect(r.body.admin_addresses).toHaveLength(3)
    // wallet[2] is no longer admin, replaced by newWallet
    expect(r.body.admin_addresses.map((a: string) => a.toLowerCase())).not.toContain(wallets[2].address.toLowerCase())
  })
  it('old admin (wallet[2]) can no longer sign', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    await request(app.getHttpServer()).post('/api/registry/pending')
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body
    const { signatures: _, ...unsigned } = pending
    const sig = await signDocument(unsigned, wallets[2].privateKey)
    const r = await request(app.getHttpServer()).post('/api/registry/pending/sign').send({
      admin_address: wallets[2].address, signature: sig,
    })
    expect(r.status).toBe(400)
    await request(app.getHttpServer()).delete('/api/registry/pending')
  })
})

describe('Security', () => {
  it('draft locked during signing — rejects enroll after sign', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ik_pub: 'c'.repeat(64), ek_pub: 'd'.repeat(64),
      role: 'USER_COSIGNER',    })
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body
    const { signatures: _, ...unsigned } = pending
    const sig = await signDocument(unsigned, wallets[0].privateKey)
    await request(app.getHttpServer()).post('/api/registry/pending/sign').send({
      admin_address: wallets[0].address, signature: sig,
    })
    const r = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ik_pub: 'e'.repeat(64), ek_pub: 'f'.repeat(64),
      role: 'USER_COSIGNER',    })
    expect(r.status).toBe(409)
    await request(app.getHttpServer()).delete('/api/registry/pending')
  })

  it('revoked node re-enrollment blocked', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    const currentNodes = (await request(app.getHttpServer()).get('/api/registry/nodes')).body
    const activeNode = currentNodes.find((n: any) => n.status === 'ACTIVE')
    if (!activeNode) throw new Error('No active node to revoke')

    await request(app.getHttpServer()).post('/api/registry/nodes/revoke').send({
      node_id: activeNode.node_id, reason: 'test revocation',
    })
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body
    const signed = await signPending(pending)
    await request(app.getHttpServer()).post('/api/registry/publish').send(signed)

    const r = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ik_pub: activeNode.ik_pub, ek_pub: activeNode.ek_pub,
      role: activeNode.role,
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
    const { signatures: _, ...unsigned } = pending
    const docWithExtra = {
      ...pending,
      malicious: 'data',
      signatures: [
        { admin_address: wallets[0].address, signature: await signWithWallet(wallets[0], unsigned) },
        { admin_address: wallets[1].address, signature: await signWithWallet(wallets[1], unsigned) },
      ]
    }
    const r = await request(app.getHttpServer()).post('/api/registry/publish').send(docWithExtra)
    expect(r.status).toBe(200)

    const current = (await request(app.getHttpServer()).get('/api/registry/current')).body
    expect(current.malicious).toBeUndefined()
  })

  it('node_id collision check', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    const r1 = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ik_pub: '1'.repeat(64), ek_pub: '2'.repeat(64),
      role: 'RECOVERY_GUARDIAN',    })
    expect(r1.status).toBe(200)
    const r2 = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ik_pub: '1'.repeat(64), ek_pub: '3'.repeat(64),
      role: 'RECOVERY_GUARDIAN',    })
    expect(r2.status).toBe(409)
    await request(app.getHttpServer()).delete('/api/registry/pending')
  })

  it('admin_address validation — rejects invalid values', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    await request(app.getHttpServer()).post('/api/registry/pending')

    const r1 = await request(app.getHttpServer()).post('/api/registry/pending/sign').send({
      admin_address: 'not-an-address', signature: '0x' + 'a'.repeat(130),
    })
    expect(r1.status).toBe(400)

    const r2 = await request(app.getHttpServer()).post('/api/registry/pending/sign').send({
      admin_address: 'a'.repeat(40), signature: '0x' + 'a'.repeat(130),
    })
    expect(r2.status).toBe(400)

    await request(app.getHttpServer()).delete('/api/registry/pending')
  })

  it('invalid role — rejects bad role value', async () => {
    const r1 = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ik_pub: '5'.repeat(64), ek_pub: '6'.repeat(64),
      role: 'INVALID_ROLE',
    })
    expect(r1.status).toBe(400)
  })

  it('document_hash mismatch on sign — rejects stale hash', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    await request(app.getHttpServer()).post('/api/registry/pending')
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body

    const { signatures: _, ...unsigned } = pending
    const sig = await signDocument(unsigned, wallets[0].privateKey)
    const r = await request(app.getHttpServer()).post('/api/registry/pending/sign').send({
      admin_address: wallets[0].address, signature: sig, document_hash: 'wrong_hash_value',
    })
    expect(r.status).toBe(409)

    await request(app.getHttpServer()).delete('/api/registry/pending')
  })
})
