// Set env vars BEFORE any imports that read config
import { unlinkSync, existsSync, readFileSync, rmSync } from 'fs'

const TEST_REGISTRY_FILE = '/tmp/test-registry-jest.json'
const TEST_VERSIONS_DIR = '/tmp/versions'
try { unlinkSync(TEST_REGISTRY_FILE) } catch {}
try { rmSync(TEST_VERSIONS_DIR, { recursive: true, force: true }) } catch {}
process.env.REGISTRY_FILE = TEST_REGISTRY_FILE
process.env.REGISTRY_ID = 'test-registry-v1'

import * as dotenv from 'dotenv'
dotenv.config({ path: '.env.test' })
import { Test } from '@nestjs/testing'
import { INestApplication, ValidationPipe } from '@nestjs/common'
import request from 'supertest'
import { ethers } from 'ethers'
import { AppModule } from '../src/app.module'
import {
  signDocument, computeDocumentHash, computeMerkleRoot,
  EIP712_DOMAIN, EIP712_TYPES, buildTypedDataValue,
} from '../src/common/crypto'
import { RegistryDocument, UnsignedDocument, RoleSignature } from '../src/common/types'
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { ed25519 } = require('@noble/curves/ed25519.js')

let wallets: ethers.HDNodeWallet[] = []
let app: INestApplication

beforeAll(async () => {
  wallets = [
    ethers.Wallet.createRandom(),
    ethers.Wallet.createRandom(),
    ethers.Wallet.createRandom(),
  ]
  process.env.ADMIN_ADDRESS_0 = wallets[0].address
  process.env.ADMIN_ADDRESS_1 = wallets[1].address
  process.env.ADMIN_ADDRESS_2 = wallets[2].address

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
  const value = buildTypedDataValue(doc as any)
  return wallet.signTypedData(EIP712_DOMAIN, EIP712_TYPES, value)
}

/** Build a valid genesis document with 2-of-3 SYSTEM_ADMIN signatures */
async function buildDoc(overrides: Record<string, any> = {}): Promise<RegistryDocument> {
  const now = Math.floor(Date.now() / 1000)
  const u: UnsignedDocument = {
    registry_metadata: {
      registry_id: 'test-registry-v1',
      version: 1,
      issued_at: now,
      expires_at: now + 3600,
      updated_at: new Date().toISOString(),
      document_hash: '',
      merkle_root: computeMerkleRoot([]),
      prev_document_hash: null,
      endpoints: null,
    },
    governance: {
      roles: [{
        role: 'SYSTEM_ADMIN',
        display_name: 'System Administrators',
        addresses: adminAddresses(),
        quorum: 2,
        features: {},
      }],
    },
    ceremony_config: {
      global_threshold_t: 2,
      max_participants_n: 9,
      allowed_protocols: ['CGGMP21', 'FROST'],
      allowed_curves: ['Secp256k1', 'Ed25519'],
    },
    trusted_infrastructure: {
      backoffice_pubkey: null,
      market_oracle_pubkey: null,
      trusted_binary_hashes: [],
    },
    nodes: [],
    immutable_policies: {
      max_withdrawal_usd_24h: 100000,
      require_oracle_price: true,
      enforce_whitelist: true,
    },
  }

  // Apply overrides (shallow merge into nested sections)
  if (overrides.registry_metadata) {
    Object.assign(u.registry_metadata, overrides.registry_metadata)
  }
  if (overrides.governance) u.governance = overrides.governance
  if (overrides.ceremony_config) u.ceremony_config = overrides.ceremony_config
  if (overrides.trusted_infrastructure) u.trusted_infrastructure = overrides.trusted_infrastructure
  if (overrides.nodes) u.nodes = overrides.nodes
  if (overrides.immutable_policies) u.immutable_policies = overrides.immutable_policies

  // Recompute merkle root and document hash
  u.registry_metadata.merkle_root = computeMerkleRoot(u.nodes)
  u.registry_metadata.document_hash = ''
  u.registry_metadata.document_hash = computeDocumentHash(u)

  return {
    ...u,
    signatures: [
      { role: 'SYSTEM_ADMIN', signer: wallets[0].address, signature: await signWithWallet(wallets[0], u) },
      { role: 'SYSTEM_ADMIN', signer: wallets[1].address, signature: await signWithWallet(wallets[1], u) },
    ],
  }
}

/** Sign a pending draft fetched from the server with 2 wallets */
async function signPending(pending: any): Promise<RegistryDocument> {
  const { signatures: _, ...unsigned } = pending
  return {
    ...pending,
    signatures: [
      { role: 'SYSTEM_ADMIN', signer: wallets[0].address, signature: await signWithWallet(wallets[0], unsigned) },
      { role: 'SYSTEM_ADMIN', signer: wallets[1].address, signature: await signWithWallet(wallets[1], unsigned) },
    ],
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('Health', () => {
  it('returns ok', async () => {
    const r = await request(app.getHttpServer()).get('/api/registry/health')
    expect(r.status).toBe(200)
    expect(r.body.status).toBe('ok')
    expect(r.body.governanceSource).toBe('genesis-env')
  })
})

describe('Verify — each failure case', () => {
  it('missing sections', async () => {
    const r = await request(app.getHttpServer()).post('/api/registry/verify').send({
      registry_metadata: {
        registry_id: 'x', version: 1, issued_at: 1, expires_at: 1,
        document_hash: 'x', merkle_root: 'x', prev_document_hash: null,
        updated_at: '', endpoints: null,
      },
      governance: { roles: [] },
      ceremony_config: { global_threshold_t: 2, max_participants_n: 9, allowed_protocols: ['CGGMP21'], allowed_curves: ['Secp256k1'] },
      trusted_infrastructure: { backoffice_pubkey: null, market_oracle_pubkey: null, trusted_binary_hashes: [] },
      nodes: [],
      immutable_policies: { max_withdrawal_usd_24h: 50000, require_oracle_price: true, enforce_whitelist: true },
      signatures: [],
    })
    expect(r.status).toBe(200)
  })

  it('expired', async () => {
    const d = await buildDoc({ registry_metadata: { expires_at: Math.floor(Date.now() / 1000) - 1 } })
    // Recompute hash and signatures since expires_at changed
    const { signatures: _, ...unsigned } = d
    unsigned.registry_metadata.document_hash = ''
    unsigned.registry_metadata.document_hash = computeDocumentHash(unsigned as UnsignedDocument)
    d.registry_metadata.document_hash = unsigned.registry_metadata.document_hash
    d.signatures = [
      { role: 'SYSTEM_ADMIN', signer: wallets[0].address, signature: await signWithWallet(wallets[0], unsigned as UnsignedDocument) },
      { role: 'SYSTEM_ADMIN', signer: wallets[1].address, signature: await signWithWallet(wallets[1], unsigned as UnsignedDocument) },
    ]
    const r = await request(app.getHttpServer()).post('/api/registry/verify').send(d)
    expect(r.body.steps.find((s: any) => s.step === 'expiry').passed).toBe(false)
  })

  it('tampered content', async () => {
    const d = await buildDoc()
    d.nodes = [{ node_id: 'hack', ik_pub: 'a'.repeat(64), ek_pub: 'b'.repeat(64), role: 'RECOVERY_GUARDIAN', status: 'ACTIVE', enrolled_at: 1 }]
    const r = await request(app.getHttpServer()).post('/api/registry/verify').send(d)
    expect(r.body.steps.find((s: any) => s.step === 'document_hash').passed).toBe(false)
  })

  it('only 1 signature', async () => {
    const d = await buildDoc()
    d.signatures = [d.signatures[0]]
    const r = await request(app.getHttpServer()).post('/api/registry/verify').send(d)
    expect(r.body.steps.find((s: any) => s.step === 'roleQuorum').passed).toBe(false)
  })

  it('valid document passes all steps', async () => {
    const d = await buildDoc()
    const r = await request(app.getHttpServer()).post('/api/registry/verify').send(d)
    expect(r.body.valid).toBe(true)
    expect(r.body.steps.every((s: any) => s.passed)).toBe(true)
  })
})

describe('Full publish flow', () => {
  it('publishes genesis', async () => {
    const d = await buildDoc()
    const r = await request(app.getHttpServer()).post('/api/registry/publish').send(d)
    expect(r.status).toBe(200)
    expect(r.body.version).toBe(1)
  })

  it('current returns v1 with governance roles', async () => {
    const r = await request(app.getHttpServer()).get('/api/registry/current')
    expect(r.body.registry_metadata.version).toBe(1)
    expect(r.body.governance.roles).toHaveLength(1)
    expect(r.body.governance.roles[0].role).toBe('SYSTEM_ADMIN')
    expect(r.body.governance.roles[0].addresses).toHaveLength(3)
    expect(r.body.governance.roles[0].addresses[0].toLowerCase()).toBe(wallets[0].address.toLowerCase())
  })

  it('health shows governance source as document', async () => {
    const r = await request(app.getHttpServer()).get('/api/registry/health')
    expect(r.body.governanceSource).toBe('document')
  })

  it('enroll proposes a draft', async () => {
    const r = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ik_pub: 'a'.repeat(64), ek_pub: 'b'.repeat(64),
      role: 'PROVIDER_COSIGNER',
    })
    expect(r.status).toBe(200)
    expect(r.body.draft.registry_metadata.version).toBe(2)
    expect(r.body.draft.nodes.length).toBe(1)
    expect(r.body.draft.governance.roles[0].addresses).toEqual(adminAddresses())
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

  it('version files are written on publish', () => {
    expect(existsSync(`${TEST_VERSIONS_DIR}/1.json`)).toBe(true)
    expect(existsSync(`${TEST_VERSIONS_DIR}/2.json`)).toBe(true)
    const v1 = JSON.parse(readFileSync(`${TEST_VERSIONS_DIR}/1.json`, 'utf-8'))
    const v2 = JSON.parse(readFileSync(`${TEST_VERSIONS_DIR}/2.json`, 'utf-8'))
    expect(v1.registry_metadata.version).toBe(1)
    expect(v2.registry_metadata.version).toBe(2)
    expect(v2.registry_metadata.prev_document_hash).toBe(v1.registry_metadata.document_hash)
  })

  it('GET /versions returns version list', async () => {
    const r = await request(app.getHttpServer()).get('/api/registry/versions')
    expect(r.status).toBe(200)
    expect(r.body).toContain(1)
    expect(r.body).toContain(2)
  })

  it('GET /versions/:v returns specific version', async () => {
    const r = await request(app.getHttpServer()).get('/api/registry/versions/1')
    expect(r.status).toBe(200)
    expect(r.body.registry_metadata.version).toBe(1)
  })

  it('GET /versions/:v returns 404 for missing version', async () => {
    const r = await request(app.getHttpServer()).get('/api/registry/versions/999')
    expect(r.status).toBe(404)
  })
})

describe('Governance role rotation', () => {
  it('proposes new SYSTEM_ADMIN addresses', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    const newWallet = ethers.Wallet.createRandom()
    const newAddresses = [wallets[0].address, wallets[1].address, newWallet.address]
    const r = await request(app.getHttpServer()).post('/api/registry/governance/role').send({
      role: 'SYSTEM_ADMIN',
      display_name: 'System Administrators',
      addresses: newAddresses,
      quorum: 2,
    })
    expect(r.status).toBe(200)
    const saRole = r.body.governance.roles.find((r: any) => r.role === 'SYSTEM_ADMIN')
    expect(saRole.addresses).toEqual(newAddresses)
  })

  it('current admins sign the governance change', async () => {
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body
    const signed = await signPending(pending)
    const r = await request(app.getHttpServer()).post('/api/registry/publish').send(signed)
    expect(r.status).toBe(200)
    expect(r.body.version).toBe(3)
  })

  it('new admin addresses are now active', async () => {
    const r = await request(app.getHttpServer()).get('/api/registry/current')
    const saRole = r.body.governance.roles.find((role: any) => role.role === 'SYSTEM_ADMIN')
    expect(saRole.addresses).toHaveLength(3)
    // wallet[2] is no longer admin, replaced by newWallet
    expect(saRole.addresses.map((a: string) => a.toLowerCase())).not.toContain(wallets[2].address.toLowerCase())
  })

  it('old admin (wallet[2]) can no longer sign', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    await request(app.getHttpServer()).post('/api/registry/pending')
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body
    const { signatures: _, ...unsigned } = pending
    const sig = await signDocument(unsigned, wallets[2].privateKey)
    const r = await request(app.getHttpServer()).post('/api/registry/pending/sign').send({
      role: 'SYSTEM_ADMIN',
      signer: wallets[2].address,
      signature: sig,
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
      role: 'USER_COSIGNER',
    })
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body
    const { signatures: _, ...unsigned } = pending
    const sig = await signDocument(unsigned, wallets[0].privateKey)
    await request(app.getHttpServer()).post('/api/registry/pending/sign').send({
      role: 'SYSTEM_ADMIN',
      signer: wallets[0].address,
      signature: sig,
    })
    const r = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ik_pub: 'e'.repeat(64), ek_pub: 'f'.repeat(64),
      role: 'USER_COSIGNER',
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
        { role: 'SYSTEM_ADMIN', signer: wallets[0].address, signature: await signWithWallet(wallets[0], unsigned) },
        { role: 'SYSTEM_ADMIN', signer: wallets[1].address, signature: await signWithWallet(wallets[1], unsigned) },
      ],
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
      role: 'RECOVERY_GUARDIAN',
    })
    expect(r1.status).toBe(200)
    const r2 = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ik_pub: '1'.repeat(64), ek_pub: '3'.repeat(64),
      role: 'RECOVERY_GUARDIAN',
    })
    expect(r2.status).toBe(409)
    await request(app.getHttpServer()).delete('/api/registry/pending')
  })

  it('signer validation — rejects invalid signer address', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    await request(app.getHttpServer()).post('/api/registry/pending')

    const r1 = await request(app.getHttpServer()).post('/api/registry/pending/sign').send({
      role: 'SYSTEM_ADMIN',
      signer: 'not-an-address',
      signature: '0x' + 'a'.repeat(130),
    })
    expect(r1.status).toBe(400)

    const r2 = await request(app.getHttpServer()).post('/api/registry/pending/sign').send({
      role: 'SYSTEM_ADMIN',
      signer: 'a'.repeat(40),
      signature: '0x' + 'a'.repeat(130),
    })
    expect(r2.status).toBe(400)

    await request(app.getHttpServer()).delete('/api/registry/pending')
  })

  it('invalid node role — rejects bad role value', async () => {
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
      role: 'SYSTEM_ADMIN',
      signer: wallets[0].address,
      signature: sig,
      document_hash: 'wrong_hash_value',
    })
    expect(r.status).toBe(409)

    await request(app.getHttpServer()).delete('/api/registry/pending')
  })
})

describe('Node maintenance and reactivation', () => {
  it('sets a node to maintenance', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    // Enroll a new node
    const enrollRes = await request(app.getHttpServer()).post('/api/registry/nodes/enroll').send({
      ik_pub: '7'.repeat(64), ek_pub: '8'.repeat(64),
      role: 'USER_COSIGNER',
    })
    expect(enrollRes.status).toBe(200)
    const nodeId = enrollRes.body.node_id

    // Publish the enrollment
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body
    const signed = await signPending(pending)
    const pubRes = await request(app.getHttpServer()).post('/api/registry/publish').send(signed)
    expect(pubRes.status).toBe(200)

    // Set to maintenance
    const r = await request(app.getHttpServer()).post('/api/registry/nodes/maintenance').send({
      node_id: nodeId, reason: 'planned update',
    })
    expect(r.status).toBe(200)
    const draftNode = r.body.nodes.find((n: any) => n.node_id === nodeId)
    expect(draftNode.status).toBe('MAINTENANCE')

    // Publish maintenance
    const pending2 = (await request(app.getHttpServer()).get('/api/registry/pending')).body
    const signed2 = await signPending(pending2)
    await request(app.getHttpServer()).post('/api/registry/publish').send(signed2)

    // Verify node status
    const nodeRes = await request(app.getHttpServer()).get(`/api/registry/nodes/${nodeId}`)
    expect(nodeRes.body.status).toBe('MAINTENANCE')
  })

  it('reactivates a maintenance node', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    const nodes = (await request(app.getHttpServer()).get('/api/registry/nodes')).body
    const maintNode = nodes.find((n: any) => n.status === 'MAINTENANCE')
    expect(maintNode).toBeDefined()

    const r = await request(app.getHttpServer()).post('/api/registry/nodes/reactivate').send({
      node_id: maintNode.node_id,
    })
    expect(r.status).toBe(200)
    const draftNode = r.body.nodes.find((n: any) => n.node_id === maintNode.node_id)
    expect(draftNode.status).toBe('ACTIVE')

    // Publish reactivation
    const pending = (await request(app.getHttpServer()).get('/api/registry/pending')).body
    const signed = await signPending(pending)
    await request(app.getHttpServer()).post('/api/registry/publish').send(signed)
  })

  it('rejects maintenance for non-ACTIVE node', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    const nodes = (await request(app.getHttpServer()).get('/api/registry/nodes')).body
    const revokedNode = nodes.find((n: any) => n.status === 'REVOKED')
    if (revokedNode) {
      const r = await request(app.getHttpServer()).post('/api/registry/nodes/maintenance').send({
        node_id: revokedNode.node_id, reason: 'test',
      })
      expect(r.status).toBe(409)
    }
    await request(app.getHttpServer()).delete('/api/registry/pending')
  })

  it('rejects reactivation for non-MAINTENANCE node', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    const nodes = (await request(app.getHttpServer()).get('/api/registry/nodes')).body
    const activeNode = nodes.find((n: any) => n.status === 'ACTIVE')
    if (activeNode) {
      const r = await request(app.getHttpServer()).post('/api/registry/nodes/reactivate').send({
        node_id: activeNode.node_id,
      })
      expect(r.status).toBe(409)
    }
    await request(app.getHttpServer()).delete('/api/registry/pending')
  })
})

describe('IK rotation', () => {
  it('rejects rotation with invalid proof', async () => {
    await request(app.getHttpServer()).delete('/api/registry/pending')
    const nodes = (await request(app.getHttpServer()).get('/api/registry/nodes')).body
    const activeNode = nodes.find((n: any) => n.status === 'ACTIVE')
    if (!activeNode) throw new Error('No active node for IK rotation test')

    const r = await request(app.getHttpServer()).post('/api/registry/nodes/rotate-ik').send({
      node_id: activeNode.node_id,
      new_ik_pub: '9'.repeat(64),
      reason: 'test rotation',
      proof: 'a'.repeat(128), // invalid proof
    })
    expect(r.status).toBe(400)
    await request(app.getHttpServer()).delete('/api/registry/pending')
  })
})
