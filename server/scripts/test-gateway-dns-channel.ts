import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { setTimeout as delay } from 'node:timers/promises'
import { Client } from 'pg'

const unitOnly = process.env.GATEWAY_CHANNEL_UNIT_ONLY === '1'
if (unitOnly) process.env.DATABASE_URL = 'postgresql://127.0.0.1:1/gateway_channel_unit_test'
const database = new URL(process.env.DATABASE_URL || '')
assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(database.hostname) && /_test$/.test(database.pathname), 'Use isolated local test PostgreSQL')
const interval = globalThis.setInterval
if (unitOnly) globalThis.setInterval = ((...args: Parameters<typeof setInterval>) => interval(...args).unref()) as typeof setInterval
const { prisma, closePrismaDatabase } = await import('../src/db/prisma.js')
const { withGatewayDnsWriteAuthorization, ensureGatewayDnsChannel, gatewayDnsChannelStatus, gatewayDnsChannelDependencies,
  gatewayDnsWriteDependencies, gatewayMaintenanceChannelCurrent, expectedGatewayMaintenanceModuleHashes } = await import('../src/services/gateway-dns-channel.js')
const { validateGatewayResponse } = await import('../src/services/onboarding-ssh.js')
const { OnboardingError } = await import('../src/lib/host-onboarding.js')
const { hostKernelMaintenanceCommand, hostKernelMaintenanceChannelDependencies } = await import('../src/services/host-kernel-maintenance-channel.js')
const { HOST_KERNEL_CHANNEL_UPGRADE_REQUIRED, HOST_KERNEL_MAINTENANCE_RECIPE } = await import('../src/lib/host-kernel-maintenance-plan.js')
const { saveStableGatewayEndpoint } = await import('../src/services/onboarding-gateway-endpoint.js')
globalThis.setInterval = interval

async function unitChannelChecks() {
  const type = Buffer.from('ssh-ed25519')
  const publicKey = 'ssh-ed25519 ' + Buffer.concat([Buffer.from([0, 0, 0, type.length]), type,
    Buffer.from([0, 0, 0, 32]), Buffer.alloc(32, 7)]).toString('base64')
  const base = { publicKey: Buffer.alloc(32, 8).toString('base64'), controlIp: '10.253.240.1', network: '10.253.240.0/20',
    managementSshPublicKey: publicKey, dnsProtocolVersion: 2 }
  const endpoint = 'old.example.com:51820', sshHost = '8.8.4.4'
  const legacy = validateGatewayResponse(base, endpoint, sshHost)
  assert.equal(legacy.dnsProtocolVersion, 2)
  assert.equal(legacy.maintenanceProtocolVersion, undefined, 'old DNS2 remains readable without kernel capability')
  const expected = await expectedGatewayMaintenanceModuleHashes()
  for (const name of ['host-security-maintenance.py', 'host-kernel-maintenance.py'] as const) {
    const raw = await readFile(fileURLToPath(new URL('../templates/' + name, import.meta.url)))
    assert.equal(expected[name], createHash('sha256').update(raw).digest('hex'), 'the advertised comparison includes every source byte')
  }
  const current = validateGatewayResponse({ ...base, maintenanceProtocolVersion: 2, maintenanceModuleHashes: expected }, endpoint, sshHost)
  const capable = (gateway: typeof current) => gatewayMaintenanceChannelCurrent(gateway, expected)
  assert.equal(await capable(legacy), false)
  assert.equal(await capable(current), true)
  const stale = { ...current, maintenanceModuleHashes: { ...expected, 'host-kernel-maintenance.py': 'f'.repeat(64) } }
  assert.equal(await capable(stale), false, 'a safe but partly published pair is not this source version')
  assert.equal(await capable({ ...current, maintenanceModuleHashes: { ...expected, 'host-security-maintenance.py': 'e'.repeat(64) } }), false)
  const malformed = [
    { maintenanceProtocolVersion: true, maintenanceModuleHashes: expected },
    { maintenanceProtocolVersion: '2', maintenanceModuleHashes: expected },
    { maintenanceProtocolVersion: 1, maintenanceModuleHashes: expected },
    { maintenanceProtocolVersion: [2], maintenanceModuleHashes: expected },
    { maintenanceProtocolVersion: 2 }, { maintenanceModuleHashes: expected },
    { maintenanceProtocolVersion: 2, maintenanceModuleHashes: false },
    { maintenanceProtocolVersion: 2, maintenanceModuleHashes: null },
    { maintenanceProtocolVersion: 2, maintenanceModuleHashes: [expected] },
    { maintenanceProtocolVersion: 2, maintenanceModuleHashes: { 'host-kernel-maintenance.py': expected['host-kernel-maintenance.py'] } },
    { maintenanceProtocolVersion: 2, maintenanceModuleHashes: { ...expected, unknown: 'a'.repeat(64) } },
    ...['short', 'A'.repeat(64), false, 0, ['a'.repeat(64)]].map(hash => ({ maintenanceProtocolVersion: 2,
      maintenanceModuleHashes: { ...expected, 'host-kernel-maintenance.py': hash } })),
  ]
  for (const delta of malformed) assert.throws(() => validateGatewayResponse({ ...base, ...delta }, endpoint, sshHost), /MAINTENANCE_CAPABILITY_INVALID/)
  const statusDeps = { ...gatewayDnsChannelDependencies, configured: () => true, command: async () => legacy, capable }
  assert.equal((await gatewayDnsChannelStatus(statusDeps)).needsChannelUpgrade, true)
  assert.equal((await gatewayDnsChannelStatus({ ...statusDeps, command: async () => current })).needsChannelUpgrade, false)
  assert.equal((await gatewayDnsChannelStatus({ ...statusDeps, command: async () => stale })).needsChannelUpgrade, true)
  const invalidStatus = await gatewayDnsChannelStatus({ ...statusDeps, command: async () => validateGatewayResponse({ ...base, ...malformed[0] }, endpoint, sshHost) })
  assert.equal(invalidStatus.needsChannelUpgrade, true)
  assert.equal(invalidStatus.channelError, 'GATEWAY_MAINTENANCE_CAPABILITY_INVALID')
  const changedPin = await gatewayDnsChannelStatus({ ...statusDeps, command: async () => { throw new OnboardingError('SSH_HOST_KEY_CHANGED') } })
  assert.equal(changedPin.needsChannelUpgrade, false, 'a changed pin is not repaired by component publication')
  assert.equal(changedPin.channelError, 'SSH_HOST_KEY_CHANGED')
  await gatewayDnsChannelStatus({ ...statusDeps, configured: () => false, command: async () => assert.fail('unconfigured gateway must not connect') })

  const savedHost = process.env.ONBOARDING_GATEWAY_HOST
  const actor = { id: 77, sid: randomUUID(), iat: Math.floor(Date.now() / 1000) + 1 }
  let authorizations = 0, writes = 0, rejectActor = false, afterRefresh = current
  const writeDeps: typeof gatewayDnsWriteDependencies = { ...gatewayDnsWriteDependencies, capable,
    authorize: async (_actor, apply) => { authorizations++; if (rejectActor) throw new OnboardingError('GATEWAY_WEB_SESSION_REQUIRED'); return apply() },
    refresh: async (original, password) => { assert.deepEqual(original, legacy); assert.equal(password, 'fixture-only'); writes++ },
    command: async () => afterRefresh }
  try {
    process.env.ONBOARDING_GATEWAY_HOST = sshHost
    await assert.rejects(ensureGatewayDnsChannel(legacy, undefined, actor, writeDeps), /HELPER_UPGRADE_REQUIRED/)
    assert.equal(authorizations, 0); assert.equal(writes, 0)
    rejectActor = true
    await assert.rejects(ensureGatewayDnsChannel(legacy, 'fixture-only', actor, writeDeps), /WEB_SESSION_REQUIRED/)
    assert.equal(writes, 0, 'old DNS2 must not bypass current write authorization')
    rejectActor = false
    await ensureGatewayDnsChannel(legacy, 'fixture-only', actor, writeDeps)
    assert.equal(writes, 1, 'old DNS2 follows the original authorized helper refresh')
    const before = authorizations
    await ensureGatewayDnsChannel(current, undefined, actor, writeDeps)
    assert.equal(authorizations, before); assert.equal(writes, 1, 'the complete current pair needs no publication')
    afterRefresh = stale
    await assert.rejects(ensureGatewayDnsChannel(legacy, 'fixture-only', actor, writeDeps), /UPGRADE_FAILED/)
    afterRefresh = { ...current, publicKey: Buffer.alloc(32, 9).toString('base64') }
    await assert.rejects(ensureGatewayDnsChannel(legacy, 'fixture-only', actor, writeDeps), /HOST_IDENTITY_CHANGED/)
    process.env.ONBOARDING_GATEWAY_HOST = '127.0.0.1'
    const beforeLocal = writes
    await assert.rejects(ensureGatewayDnsChannel(legacy, 'fixture-only', actor, writeDeps), /LOCAL_HELPER_OUTDATED/)
    assert.equal(writes, beforeLocal)
  } finally { if (savedHost === undefined) delete process.env.ONBOARDING_GATEWAY_HOST; else process.env.ONBOARDING_GATEWAY_HOST = savedHost }

  const nodeId = randomUUID(), requestId = randomUUID(), bootId = randomUUID(), hash = 'a'.repeat(64), zero = '0'.repeat(64)
  const operation = { action: 'inspect' as const, requestId, bootId, identityHash: hash, prepareHash: zero,
    recipe: HOST_KERNEL_MAINTENANCE_RECIPE, architecture: 'x86_64' as const, expectedPlanHash: null, customers: [] as [] }
  const target = { onboardingNode: { id: nodeId } } as Parameters<typeof hostKernelMaintenanceCommand>[0]
  let dispatches = 0
  const exchange: typeof hostKernelMaintenanceChannelDependencies.exchange = async (_target, wire) => {
    dispatches++; assert.equal(wire.expectedPlanHash, null); assert.equal(wire.nodeId, nodeId)
    return { version: 1, nodeId, requestId, identityHash: hash, originalBootId: bootId, bootId, architecture: 'x86_64',
      recipe: HOST_KERNEL_MAINTENANCE_RECIPE, prepareHash: zero, phase: 'inspected', plan: { status: 'up-to-date', branch: '3.22',
        flavor: 'linux-virt', bootloader: 'grub', runningRelease: '6.12.100-0-virt', installedVersion: '6.12.100-r0',
        candidateVersion: null, candidateRelease: null, planHash: null, reason: null } }
  }
  const channelDeps = { ...hostKernelMaintenanceChannelDependencies, capable, exchange }
  for (const unsupported of [legacy, stale]) {
    await assert.rejects(hostKernelMaintenanceCommand(target, operation, { ...channelDeps, command: async () => unsupported }),
      { message: HOST_KERNEL_CHANNEL_UPGRADE_REQUIRED })
  }
  for (const delta of malformed) {
    await assert.rejects(hostKernelMaintenanceCommand(target, operation, { ...channelDeps,
      command: async () => validateGatewayResponse({ ...base, ...delta }, endpoint, sshHost) }), { message: HOST_KERNEL_CHANNEL_UPGRADE_REQUIRED })
  }
  assert.equal(dispatches, 0, 'missing, malformed and partly published helpers receive zero kernel requests')
  await assert.rejects(hostKernelMaintenanceCommand(target, { ...operation, customers: [{}] } as any,
    { ...channelDeps, command: async () => assert.fail('invalid intent must not even read the gateway') }), /REQUEST_UNKNOWN/)
  assert.equal((await hostKernelMaintenanceCommand(target, operation, { ...channelDeps, command: async () => current })).phase, 'inspected')
  assert.equal(dispatches, 1, 'a fresh matching pair dispatches the original fixed request')
  console.log('Gateway maintenance capability: strict schema, full source hashes, old DNS2, partial publication, zero unsupported dispatches and preserved identity boundaries passed (no DB/SSH)')
}

await unitChannelChecks()
if (unitOnly) {
  await closePrismaDatabase()
} else {
const holder = new Client({ connectionString: database.href }), observer = new Client({ connectionString: database.href })
const admin = await prisma.user.create({ data: { username: 'gateway-channel-' + randomUUID(), passwordHash: 'unusable', role: 'admin' } })
const actor = { id: admin.id, sid: randomUUID(), iat: Math.floor(Date.now() / 1000) + 1 }
let calls = 0
const apply = async () => { calls++; return { preserved: true } }
const env = process.env.ONBOARDING_GATEWAY_HOST
const gateway = { endpoint: 'old.example.com:51820', sshHost: '8.8.4.4', publicKey: 'fixture', controlIp: '10.253.240.1', network: '10.253.240.0/20', managementSshPublicKey: 'fixture', dnsProtocolVersion: 2 }
try {
  await holder.connect(); await observer.connect()
  const pid = (await holder.query('SELECT pg_backend_pid() AS pid')).rows[0].pid as number
  assert.deepEqual(await withGatewayDnsWriteAuthorization(actor, apply), { preserved: true })
  assert.equal(calls, 1)
  for (const session of [{ id: admin.id }, { ...actor, sid: undefined }, { ...actor, iat: undefined }]) {
    await assert.rejects(withGatewayDnsWriteAuthorization(session, apply), /WEB_SESSION_REQUIRED/)
  }
  await prisma.tokenInvalidation.create({ data: { userId: admin.id, sessionId: actor.sid, invalidatedAt: actor.iat } })
  await assert.rejects(withGatewayDnsWriteAuthorization(actor, apply), /WEB_SESSION_REQUIRED/)
  await assert.rejects(saveStableGatewayEndpoint({ hostname: 'new.example.com', port: 51820 }, actor.id, undefined, undefined, actor), /WEB_SESSION_REQUIRED/)
  assert.equal(calls, 1)
  await prisma.tokenInvalidation.deleteMany({ where: { userId: admin.id } })
  await prisma.user.update({ where: { id: admin.id }, data: { role: 'user' } })
  await assert.rejects(withGatewayDnsWriteAuthorization(actor, apply), /WEB_SESSION_REQUIRED/)
  await prisma.user.update({ where: { id: admin.id }, data: { role: 'admin' } })
  // A revocation that holds the account lock wins over a request already waiting.
  await holder.query('BEGIN')
  await holder.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [admin.id])
  const waiting = assert.rejects(withGatewayDnsWriteAuthorization(actor, apply), /WEB_SESSION_REQUIRED/)
  let deadline = Date.now() + 1500
  while (!(await observer.query('SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))) AS waiting', [pid])).rows[0].waiting) {
    assert.ok(Date.now() < deadline, 'helper write must wait for the administrator lock'); await delay(10)
  }
  await holder.query('UPDATE users SET role=$1 WHERE id=$2', ['user', admin.id]); await holder.query('COMMIT'); await waiting
  assert.equal(calls, 1)
  await prisma.user.update({ where: { id: admin.id }, data: { role: 'admin' } })
  // Once authorized, the lock stays held until the fixed remote operation ends.
  let begin!: () => void, release!: () => void
  const started = new Promise<void>(resolve => { begin = resolve }), paused = new Promise<void>(resolve => { release = resolve })
  const running = withGatewayDnsWriteAuthorization(actor, async () => { calls++; begin(); await paused; return true })
  await started
  const revocation = holder.query('UPDATE users SET role=$1 WHERE id=$2', ['user', admin.id])
  deadline = Date.now() + 1500
  try {
    while (!(await observer.query('SELECT cardinality(pg_blocking_pids($1))>0 AS waiting', [pid])).rows[0].waiting) {
      assert.ok(Date.now() < deadline, 'role revocation must wait for the in-flight remote operation'); await delay(10)
    }
  } finally { release() }
  assert.equal(await running, true); await revocation
  await assert.rejects(withGatewayDnsWriteAuthorization(actor, apply), /WEB_SESSION_REQUIRED/)
  assert.equal(calls, 2)
  await prisma.user.update({ where: { id: admin.id }, data: { role: 'admin' } })
  const auditCount = await prisma.log.count({ where: { userId: admin.id, action: 'gateway.dns.channel.updated' } })
  await assert.rejects(withGatewayDnsWriteAuthorization(actor, async () => { throw new Error('controlled lost remote receipt') }), /controlled lost remote receipt/)
  assert.equal(await prisma.log.count({ where: { userId: admin.id, action: 'gateway.dns.channel.updated' } }), auditCount + 1,
    'a remote failure must not roll back the durable operation audit')
  assert.equal((await prisma.log.findFirstOrThrow({ where: { userId: admin.id, action: 'gateway.dns.channel.updated' }, orderBy: { id: 'desc' } })).result, 'failed')
  process.env.ONBOARDING_GATEWAY_HOST = '8.8.4.4'
  await assert.rejects(ensureGatewayDnsChannel(gateway, undefined, actor), /HELPER_UPGRADE_REQUIRED/)
  let legacyWrites = 0
  await assert.rejects(ensureGatewayDnsChannel(gateway, 'fixture-only', { id: admin.id }, { ...gatewayDnsWriteDependencies,
    refresh: async () => { legacyWrites++ } }), /WEB_SESSION_REQUIRED/)
  assert.equal(legacyWrites, 0, 'legacy DNS2 still requires a current real Web session before any helper write')
  process.env.ONBOARDING_GATEWAY_HOST = '127.0.0.1'
  await assert.rejects(ensureGatewayDnsChannel(gateway, 'must-not-use-local-ssh', actor), /LOCAL_HELPER_OUTDATED/)
  console.log('Gateway DNS helper upgrade: real PG sid/iat and role revocation, both lock orderings, zero unauthorized remote actions, local/remote credential boundary passed')
} finally {
  if (env === undefined) delete process.env.ONBOARDING_GATEWAY_HOST; else process.env.ONBOARDING_GATEWAY_HOST = env
  await holder.query('ROLLBACK').catch(() => {})
  await holder.end(); await observer.end()
  await prisma.log.deleteMany({ where: { userId: admin.id } })
  await prisma.tokenInvalidation.deleteMany({ where: { userId: admin.id } })
  await prisma.user.delete({ where: { id: admin.id } })
  await closePrismaDatabase()
}
}
