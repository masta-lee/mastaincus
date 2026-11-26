import assert from 'node:assert/strict'
import { createHash, randomInt, randomUUID } from 'node:crypto'
import Fastify from 'fastify'
import type { HostKernelInspection, HostKernelPhase } from '../src/lib/host-kernel-maintenance-plan.js'

let database: URL
try { database = new URL(process.env.DATABASE_URL || '') } catch { throw Error('HARDENING_KERNEL_TEST_DATABASE_REQUIRED') }
assert.equal(database.hostname, '127.0.0.1')
assert.match(database.pathname, /^\/[a-z0-9_]+_pool_test$/)
const interval = globalThis.setInterval
globalThis.setInterval = ((...args: Parameters<typeof setInterval>) => interval(...args).unref()) as typeof setInterval
const { prisma, closePrismaDatabase } = await import('../src/db/prisma.js')
const { hostKernelMaintenanceDependencies, inspectAutomaticHostKernelMaintenance, prepareAutomaticHostKernelMaintenance,
  resumeAutomaticHostKernelMaintenance } = await import('../src/services/host-kernel-maintenance.js')
const { hostKernelWireOperation, hostKernelWireExpiry, hostKernelMaintenanceCommand,
  hostKernelMaintenanceChannelDependencies } = await import('../src/services/host-kernel-maintenance-channel.js')
const { readHostKernelIntent, HOST_KERNEL_MAINTENANCE_RECIPE, HOST_KERNEL_CHANNEL_RECHECK_DELAY,
  HOST_KERNEL_CHANNEL_UPGRADE_REQUIRED } = await import('../src/lib/host-kernel-maintenance-plan.js')
const { expectedGatewayMaintenanceModuleHashes } = await import('../src/services/gateway-dns-channel.js')
const { HOST_MAINTENANCE_REVISION } = await import('../src/lib/host-maintenance-plan.js')
const { hardeningIdentityHash } = await import('../src/lib/hardening-identity.js')
const { hostMaintenanceBlocked } = await import('../src/lib/host-maintenance-gate.js')
const { beginHostMutation } = await import('../src/lib/host-operation-lane.js')
const { SECURITY_HARDENING_ENABLED_KEY, SECURITY_HARDENING_REVISION } = await import('../src/lib/security-hardening.js')
const { createAgentBodyHash, createAgentSignature, generateAgentId, generateAgentSecret, hashAgentSecret } = await import('../src/lib/agent-auth.js')
const { encryptSensitiveData } = await import('../src/lib/security.js')
const { default: agentRoutes } = await import('../src/routes/agent.js')
globalThis.setInterval = interval

const prefix = 'kernel-' + randomUUID().slice(0, 8), zero = '0'.repeat(64), preparedHash = 'b'.repeat(64)
let policy: { value: string } | null = null, policyChanged = false
let admin: { id: number } | null = null, batch: { id: string } | null = null
const hosts: number[] = [], orders: string[] = [], storage: number[] = []
type Remote = { boot: string; originalBoot: string; phase: HostKernelPhase; requestId?: string; reboots: number; rollbacks: number;
  installed: string; candidate: string; plan: HostKernelInspection | null; failDispatch: boolean; loseReboot: boolean; loseVerify: boolean; wrongKernel: boolean }
const remotes = new Map<number, Remote>()
const calls: { id: number; action: string; requestId: string }[] = []
let held = false, foreignInventory = false, foreignOperation = false, apparmor = true
const app = Fastify(), originalFetch = globalThis.fetch
let registeredAgentRoutes = false
const deferred = () => {
  let resolve!: () => void
  const promise = new Promise<void>(done => { resolve = done })
  return { promise, resolve }
}
async function enteredInspection(signal: ReturnType<typeof deferred>, operation: Promise<unknown>) {
  let timeout!: ReturnType<typeof setTimeout>
  try {
    await Promise.race([signal.promise, operation.then(() => { throw Error('HARDENING_KERNEL_TEST_INSPECT_NOT_REACHED') }),
      new Promise<never>((_, reject) => { timeout = setTimeout(() => reject(Error('HARDENING_KERNEL_TEST_INSPECT_TIMEOUT')), 15_000) })])
  } finally { clearTimeout(timeout) }
}
const report = (architecture: string, boot: string) => ({ architecture, bootId: boot, pageSize: architecture === 'aarch64' ? 65536 : 4096,
  memoryAvailableKiB: 262144, memoryPressure: 0, rootAvailableBytes: 268435456, rootAvailableInodes: 1024,
  rootReadonly: false, packageBusy: false, apparmorKernelSupport: true, apparmorBootDisabled: false, apparmorActive: true, bootloader: 'grub' as const })
const state = async (id: number) => (await prisma.host.findUniqueOrThrow({ where: { id } })).securityHardening as any
function available(remote: Remote): HostKernelInspection {
  const runningVersion = remote.phase === 'activated' ? remote.installed : '6.12.100-r0'
  const hash = createHash('sha256').update(JSON.stringify([remote.installed, remote.candidate, remote.phase === 'rolled-back'])).digest('hex')
  return { status: 'available', branch: '3.22', flavor: 'linux-virt', bootloader: 'grub',
    runningRelease: runningVersion.replace('-r', '-') + '-virt', installedVersion: remote.installed,
    candidateVersion: remote.candidate, candidateRelease: remote.candidate.replace('-r', '-') + '-virt', planHash: hash, reason: null }
}
async function create(architecture: 'x86_64' | 'aarch64') {
  assert.ok(admin && batch)
  const ip = `10.253.219.${randomInt(20, 220)}`
  let publicIp = ''
  do { publicIp = `198.18.${randomInt(1, 254)}.${randomInt(1, 254)}` }
  while (await prisma.hostOnboardingNode.findFirst({ where: { publicIp, deletedAt: null }, select: { id: true } }))
  const host = await prisma.host.create({ data: { userId: admin.id, name: prefix + hosts.length, url: `https://${ip}:8443`,
    singleTenant: true, isInstalled: true, status: 'online', serverCertificate: 'fixture-original-cert', serverFingerprint: 'fixture-original-pin',
    architecture, resourcePreset: architecture === 'x86_64' ? 'E2' : 'ARM1C', cpuAllowanceMax: architecture === 'x86_64' ? 200 : 100,
    memoryMax: architecture === 'x86_64' ? 768 : 4096, customerDiskGiB: 30, storageSize: 34,
    managementSshHost: ip, managementSshPort: 22, managementSshUser: 'root', onboardingNode: { create: { batchId: batch.id,
      name: prefix + hosts.length, publicIp, managementIp: ip, sshPort: 22, sshFingerprint: 'SHA256:fixture-original',
      nodePublicKey: 'A'.repeat(43) + '=', status: 'succeeded', credentialsExpireAt: new Date(0) } } }, include: { onboardingNode: { include: { batch: true } } } })
  hosts.push(host.id)
  const boot = randomUUID()
  remotes.set(host.id, { boot, originalBoot: boot, phase: 'absent', reboots: 0, rollbacks: 0, installed: '6.12.100-r0', candidate: '6.12.118-r0',
    plan: null, failDispatch: false, loseReboot: false, loseVerify: false, wrongKernel: false })
  await prisma.host.update({ where: { id: host.id }, data: { securityHardening: { revision: SECURITY_HARDENING_REVISION, status: 'verified',
    identityHash: hardeningIdentityHash(host), environment: report(architecture, boot), host: { preflight: { status: 'verified' },
      ssh: { status: 'verified' }, apparmor: { status: 'verified' } }, marker: 'keep original healthy receipt' } } })
  await prisma.hostAgent.create({ data: { hostId: host.id, agentId: randomUUID(), secretHash: 'fixture', secretEncrypted: 'fixture',
    enabled: true, lastSeenAt: new Date(), lastReport: { metrics: { bootId: boot } } } })
  return host
}
const deps: typeof hostKernelMaintenanceDependencies = { ...hostKernelMaintenanceDependencies, held: () => held, accepted: () => true, invalidate: async () => {},
  connect: async () => ({ request: async (method: string, path: string) => {
    assert.equal(method, 'GET', 'kernel maintenance cannot stop, delete or restart any customer')
    if (path.startsWith('/1.0/operations')) {
      assert.match(path, /all-projects=true/)
      return foreignOperation ? { pending: [{ status: 'Pending', project: 'other' }] } : {}
    }
    assert.equal(path, '/1.0/instances?recursion=1&all-projects=true')
    return foreignInventory ? [{ name: 'stopped-hidden', status: 'Stopped', project: 'other' }] : []
  } } as any),
  inspect: async (host: any, guests: any[], update: boolean, allowed: () => Promise<void>) => {
    assert.deepEqual(guests, []); assert.equal(update, false); await allowed()
    const remote = remotes.get(host.id)!
    const architecture = (await state(host.id)).maintenance.architecture
    return { preflight: report(architecture, remote.boot), apparmor, alpine: true, fixed: true, branch: '3.22', guests: [], hostSshUpdated: false }
  },
  command: async (host: any, operation: any) => {
    const wire = hostKernelWireOperation(operation, host.onboardingNode.id, hostKernelWireExpiry(operation))
    assert.deepEqual(Object.keys(wire).sort(), ['action', 'architecture', 'bootId', 'customers', 'expectedPlanHash', 'expiresAt', 'identityHash', 'nodeId', 'prepareHash', 'recipe', 'requestId'])
    const remote = remotes.get(host.id)!
    calls.push({ id: host.id, action: wire.action, requestId: wire.requestId })
    let phase = remote.phase, plan = remote.plan, hash = remote.phase === 'prepared' || ['reboot-intent', 'activated'].includes(remote.phase) ? preparedHash : zero
    if (wire.action === 'inspect') {
      phase = 'inspected'; hash = zero
      plan = remote.phase === 'activated' && remote.installed === remote.candidate ? { ...available(remote), status: 'up-to-date', candidateVersion: null, candidateRelease: null, planHash: null } : available(remote)
    } else if (wire.action === 'status' && remote.requestId !== wire.requestId) {
      assert.ok(!remote.requestId || ['activated', 'rolled-back'].includes(remote.phase))
      phase = 'absent'; plan = null; hash = zero
    } else if (wire.action === 'prepare') {
      if (remote.requestId !== wire.requestId) {
        assert.ok(!remote.requestId || ['activated', 'rolled-back'].includes(remote.phase))
        remote.plan = available(remote); remote.requestId = wire.requestId; remote.originalBoot = wire.bootId; remote.phase = 'absent'
      }
      assert.ok(remote.plan)
      assert.equal(wire.expectedPlanHash, remote.plan.planHash)
      const phases = ['absent', 'prepared-artifacts', 'packages-installed', 'boot-staged', 'prepared'] as const
      remote.phase = phases[Math.min(phases.findIndex(phase => phase === remote.phase) + 1, phases.length - 1)]
      if (remote.phase === 'packages-installed') remote.installed = remote.candidate
      phase = remote.phase; plan = remote.plan; hash = phase === 'prepared' ? preparedHash : zero
    } else if (wire.action === 'reboot') {
      if (remote.failDispatch) { remote.failDispatch = false; throw Error('fixture lost before dispatch') }
      if (remote.phase === 'prepared') { remote.phase = 'reboot-intent'; remote.reboots++ }
      if (remote.loseReboot) { remote.loseReboot = false; throw Error('fixture lost reboot reply') }
      phase = remote.phase; hash = preparedHash
    } else if (wire.action === 'verify') {
      assert.notEqual(remote.boot, wire.bootId)
      if (remote.wrongKernel) throw Error('HARDENING_KERNEL_BOOT_MISMATCH')
      remote.phase = 'activated'; phase = remote.phase; hash = preparedHash
      if (remote.loseVerify) { remote.loseVerify = false; throw Error('fixture lost completion reply') }
    } else if (wire.action === 'rollback') {
      if (remote.phase === 'reboot-intent') assert.notEqual(remote.boot, wire.bootId)
      remote.phase = 'rolled-back'; remote.rollbacks++; phase = remote.phase
    }
    return { version: 1, nodeId: wire.nodeId, requestId: wire.requestId, identityHash: wire.identityHash, originalBootId: wire.bootId,
      bootId: remote.boot, architecture: wire.architecture, recipe: wire.recipe, prepareHash: hash, phase, plan }
  } }
async function customer(hostId: number, status: 'running' | 'stopped' | 'suspended' | 'deleted', cleanup = false, billing = false) {
  assert.ok(admin)
  const host = await prisma.host.findUniqueOrThrow({ where: { id: hostId }, select: { cpuAllowanceMax: true, memoryMax: true, customerDiskGiB: true } })
  assert.ok([100, 200].includes(host.cpuAllowanceMax) && [768, 4096].includes(host.memoryMax) && host.customerDiskGiB === 30)
  return prisma.instance.create({ data: { hostId, userId: admin.id, incusId: prefix + randomUUID().slice(0, 8), name: prefix,
    image: 'alpine/3.22', cpu: host.cpuAllowanceMax, memory: host.memoryMax, disk: host.customerDiskGiB * 1024,
    status, provisioningCleanupPending: cleanup, deletionBillingPending: billing } })
}
async function arrive(hostId: number) {
  const remote = remotes.get(hostId)!
  remote.boot = randomUUID()
  await prisma.hostAgent.update({ where: { hostId }, data: { lastSeenAt: new Date(), lastReport: { metrics: { bootId: remote.boot } } } })
}
async function throughPrepared(hostId: number) {
  await prepareAutomaticHostKernelMaintenance(hostId, deps)
  for (let i = 0; i < 3; i++) await resumeAutomaticHostKernelMaintenance(hostId, deps)
  assert.equal(remotes.get(hostId)!.phase, 'prepared')
  assert.equal((await state(hostId)).maintenance.prepareHash, preparedHash)
}
try {
  // All seed operations live under the same bounded cleanup as the test, so
  // a schema/constraint failure before the first host leaves no actor/batch.
  policy = await prisma.systemConfig.findUnique({ where: { key: SECURITY_HARDENING_ENABLED_KEY }, select: { value: true } })
  admin = await prisma.user.create({ data: { username: prefix, passwordHash: 'isolated-fixture', role: 'admin' } })
  batch = await prisma.hostOnboardingBatch.create({ data: { id: randomUUID(), name: prefix, accountLabel: prefix, createdById: admin.id, defaults: {} } })
  await prisma.systemConfig.upsert({ where: { key: SECURITY_HARDENING_ENABLED_KEY }, update: { value: 'true' }, create: { key: SECURITY_HARDENING_ENABLED_KEY, value: 'true' } })
  policyChanged = true
  const arm = await create('aarch64'), amd = await create('x86_64')
  const originalHealthy = await state(arm.id)
  const identitySelect = { userId: true, name: true, status: true, singleTenant: true, url: true, serverCertificate: true,
    serverFingerprint: true, managementSshHost: true, managementSshPort: true, managementSshUser: true, cpuAllowanceMax: true,
    memoryMax: true, customerDiskGiB: true, storageSize: true, architecture: true } as const
  const originalHost = await prisma.host.findUniqueOrThrow({ where: { id: arm.id }, select: identitySelect })
  const expectedModules = await expectedGatewayMaintenanceModuleHashes()
  const legacyGateway = { publicKey: 'fixture', controlIp: '10.253.240.1', network: '10.253.240.0/20', endpoint: 'gateway.example:51820',
    sshHost: '8.8.4.4', managementSshPublicKey: 'fixture', dnsProtocolVersion: 2 }
  let channelDispatches = 0
  const channelDeps = (declaration: Record<string, unknown>): typeof hostKernelMaintenanceDependencies => ({ ...deps,
    command: async (host, operation) => hostKernelMaintenanceCommand(host, operation, { ...hostKernelMaintenanceChannelDependencies,
      command: async () => ({ ...legacyGateway, ...declaration }) as any,
      exchange: async () => { channelDispatches++; return deps.command(host, operation) } }) })
  for (const declaration of [{}, { maintenanceProtocolVersion: 2 },
    { maintenanceProtocolVersion: false, maintenanceModuleHashes: expectedModules },
    { maintenanceProtocolVersion: 2, maintenanceModuleHashes: { ...expectedModules, 'host-kernel-maintenance.py': 'f'.repeat(64) } },
    { maintenanceProtocolVersion: 2, maintenanceModuleHashes: { ...expectedModules, 'host-security-maintenance.py': false } }]) {
    await prepareAutomaticHostKernelMaintenance(arm.id, channelDeps(declaration))
    const waiting = await state(arm.id), { kernel, ...primary } = waiting
    assert.deepEqual(primary, originalHealthy, 'channel failure only saves its own kernel summary, preserving the original healthy receipt')
    assert.equal(kernel.status, 'waiting-channel'); assert.equal(kernel.reason, HOST_KERNEL_CHANNEL_UPGRADE_REQUIRED)
    assert.equal(Date.parse(kernel.nextCheckAt) - Date.parse(kernel.checkedAt), HOST_KERNEL_CHANNEL_RECHECK_DELAY)
    assert.equal(waiting.maintenance, undefined); assert.equal(hostMaintenanceBlocked(waiting), false)
    assert.deepEqual(await prisma.host.findUniqueOrThrow({ where: { id: arm.id }, select: identitySelect }), originalHost)
    assert.equal(channelDispatches, 0, 'old, malformed or partially published gateways receive zero kernel dispatches')
  }
  const upgradedChannel = channelDeps({ maintenanceProtocolVersion: 2, maintenanceModuleHashes: expectedModules })
  await inspectAutomaticHostKernelMaintenance(arm.id, { ...upgradedChannel, accepted: () => false })
  assert.equal(channelDispatches, 1, 'the same healthy host automatically leaves waiting-channel after trusted helper refresh')
  assert.equal((await state(arm.id)).status, 'verified'); assert.equal((await state(arm.id)).kernel.status, 'waiting-native')
  assert.equal((await state(arm.id)).maintenance, undefined); assert.equal(hostMaintenanceBlocked(await state(arm.id)), false)
  for (const delta of [{ role: 'user' as const }, { status: 'banned' as const }]) {
    await prisma.user.update({ where: { id: admin.id }, data: delta })
    const before = calls.length
    assert.equal(await inspectAutomaticHostKernelMaintenance(arm.id, deps), null)
    assert.equal(calls.length, before); assert.equal((await state(arm.id)).maintenance, undefined)
    await prisma.user.update({ where: { id: admin.id }, data: { role: 'admin', status: 'active' } })
  }
  held = true; const beforeHeld = calls.length
  await prepareAutomaticHostKernelMaintenance(arm.id, deps)
  assert.equal(calls.length, beforeHeld); held = false
  for (const [status, cleanup, billing] of [['running', false, false], ['stopped', false, false], ['suspended', false, false],
    ['deleted', true, false], ['deleted', false, true]] as const) {
    const instance = await customer(arm.id, status, cleanup, billing)
    await prepareAutomaticHostKernelMaintenance(arm.id, deps)
    assert.equal((await state(arm.id)).maintenance, undefined); assert.equal((await state(arm.id)).status, 'verified')
    assert.equal((await state(arm.id)).kernel.status, 'waiting-empty')
    await prisma.instance.delete({ where: { id: instance.id } })
  }
  const order = await prisma.checkoutOrder.create({ data: { id: randomUUID(), userId: admin.id, requestHash: 'fixture', source: 'direct',
    totalCents: 1000, snapshot: 'isolated-fixture', display: {}, expiresAt: new Date(Date.now() + 60000) } })
  orders.push(order.id)
  await prisma.checkoutReservation.create({ data: { hostId: arm.id, orderId: order.id, ordinal: 0 } })
  await prepareAutomaticHostKernelMaintenance(arm.id, deps)
  assert.equal((await state(arm.id)).maintenance, undefined)
  await prisma.checkoutReservation.delete({ where: { hostId: arm.id } })
  const other = await customer(amd.id, 'deleted')
  const task = await prisma.instanceTask.create({ data: { hostId: amd.id, targetHostId: arm.id, instanceId: other.id, userId: admin.id, taskType: 'change_host' } })
  await prepareAutomaticHostKernelMaintenance(arm.id, deps); assert.equal((await state(arm.id)).maintenance, undefined)
  await prisma.instanceTask.delete({ where: { id: task.id } })
  const restore = await prisma.restoreTask.create({ data: { hostId: arm.id, instanceId: other.id, userId: admin.id, originalInstanceName: prefix, originalIncusId: prefix } })
  await prepareAutomaticHostKernelMaintenance(arm.id, deps); assert.equal((await state(arm.id)).maintenance, undefined)
  await prisma.restoreTask.delete({ where: { id: restore.id } })
  const config = await prisma.storageConfig.create({ data: { userId: admin.id, name: prefix, type: 'FTP', host: '127.0.0.1' } })
  storage.push(config.id)
  const upload = await prisma.backupUploadTask.create({ data: { hostId: arm.id, instanceId: other.id, userId: admin.id, backupId: 1, storageConfigId: config.id } })
  await prepareAutomaticHostKernelMaintenance(arm.id, deps); assert.equal((await state(arm.id)).maintenance, undefined)
  await prisma.backupUploadTask.delete({ where: { id: upload.id } })
  await prisma.instance.delete({ where: { id: other.id } })
  foreignInventory = true
  await prepareAutomaticHostKernelMaintenance(arm.id, deps); assert.equal((await state(arm.id)).maintenance, undefined)
  foreignInventory = false; foreignOperation = true
  await prepareAutomaticHostKernelMaintenance(arm.id, deps); assert.equal((await state(arm.id)).maintenance, undefined)
  foreignOperation = false
  const release = beginHostMutation(arm.id)
  await prepareAutomaticHostKernelMaintenance(arm.id, deps); assert.equal((await state(arm.id)).maintenance, undefined)
  release()
  await throughPrepared(arm.id)
  await prepareAutomaticHostKernelMaintenance(amd.id, deps)
  assert.equal((await state(amd.id)).maintenance, undefined); assert.equal(remotes.get(amd.id)!.reboots, 0)
  const remote = remotes.get(arm.id)!
  remote.failDispatch = true
  await resumeAutomaticHostKernelMaintenance(arm.id, deps)
  assert.equal((await state(arm.id)).maintenance.phase, 'reboot-intent'); assert.equal(remote.reboots, 0)
  remote.loseReboot = true
  await resumeAutomaticHostKernelMaintenance(arm.id, deps)
  await resumeAutomaticHostKernelMaintenance(arm.id, deps)
  assert.equal(remote.reboots, 1); assert.equal(remote.phase, 'reboot-intent')
  held = true; const heldAfter = calls.length
  await resumeAutomaticHostKernelMaintenance(arm.id, deps); assert.equal(calls.length, heldAfter); held = false
  await arrive(arm.id)
  await prisma.hostAgent.update({ where: { hostId: arm.id }, data: { enabled: false } })
  await resumeAutomaticHostKernelMaintenance(arm.id, deps)
  assert.equal(remote.phase, 'reboot-intent', 'root activation waits for a new enabled Agent boot report')
  await prisma.hostAgent.update({ where: { hostId: arm.id }, data: { enabled: true } })
  apparmor = false; await resumeAutomaticHostKernelMaintenance(arm.id, deps); assert.equal(remote.phase, 'reboot-intent'); apparmor = true
  remote.loseVerify = true
  await resumeAutomaticHostKernelMaintenance(arm.id, deps)
  assert.equal(remote.phase, 'activated'); assert.notEqual((await state(arm.id)).maintenance.phase, 'verified')
  await resumeAutomaticHostKernelMaintenance(arm.id, deps)
  assert.equal((await state(arm.id)).maintenance.phase, 'verified'); assert.equal((await state(arm.id)).status, 'verified')
  assert.equal((await state(arm.id)).marker, 'keep original healthy receipt'); assert.equal(hostMaintenanceBlocked(await state(arm.id)), false)
  await prepareAutomaticHostKernelMaintenance(arm.id, deps)
  assert.equal(remote.reboots, 1); assert.equal((await state(arm.id)).kernel.status, 'up-to-date')
  await throughPrepared(amd.id)
  await resumeAutomaticHostKernelMaintenance(amd.id, deps)
  await arrive(amd.id); remotes.get(amd.id)!.wrongKernel = true
  await resumeAutomaticHostKernelMaintenance(amd.id, deps)
  assert.equal(remotes.get(amd.id)!.rollbacks, 1); assert.equal((await state(amd.id)).maintenance.phase, 'aborted')
  assert.equal((await state(amd.id)).kernel.reason, 'HARDENING_KERNEL_INSTALLED_BOOT_REQUIRED')
  assert.ok((await state(amd.id)).maintenance.history.some((event: any) => event.phase === 'reboot-intent'))
  assert.equal(hostMaintenanceBlocked(await state(amd.id)), false)

  const unaccepted = await create('x86_64')
  await inspectAutomaticHostKernelMaintenance(unaccepted.id, { ...deps, accepted: () => false })
  const unacceptedState = await state(unaccepted.id), unacceptedBoot = remotes.get(unaccepted.id)!.boot
  const unacceptedStartedAt = Date.now()
  const unacceptedIntent = readHostKernelIntent({ revision: HOST_MAINTENANCE_REVISION, recipe: HOST_KERNEL_MAINTENANCE_RECIPE,
    requestId: randomUUID(), identityHash: unacceptedState.identityHash, bootId: unacceptedBoot, prepareHash: zero,
    architecture: 'x86_64', phase: 'prepared', rebootIssued: false, startedAt: new Date(unacceptedStartedAt).toISOString(),
    deadline: new Date(unacceptedStartedAt + 20 * 60_000).toISOString(), customers: [], expectedPlanHash: unacceptedState.kernel.plan.planHash })
  // A stale or externally-written DB intent cannot bypass the current release
  // gate. A signed root absence proves there is no preparation to clean up.
  await prisma.host.update({ where: { id: unaccepted.id }, data: { securityHardening: { ...unacceptedState, maintenance: unacceptedIntent } } })
  const beforeUnaccepted = calls.length
  await resumeAutomaticHostKernelMaintenance(unaccepted.id, { ...deps, accepted: () => false })
  assert.deepEqual(calls.slice(beforeUnaccepted).map(call => call.action), ['status'])
  assert.equal((await state(unaccepted.id)).maintenance.phase, 'aborted')
  assert.equal((await state(unaccepted.id)).kernel.status, 'waiting-native')
  assert.equal(hostMaintenanceBlocked(await state(unaccepted.id)), false)

  const staged = await create('aarch64')
  await throughPrepared(staged.id)
  // Removing a release acceptance before root dispatch restores the original
  // boot files and clears only its now-confirmed outstanding barrier.
  await resumeAutomaticHostKernelMaintenance(staged.id, { ...deps, accepted: () => false })
  assert.equal(remotes.get(staged.id)!.rollbacks, 1); assert.equal(remotes.get(staged.id)!.reboots, 0)
  assert.equal((await state(staged.id)).maintenance.phase, 'aborted')
  assert.equal((await state(staged.id)).kernel.status, 'waiting-native')
  assert.equal(hostMaintenanceBlocked(await state(staged.id)), false)
  await throughPrepared(staged.id)
  await resumeAutomaticHostKernelMaintenance(staged.id, deps)
  assert.equal(remotes.get(staged.id)!.reboots, 1)
  await arrive(staged.id)
  await resumeAutomaticHostKernelMaintenance(staged.id, { ...deps, accepted: () => false })
  assert.equal((await state(staged.id)).maintenance.phase, 'verified', 'already crossed root barriers retain safe boot recovery')

  const raced = await create('x86_64'), inspected = deferred(), releaseInspection = deferred()
  const slowInspect = { ...deps, command: async (host: any, operation: any) => {
    const receipt = await deps.command(host, operation)
    if (operation.action === 'inspect') { inspected.resolve(); await releaseInspection.promise }
    return receipt
  } }
  const inspection = prepareAutomaticHostKernelMaintenance(raced.id, slowInspect)
  try {
    await enteredInspection(inspected, inspection)
    // This separate real PG transaction would fail if the read-only network
    // wait still retained the host lock. A purchase reserved during the wait
    // wins admission and must remain untouched by maintenance registration.
    await prisma.$transaction(async tx => {
      await tx.$executeRaw`SET LOCAL lock_timeout='1s'`
      await tx.$queryRaw`SELECT id FROM hosts WHERE id=${raced.id} FOR UPDATE`
      await tx.checkoutReservation.create({ data: { hostId: raced.id, orderId: order.id, ordinal: 1 } })
    }, { maxWait: 2000, timeout: 5000 })
  } finally { releaseInspection.resolve() }
  await inspection
  assert.equal((await state(raced.id)).maintenance, undefined)
  assert.equal((await state(raced.id)).status, 'verified')
  assert.equal(await prisma.checkoutReservation.count({ where: { hostId: raced.id } }), 1)
  assert.equal(calls.some(call => call.id === raced.id && call.action !== 'inspect'), false)
  await prisma.checkoutReservation.delete({ where: { hostId: raced.id } })

  const stale = await create('aarch64'), staleEntered = deferred(), staleRelease = deferred()
  const staleInspect = { ...deps, command: async (host: any, operation: any) => {
    const receipt = await deps.command(host, operation)
    if (operation.action === 'inspect') { staleEntered.resolve(); await staleRelease.promise }
    return receipt
  } }
  const delayedSummary = inspectAutomaticHostKernelMaintenance(stale.id, staleInspect)
  try { await enteredInspection(staleEntered, delayedSummary); await prepareAutomaticHostKernelMaintenance(stale.id, deps) }
  finally { staleRelease.resolve() }
  const activeState = await state(stale.id)
  await delayedSummary
  assert.deepEqual((await state(stale.id)).maintenance, activeState.maintenance, 'a stale inspector cannot overwrite a durable maintenance intent')
  assert.equal((await state(stale.id)).kernel.status, 'maintaining')
  assert.equal((await state(stale.id)).marker, 'keep original healthy receipt')
  await resumeAutomaticHostKernelMaintenance(stale.id, { ...deps, accepted: () => false })
  assert.equal(hostMaintenanceBlocked(await state(stale.id)), false)

  const pair = [await create('x86_64'), await create('aarch64')], bothInspected = deferred(), pairRelease = deferred()
  let pairInspections = 0
  const simultaneous = { ...deps, command: async (host: any, operation: any) => {
    const receipt = await deps.command(host, operation)
    if (operation.action === 'inspect') { if (++pairInspections === 2) bothInspected.resolve(); await pairRelease.promise }
    return receipt
  } }
  const competingPreparations = Promise.all(pair.map(host => prepareAutomaticHostKernelMaintenance(host.id, simultaneous)))
  try { await enteredInspection(bothInspected, competingPreparations) } finally { pairRelease.resolve() }
  await competingPreparations
  const activePair = (await Promise.all(pair.map(host => state(host.id)))).filter(value => hostMaintenanceBlocked(value))
  assert.equal(activePair.length, 1, 'the real global PG admission lock permits exactly one maintenance target')
  assert.equal(pair.reduce((count, host) => count + Number(remotes.get(host.id)!.phase !== 'absent'), 0), 1)
  for (const host of pair) {
    assert.equal((await state(host.id)).status, 'verified')
    assert.equal((await state(host.id)).marker, 'keep original healthy receipt')
    if (hostMaintenanceBlocked(await state(host.id))) await resumeAutomaticHostKernelMaintenance(host.id, { ...deps, accepted: () => false })
  }
  assert.equal((await Promise.all(pair.map(host => state(host.id)))).some(value => hostMaintenanceBlocked(value)), false)
  // Exercise the actual HMAC route while the real kernel prepare transaction
  // waits for its bounded remote result. Pure liveness must retain current
  // Agent authority without being starved behind non-key maintenance fields.
  const heartbeatHost = await create('x86_64'), preparing = deferred(), releasePrepare = deferred()
  const secret = generateAgentSecret()
  const heartbeatAgent = await prisma.hostAgent.update({ where: { hostId: heartbeatHost.id }, data: {
    agentId: generateAgentId(), secretHash: hashAgentSecret(secret), secretEncrypted: encryptSensitiveData(secret), lastSeenAt: null,
  } })
  for (const name of ['authenticate', 'authenticateAdmin']) app.decorate(name, async (request: any) => {
    request.user = { id: admin!.id, sid: prefix, iat: Math.floor(Date.now() / 1000) + 1 }
  })
  globalThis.fetch = async () => new Response(JSON.stringify({ tag_name: 'agent-v1.0.3', assets: [] }), {
    status: 200, headers: { 'content-type': 'application/json' },
  })
  await app.register(agentRoutes, { prefix: '/agent' }); registeredAgentRoutes = true
  const waitingPrepare = prepareAutomaticHostKernelMaintenance(heartbeatHost.id, { ...deps,
    command: async (host: any, operation: any) => {
      if (operation.action === 'prepare') { preparing.resolve(); await releasePrepare.promise }
      return deps.command(host, operation)
    },
  })
  let heartbeat: Promise<unknown> | undefined, heartbeatTimer: ReturnType<typeof setTimeout> | undefined
  try {
    await enteredInspection(preparing, waitingPrepare)
    const payload = { version: 'kernel-lock-fixture', runtime: { goos: 'linux', goarch: 'amd64' },
      metrics: { heartbeatIntervalSeconds: 30, bootId: remotes.get(heartbeatHost.id)!.boot } }
    const timestamp = String(Date.now()), nonce = randomUUID(), bodyHash = createAgentBodyHash(payload)
    heartbeat = app.inject({ method: 'POST', url: '/agent/heartbeat', payload, headers: {
      'x-incudal-agent-id': heartbeatAgent.agentId, 'x-incudal-timestamp': timestamp,
      'x-incudal-nonce': nonce, 'x-incudal-body-sha256': bodyHash,
      'x-incudal-signature': createAgentSignature(secret, { method: 'POST', path: '/agent/heartbeat', timestamp, nonce, bodyHash }),
    } }).then(response => {
      if (response.statusCode !== 200) assert.fail('HARDENING_KERNEL_TEST_HEARTBEAT_' +
        (/^AGENT_[A-Z_]+$/.test(response.json().code || '') ? response.json().code : 'REJECTED'))
      assert.equal(response.statusCode, 200, 'current signed liveness must finish during kernel preparation')
      assert.equal(response.json().ok, true)
    })
    await Promise.race([heartbeat, new Promise<never>((_, reject) => {
      heartbeatTimer = setTimeout(() => reject(Error('HARDENING_KERNEL_TEST_HEARTBEAT_LOCKED')), 1500)
    })])
    const live = await prisma.hostAgent.findUniqueOrThrow({ where: { hostId: heartbeatHost.id } })
    assert.equal(live.id, heartbeatAgent.id); assert.equal(live.agentId, heartbeatAgent.agentId)
    assert.equal(live.secretHash, heartbeatAgent.secretHash); assert.ok(live.lastSeenAt)
    assert.equal(remotes.get(heartbeatHost.id)!.reboots, 0)
  } finally {
    clearTimeout(heartbeatTimer); releasePrepare.resolve()
    await waitingPrepare; await heartbeat?.catch(() => {})
  }
  await resumeAutomaticHostKernelMaintenance(heartbeatHost.id, { ...deps, accepted: () => false })
  assert.equal(hostMaintenanceBlocked(await state(heartbeatHost.id)), false)
  console.log('Real PostgreSQL kernel admission, concurrent reservations, serialized targets, stale inspections, native gates and original-boot recovery guards passed')
  console.log('Actual HMAC heartbeat remains live during a real locked kernel preparation; original Agent credentials and reboot gates retained')
} finally {
  try {
    globalThis.fetch = originalFetch
    if (registeredAgentRoutes) await app.close()
    if (orders.length) {
      await prisma.checkoutReservation.deleteMany({ where: { orderId: { in: orders } } })
      await prisma.checkoutOrder.deleteMany({ where: { id: { in: orders } } })
    }
    if (hosts.length) {
      await prisma.restoreTask.deleteMany({ where: { hostId: { in: hosts } } })
      await prisma.backupUploadTask.deleteMany({ where: { hostId: { in: hosts } } })
      await prisma.instanceTask.deleteMany({ where: { OR: [{ hostId: { in: hosts } }, { targetHostId: { in: hosts } }] } })
      await prisma.instance.deleteMany({ where: { hostId: { in: hosts } } })
      await prisma.host.deleteMany({ where: { id: { in: hosts } } })
    }
    if (storage.length) await prisma.storageConfig.deleteMany({ where: { id: { in: storage } } })
    if (batch) await prisma.hostOnboardingBatch.delete({ where: { id: batch.id } })
    if (admin) await prisma.user.delete({ where: { id: admin.id } })
    if (policyChanged) {
      if (policy) await prisma.systemConfig.update({ where: { key: SECURITY_HARDENING_ENABLED_KEY }, data: { value: policy.value } })
      else await prisma.systemConfig.deleteMany({ where: { key: SECURITY_HARDENING_ENABLED_KEY } })
    }
  } finally { await closePrismaDatabase() }
}
