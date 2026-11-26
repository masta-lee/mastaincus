import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { automaticHostKernelPatchAllowed, HOST_KERNEL_MAINTENANCE_RECIPE, hostKernelReleaseVersion,
  hostKernelVersionRelease, nextHostKernelAction, readHostKernelInspection, readHostKernelIntent,
  readHostKernelReceipt, sameHostKernelPatchSeries, type HostKernelInspection } from '../src/lib/host-kernel-maintenance-plan.js'
import { HOST_MAINTENANCE_REVISION } from '../src/lib/host-maintenance-plan.js'
import { hostKernelWireExpiry, hostKernelWireOperation } from '../src/services/host-kernel-maintenance-channel.js'

const zero = '0'.repeat(64), digest = 'a'.repeat(64), prepareHash = 'b'.repeat(64)
const now = Date.now(), bootId = randomUUID(), nodeId = randomUUID(), requestId = randomUUID()
const plan: HostKernelInspection = { status: 'available', branch: '3.22', flavor: 'linux-virt', bootloader: 'grub',
  runningRelease: '6.12.100-0-virt', installedVersion: '6.12.100-r0', candidateVersion: '6.12.118-r0',
  candidateRelease: '6.12.118-0-virt', planHash: digest, reason: null }
const intent = readHostKernelIntent({ revision: HOST_MAINTENANCE_REVISION, requestId, identityHash: digest,
  bootId, prepareHash: zero, recipe: HOST_KERNEL_MAINTENANCE_RECIPE, architecture: 'x86_64', phase: 'prepared',
  rebootIssued: false, startedAt: new Date(now).toISOString(), deadline: new Date(now + 20 * 60_000).toISOString(),
  customers: [], expectedPlanHash: digest })
const receipt = readHostKernelReceipt({ version: 1, nodeId, requestId, identityHash: digest, originalBootId: bootId,
  bootId, prepareHash, recipe: intent.recipe, architecture: intent.architecture, phase: 'prepared', plan })
assert.equal(hostKernelVersionRelease('6.12.118-r0', 'linux-virt'), '6.12.118-0-virt')
assert.equal(hostKernelVersionRelease('6.12.118-r10', 'linux-lts'), '6.12.118-10-lts')
assert.equal(hostKernelReleaseVersion('6.12.118-10-lts', 'linux-lts'), '6.12.118-r10')
assert.throws(() => hostKernelReleaseVersion('6.12.118-0-virt', 'linux-lts'))
for (const [before, after, expected] of [['6.12.9-r0', '6.12.10-r0', true], ['6.12.118-r9', '6.12.118-r10', true],
  ['6.12.118-r0', '6.13.1-r0', false], ['6.12.118-r0', '6.12.118-r0', false], ['6.12.118-r0', '6.12.100-r2', false],
  ['6.12.118-r0', '6.12.118-r00', false]] as const) assert.equal(sameHostKernelPatchSeries(before, after), expected)
assert.deepEqual(readHostKernelInspection(plan), plan)
assert.deepEqual(readHostKernelInspection({ ...plan, installedVersion: plan.candidateVersion }), { ...plan, installedVersion: plan.candidateVersion },
  'authenticated recovery can re-stage an already-installed same-series candidate')
for (const delta of [{ candidateVersion: '6.13.1-r0', candidateRelease: '6.13.1-0-virt' }, { candidateRelease: '6.12.118-0-lts' },
  { candidateVersion: '6.12.100-r0', candidateRelease: plan.runningRelease }, { branch: 'edge' }, { planHash: null },
  { runningRelease: '5.15.1-0-virt' }, { status: ['available'] }, { status: 'up-to-date' }, { reason: 'private-secret' }, { command: 'reboot' }])
  assert.throws(() => readHostKernelInspection({ ...plan, ...delta }))
const current = { ...plan, status: 'up-to-date', candidateVersion: null, candidateRelease: null, planHash: null }
assert.equal(readHostKernelInspection(current).status, 'up-to-date')
assert.throws(() => readHostKernelInspection({ ...current, runningRelease: '6.12.99-0-virt' }))
for (const architecture of ['x86_64', 'aarch64'] as const) assert.equal(automaticHostKernelPatchAllowed(plan, architecture), false)
for (const delta of [{ customers: [{}] }, { expectedPlanHash: null }, { command: 'reboot' }, { identityHash: [digest] },
  { history: [{ phase: 'unknown', at: new Date(now).toISOString() }] }, { error: 'raw database output' }])
  assert.throws(() => readHostKernelIntent({ ...intent, ...delta }))
for (const delta of [{ phase: 'activated' }, { phase: 'prepared-artifacts' }, { phase: ['prepared'] }, { plan: { ...plan, paths: ['/boot'] } },
  { prepareHash: zero }, { version: 2 }, { customers: [] }]) assert.throws(() => readHostKernelReceipt({ ...receipt, ...delta }))
assert.equal(nextHostKernelAction(intent, receipt, now), 'reboot')
for (const phase of ['prepared-artifacts', 'packages-installed', 'boot-staged'] as const)
  assert.equal(nextHostKernelAction(intent, { ...receipt, phase, prepareHash: zero }, now), 'prepare')
assert.equal(nextHostKernelAction(intent, { ...receipt, phase: 'absent', plan: null, prepareHash: zero }, now), 'prepare')
assert.equal(nextHostKernelAction(intent, receipt, now + 21 * 60_000), 'rollback')
assert.equal(nextHostKernelAction(intent, receipt, now, true), 'wait')
for (const delta of [{ requestId: randomUUID() }, { architecture: 'aarch64' as const }, { identityHash: 'c'.repeat(64) },
  { plan: { ...plan, planHash: 'c'.repeat(64) } }, { bootId: randomUUID() }])
  assert.equal(nextHostKernelAction(intent, { ...receipt, ...delta }, now), 'blocked')
const issued = { ...intent, phase: 'reboot-intent' as const, prepareHash, rebootIssued: true }
assert.equal(nextHostKernelAction(issued, receipt, now), 'reboot', 'lost dispatch resends the original durable request')
assert.equal(nextHostKernelAction(issued, { ...receipt, phase: 'reboot-intent' }, now + 21 * 60_000), 'wait', 'expiry never clears root barrier')
const arrival = { ...receipt, phase: 'reboot-intent' as const, bootId: randomUUID() }
assert.equal(nextHostKernelAction(issued, arrival, now + 21 * 60_000), 'verify')
assert.equal(nextHostKernelAction(intent, arrival, now), 'blocked', 'old DB intent cannot infer reboot authority')
assert.equal(nextHostKernelAction(issued, { ...arrival, phase: 'activated' }, now), 'complete')
assert.equal(nextHostKernelAction(issued, { ...arrival, phase: 'rolled-back' }, now), 'abort')
assert.equal(nextHostKernelAction(issued, { ...receipt, phase: 'rolled-back' }, now), 'blocked')
const operation = { ...intent, action: 'prepare' as const }
const wire = hostKernelWireOperation(operation, nodeId, hostKernelWireExpiry(operation, now))
assert.deepEqual(Object.keys(wire).sort(), ['action', 'architecture', 'bootId', 'customers', 'expectedPlanHash', 'expiresAt',
  'identityHash', 'nodeId', 'prepareHash', 'recipe', 'requestId'])
assert.equal(wire.expiresAt, now + 59_000)
assert.equal(hostKernelWireExpiry({ ...operation, deadline: new Date(now + 250).toISOString() }, now), now + 250)
assert.throws(() => hostKernelWireExpiry({ ...operation, deadline: new Date(now).toISOString() }, now))
for (const delta of [{ customers: [{}] }, { expectedPlanHash: null }, { recipe: 'alpine-apparmor-grub-v1' }, { prepareHash: null }])
  assert.throws(() => hostKernelWireOperation({ ...operation, ...delta } as any, nodeId, now + 59_000))
assert.equal(hostKernelWireOperation({ ...operation, action: 'inspect', expectedPlanHash: null }, nodeId, now + 59_000).expectedPlanHash, null)
console.log('Host kernel plan, protocol, original barrier and native acceptance guards passed')
execFileSync(process.platform === 'win32' ? 'python' : 'python3', ['-B',
  fileURLToPath(new URL('../../scripts/test-host-kernel-maintenance.py', import.meta.url))],
  { stdio: 'inherit', timeout: 180_000 })
