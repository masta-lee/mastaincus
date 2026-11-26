import { randomUUID } from 'node:crypto'
import { Prisma } from '@prisma/client'
import { prisma } from '../db/prisma.js'
import { hardeningIdentityHash } from '../lib/hardening-identity.js'
import { hostMaintenanceBlocked } from '../lib/host-maintenance-gate.js'
import { withHostMaintenanceLane } from '../lib/host-operation-lane.js'
import { HOST_MAINTENANCE_REVISION, readHostMaintenanceIntent, recordMaintenanceEvent } from '../lib/host-maintenance-plan.js'
import { automaticHostKernelPatchAllowed, HOST_KERNEL_MAINTENANCE_RECIPE, HOST_KERNEL_MAX_PREPARATION_RETRIES,
  HOST_KERNEL_CHANNEL_UPGRADE_REQUIRED, HOST_KERNEL_CHANNEL_RECHECK_DELAY,
  HOST_KERNEL_PREPARATION_WINDOW, HOST_KERNEL_RETRY_DELAY, HOST_KERNEL_STATE_REVISION, nextHostKernelAction,
  readHostKernelIntent, readHostKernelReceipt, readHostKernelInspection, type HostKernelArchitecture, type HostKernelInspection,
  type HostKernelIntent, type HostKernelReceipt, type HostKernelState } from '../lib/host-kernel-maintenance-plan.js'
import { onboardingOwnsHardening, ownsOnboardingHardeningLease } from '../lib/onboarding-hardening-owner.js'
import { hardeningPreflightCheck } from './host-security-inspection.js'
import { hostKernelMaintenanceCommand, type HostKernelOperation } from './host-kernel-maintenance-channel.js'
import { authorizeHostMaintenance, lockHostMaintenanceCustomers, readHostMaintenanceCustomers,
  assertHostMaintenanceRemoteBaseline, hostMaintenanceDependencies, type HostMaintenanceHost } from './host-security-maintenance.js'

type Enrollment = { nodeId: string; leaseToken: string }
const include = { onboardingNode: { include: { batch: true } }, agent: true } as const
const record = (value: unknown): Record<string, unknown> => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
const json = (value: unknown) => value as Prisma.InputJsonValue
const zero = '0'.repeat(64)
const code = (error: unknown): string => error instanceof Error && /^HARDENING_[A-Z_]{1,90}$/.test(error.message) ? error.message : 'HARDENING_KERNEL_REMOTE_UNKNOWN'
export const hostKernelMaintenanceDependencies = {
  held: hostMaintenanceDependencies.held, command: hostKernelMaintenanceCommand, accepted: automaticHostKernelPatchAllowed,
  connect: hostMaintenanceDependencies.connect, invalidate: hostMaintenanceDependencies.invalidate, inspect: hostMaintenanceDependencies.inspect,
}
type Dependencies = typeof hostKernelMaintenanceDependencies

function enrollmentOwns(host: HostMaintenanceHost, enrollment?: Enrollment): boolean {
  return enrollment ? ownsOnboardingHardeningLease(host.onboardingNode, enrollment) : !onboardingOwnsHardening(host.onboardingNode)
}
function kernelState(identityHash: string, status: HostKernelState['status'], plan: HostKernelInspection | null, reason: string | null,
  delay: number): HostKernelState {
  const now = Date.now()
  return { revision: HOST_KERNEL_STATE_REVISION, identityHash, status, plan, reason,
    checkedAt: new Date(now).toISOString(), nextCheckAt: new Date(now + delay).toISOString() }
}
function originalOperation(intent: HostKernelIntent, action: HostKernelOperation['action']): HostKernelOperation {
  return { ...intent, action, expectedPlanHash: intent.expectedPlanHash, customers: [] }
}
function checkReceipt(host: HostMaintenanceHost, intent: HostKernelIntent, raw: unknown): HostKernelReceipt {
  const receipt = readHostKernelReceipt(raw)
  if (receipt.nodeId !== host.onboardingNode?.id || receipt.requestId !== intent.requestId || receipt.identityHash !== intent.identityHash ||
    receipt.originalBootId !== intent.bootId || receipt.recipe !== intent.recipe || receipt.architecture !== intent.architecture ||
    receipt.plan !== null && receipt.plan.planHash !== intent.expectedPlanHash ||
    intent.prepareHash !== zero && receipt.prepareHash !== intent.prepareHash) throw Error('HARDENING_KERNEL_RESULT_UNKNOWN')
  return receipt
}
async function emptyHost(tx: Prisma.TransactionClient, host: HostMaintenanceHost, deps: Dependencies, intent: HostKernelIntent) {
  if ((await readHostMaintenanceCustomers(tx, host.id, intent)).length) throw Error('HARDENING_KERNEL_HOST_OCCUPIED')
  await assertHostMaintenanceRemoteBaseline(host, tx, { ...hostMaintenanceDependencies, connect: deps.connect }, intent)
}
async function lockedHost(tx: Prisma.TransactionClient, hostId: number, deps: Dependencies, enrollment?: Enrollment) {
  await tx.$executeRaw`SET LOCAL lock_timeout='2s'`
  await tx.$queryRaw`SELECT pg_advisory_xact_lock(4128,1)::text`
  await lockHostMaintenanceCustomers(tx, hostId)
  // Maintenance changes only non-key state. Keep mutations/credential
  // rotation excluded while permitting the Agent's KEY SHARE liveness lock.
  await tx.$queryRaw`SELECT id FROM hosts WHERE id=${hostId} FOR NO KEY UPDATE`
  const host = await tx.host.findUniqueOrThrow({ where: { id: hostId }, include })
  if (!enrollmentOwns(host, enrollment)) throw Error('HARDENING_BUSY')
  await authorizeHostMaintenance(tx, host, deps.held, enrollment)
  return host
}
async function currentIntent(tx: Prisma.TransactionClient, hostId: number, deps: Dependencies, requestId: string, enrollment?: Enrollment) {
  const host = await lockedHost(tx, hostId, deps, enrollment), state = record(host.securityHardening)
  const intent = readHostKernelIntent(state.maintenance)
  if (intent.requestId !== requestId || intent.identityHash !== hardeningIdentityHash(host)) throw Error('HARDENING_IDENTITY_CHANGED')
  return { host, state, intent }
}
async function saveKernelSummary(host: HostMaintenanceHost, summary: HostKernelState, deps: Dependencies, enrollment?: Enrollment) {
  if (deps.held()) return
  await prisma.$transaction(async tx => {
    await tx.$executeRaw`SET LOCAL lock_timeout='2s'`
    await tx.$queryRaw`SELECT id FROM hosts WHERE id=${host.id} FOR NO KEY UPDATE`
    const current = await tx.host.findUnique({ where: { id: host.id }, include })
    if (!current || !enrollmentOwns(current, enrollment) || hardeningIdentityHash(current) !== summary.identityHash || deps.held()) return
    const state = record(current.securityHardening)
    // A stale read-only check cannot overwrite an active maintenance receipt.
    if (state.maintenance && hostMaintenanceBlocked(state)) return
    await tx.host.update({ where: { id: current.id }, data: { securityHardening: json({ ...state, kernel: summary }) } })
  }, { maxWait: 3000, timeout: 8000 })
}

/** Signed planning writes only a separate summary. Waiting for empty inventory
 * or native acceptance never synthesizes a primary fault or maintenance fence. */
export async function inspectAutomaticHostKernelMaintenance(hostId: number, deps = hostKernelMaintenanceDependencies,
  enrollment?: Enrollment): Promise<HostKernelReceipt | null> {
  if (deps.held()) return null
  const host = await prisma.host.findUnique({ where: { id: hostId }, include })
  if (!host || !enrollmentOwns(host, enrollment) || hostMaintenanceBlocked(host.securityHardening)) return null
  const identityHash = hardeningIdentityHash(host), environment = record(record(host.securityHardening).environment)
  try {
    if (!['x86_64', 'aarch64'].includes(String(environment.architecture)) || typeof environment.bootId !== 'string' ||
      !/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(environment.bootId)) throw Error('HARDENING_KERNEL_BOOT_UNKNOWN')
    // Authentication is bounded and committed before the separate read-only
    // network wait; no host row/instance lock spans index downloads.
    await prisma.$transaction(tx => authorizeHostMaintenance(tx, host, deps.held, enrollment), { maxWait: 3000, timeout: 8000 })
    const operation: HostKernelOperation = { action: 'inspect', requestId: randomUUID(), identityHash,
      bootId: environment.bootId, prepareHash: zero, recipe: HOST_KERNEL_MAINTENANCE_RECIPE,
      architecture: environment.architecture as HostKernelArchitecture, expectedPlanHash: null, customers: [] }
    if (deps.held()) return null
    const receipt = readHostKernelReceipt(await deps.command(host, operation))
    if (receipt.phase !== 'inspected' || !receipt.plan || receipt.nodeId !== host.onboardingNode?.id || receipt.requestId !== operation.requestId ||
      receipt.identityHash !== identityHash || receipt.originalBootId !== operation.bootId || receipt.recipe !== operation.recipe ||
      receipt.architecture !== operation.architecture) throw Error('HARDENING_KERNEL_RESULT_UNKNOWN')
    const plan = receipt.plan
    let status: HostKernelState['status'] = plan.status, reason = plan.reason, delay = 6 * 60 * 60_000
    if (plan.status === 'available') {
      const occupied = await prisma.instance.count({ where: { hostId, OR: [{ status: { not: 'deleted' } },
        { provisioningCleanupPending: true }, { deletionBillingPending: true }] } })
      status = occupied ? 'waiting-empty' : deps.accepted(plan, receipt.architecture) ? 'available' : 'waiting-native'
      reason = occupied ? 'HARDENING_KERNEL_HOST_OCCUPIED' : status === 'waiting-native' ? 'HARDENING_KERNEL_NATIVE_ACCEPTANCE_REQUIRED' : null
      delay = occupied ? 5 * 60_000 : status === 'waiting-native' ? 60 * 60_000 : 1000
    }
    await saveKernelSummary(host, kernelState(identityHash, status, plan, reason, delay), deps, enrollment)
    return receipt
  } catch (error) {
    const reason = code(error), waitingChannel = reason === HOST_KERNEL_CHANNEL_UPGRADE_REQUIRED
    await saveKernelSummary(host, kernelState(identityHash, waitingChannel ? 'waiting-channel' : 'retry', null, reason,
      waitingChannel ? HOST_KERNEL_CHANNEL_RECHECK_DELAY : 5 * 60_000), deps, enrollment)
    return null
  }
}

export async function prepareAutomaticHostKernelMaintenance(hostId: number, deps = hostKernelMaintenanceDependencies,
  enrollment?: Enrollment): Promise<void> {
  const receipt = await inspectAutomaticHostKernelMaintenance(hostId, deps, enrollment)
  if (!receipt || receipt.plan?.status !== 'available' || !deps.accepted(receipt.plan, receipt.architecture) || deps.held()) return
  const plan = receipt.plan
  let registered = false
  try {
    await withHostMaintenanceLane(hostId, () => prisma.$transaction(async tx => {
      const host = await lockedHost(tx, hostId, deps, enrollment), state = record(host.securityHardening)
      if (hostMaintenanceBlocked(state) || hardeningIdentityHash(host) !== receipt.identityHash) throw Error('HARDENING_BUSY')
      const environment = record(state.environment)
      if (environment.architecture !== receipt.architecture || environment.bootId !== receipt.bootId) throw Error('HARDENING_KERNEL_BOOT_CHANGED')
      const others = await tx.host.findMany({ where: { id: { not: hostId }, securityHardening: { path: ['maintenance'], not: Prisma.AnyNull } }, select: { securityHardening: true } })
      if (others.some(row => hostMaintenanceBlocked(row.securityHardening))) throw Error('HARDENING_BATCH_PAUSED')
      if (await tx.instance.count({ where: { hostId, OR: [{ status: { not: 'deleted' } }, { provisioningCleanupPending: true }, { deletionBillingPending: true }] } }))
        throw Error('HARDENING_KERNEL_HOST_OCCUPIED')
      const now = Date.now()
      const intent = readHostKernelIntent({ revision: HOST_MAINTENANCE_REVISION, recipe: HOST_KERNEL_MAINTENANCE_RECIPE,
        requestId: randomUUID(), identityHash: hardeningIdentityHash(host), bootId: receipt.bootId, prepareHash: zero,
        architecture: receipt.architecture, phase: 'prepared', rebootIssued: false, startedAt: new Date(now).toISOString(),
        deadline: new Date(now + HOST_KERNEL_PREPARATION_WINDOW).toISOString(), customers: [], expectedPlanHash: plan.planHash })
      await emptyHost(tx, host, deps, intent)
      await authorizeHostMaintenance(tx, host, deps.held, enrollment)
      if (Date.now() >= Date.parse(intent.deadline)) throw Error('HARDENING_REQUEST_EXPIRED')
      // Keep an independently parsed terminal intent in the admin evidence;
      // neither expiry nor a read-only check can archive a nonterminal one.
      const previous = state.maintenance ? record(state.maintenance).recipe === HOST_KERNEL_MAINTENANCE_RECIPE
        ? readHostKernelIntent(state.maintenance) : readHostMaintenanceIntent(state.maintenance) : null
      const archive = Array.isArray(state.maintenanceHistory) ? state.maintenanceHistory.slice(-7) : []
      if (previous) archive.push({ at: new Date(now).toISOString(), intent: previous })
      recordMaintenanceEvent(intent)
      await tx.host.update({ where: { id: hostId }, data: { securityHardening: json({ ...state,
        ...(previous ? { maintenanceHistory: archive } : {}), maintenance: intent,
        kernel: kernelState(intent.identityHash, 'maintaining', plan, null, 1000), nextCheckAt: new Date(now + 1000).toISOString() }) } })
      registered = true
    }, { maxWait: 3000, timeout: 30_000 }))
  } catch (error) {
    const host = await prisma.host.findUnique({ where: { id: hostId }, include })
    if (host) await saveKernelSummary(host, kernelState(hardeningIdentityHash(host),
      ['HARDENING_KERNEL_HOST_OCCUPIED', 'HARDENING_BUSY', 'HARDENING_KERNEL_HOST_BUSY', 'HARDENING_CUSTOMER_BOOT_RECOVERY_UNVERIFIED'].includes(code(error)) ? 'waiting-empty' : 'retry',
      plan, code(error), 5 * 60_000), deps, enrollment)
  }
  if (registered) await resumeAutomaticHostKernelMaintenance(hostId, deps, enrollment)
}

async function bootProof(tx: Prisma.TransactionClient, host: HostMaintenanceHost, deps: Dependencies, intent: HostKernelIntent, bootId: string, enrollment?: Enrollment) {
  await emptyHost(tx, host, deps, intent)
  const report = await deps.inspect(host, [], false, () => authorizeHostMaintenance(tx, host, deps.held, enrollment), Date.now() + 40_000, randomUUID())
  const agent = await tx.hostAgent.findUnique({ where: { hostId: host.id }, select: { enabled: true, lastSeenAt: true, lastReport: true } })
  if (report.preflight.bootId !== bootId || bootId === intent.bootId || report.preflight.architecture !== intent.architecture ||
    !report.alpine || !report.fixed || !report.apparmor || !report.preflight.apparmorActive || report.guests.length ||
    hardeningPreflightCheck(report.preflight).status !== 'verified' || !agent?.enabled || !agent.lastSeenAt ||
    agent.lastSeenAt.getTime() < Date.parse(intent.startedAt) || agent.lastSeenAt.getTime() > Date.now() + 1000 || Date.now() - agent.lastSeenAt.getTime() > 90_000 ||
    record(record(agent.lastReport).metrics).bootId !== bootId) throw Error('HARDENING_KERNEL_RECONNECT_INCOMPLETE')
  return report
}

async function persistProgress(tx: Prisma.TransactionClient, host: HostMaintenanceHost, state: Record<string, unknown>,
  intent: HostKernelIntent, plan: HostKernelInspection | null, status: HostKernelState['status'] = 'maintaining', reason: string | null = null,
  delay = 1000) {
  recordMaintenanceEvent(intent, reason || undefined)
  await tx.host.update({ where: { id: host.id }, data: { securityHardening: json({ ...state, maintenance: intent,
    kernel: kernelState(intent.identityHash, status, plan, reason, delay), nextCheckAt: new Date(Date.now() + delay).toISOString() }) } })
}

export async function resumeAutomaticHostKernelMaintenance(hostId: number, deps = hostKernelMaintenanceDependencies,
  enrollment?: Enrollment): Promise<void> {
  if (deps.held()) return
  await withHostMaintenanceLane(hostId, async () => {
    let original: HostKernelIntent | undefined
    try {
      const selected = await prisma.host.findUnique({ where: { id: hostId }, select: { securityHardening: true } })
      if (!record(selected?.securityHardening).maintenance) return
      original = readHostKernelIntent(record(selected?.securityHardening).maintenance)
      if (['verified', 'aborted'].includes(original.phase)) return
      const pending = await prisma.$transaction(async tx => {
        const { host, state, intent } = await currentIntent(tx, hostId, deps, original!.requestId, enrollment)
        const receipt = checkReceipt(host, intent, await deps.command(host, originalOperation(intent, 'status')))
        if (intent.prepareHash === zero && receipt.prepareHash !== zero) intent.prepareHash = receipt.prepareHash
        let decision = nextHostKernelAction(intent, receipt, Date.now(), deps.held())
        if (receipt.phase === 'absent' && !intent.rebootIssued && intent.prepareHash === zero &&
          ['HARDENING_KERNEL_PLAN_CHANGED', 'HARDENING_KERNEL_ORPHAN_PREPARATION'].includes(intent.error || '')) decision = 'abort'
        if (decision === 'prepare' && (intent.preparationRetries || 0) >= HOST_KERNEL_MAX_PREPARATION_RETRIES)
          decision = receipt.phase === 'absent' ? 'abort' : 'rollback'
        if (decision === 'blocked') throw Error('HARDENING_KERNEL_JOURNAL_CONFLICT')
        let nativeRequired = false
        if (decision === 'prepare' || decision === 'reboot') {
          // A persisted request is not release acceptance. Recheck the current
          // native gate before package writes or crossing the root reboot
          // barrier, including a lost-dispatch retry. An already-issued root
          // barrier still proceeds through its original safe boot recovery.
          let plan = receipt.plan
          if (!plan) try { plan = readHostKernelInspection(record(state.kernel).plan) } catch { /* absence grants only abort authority */ }
          if (!plan || plan.planHash !== intent.expectedPlanHash || !deps.accepted(plan, intent.architecture)) {
            nativeRequired = true
            decision = receipt.phase === 'absent' ? 'abort' : 'rollback'
          }
        }
        if (decision === 'prepare') {
          await emptyHost(tx, host, deps, intent)
          await authorizeHostMaintenance(tx, host, deps.held, enrollment)
          const prepared = checkReceipt(host, intent, await deps.command(host, originalOperation(intent, 'prepare')))
          if (prepared.phase === 'prepared') intent.prepareHash = prepared.prepareHash
          if (!['prepared-artifacts', 'packages-installed', 'boot-staged', 'prepared'].includes(prepared.phase)) throw Error('HARDENING_KERNEL_PREPARE_INCOMPLETE')
          await persistProgress(tx, host, state, intent, prepared.plan)
          return null
        }
        if (decision === 'rollback') {
          await emptyHost(tx, host, deps, intent)
          const rolled = checkReceipt(host, intent, await deps.command(host, originalOperation(intent, 'rollback')))
          if (rolled.phase !== 'rolled-back') throw Error('HARDENING_KERNEL_ROLLBACK_INCOMPLETE')
          // Clear only the now-confirmed outstanding barrier. Its original
          // reboot-intent remains in immutable root and local history.
          intent.phase = 'aborted'; intent.rebootIssued = false; delete intent.error
          await persistProgress(tx, host, state, intent, rolled.plan, nativeRequired ? 'waiting-native' : 'retry',
            nativeRequired ? 'HARDENING_KERNEL_NATIVE_ACCEPTANCE_REQUIRED' : 'HARDENING_KERNEL_INSTALLED_BOOT_REQUIRED',
            nativeRequired ? 60 * 60_000 : HOST_KERNEL_RETRY_DELAY)
          return null
        }
        if (decision === 'abort') {
          intent.phase = 'aborted'; intent.rebootIssued = false; delete intent.error
          let plan = receipt.plan
          if (!plan && nativeRequired) try { plan = readHostKernelInspection(record(state.kernel).plan) } catch { /* no root state was created */ }
          await persistProgress(tx, host, state, intent, plan, nativeRequired ? 'waiting-native' : 'retry',
            nativeRequired ? 'HARDENING_KERNEL_NATIVE_ACCEPTANCE_REQUIRED' : 'HARDENING_KERNEL_PREPARATION_ABORTED',
            nativeRequired ? 60 * 60_000 : HOST_KERNEL_RETRY_DELAY)
          return null
        }
        if (decision === 'reboot') {
          await emptyHost(tx, host, deps, intent)
          intent.phase = 'reboot-intent'; intent.rebootIssued = true; delete intent.error
        } else if (decision === 'wait' && receipt.phase === 'reboot-intent') intent.phase = 'waiting-boot'
        else if (decision === 'verify' || decision === 'complete') intent.phase = 'restoring'
        await persistProgress(tx, host, state, intent, receipt.plan, 'maintaining', null, 30_000)
        return { host, intent, decision, receipt }
      }, { maxWait: 3000, timeout: 90_000 })
      if (!pending || deps.held()) return
      if (pending.decision === 'reboot') {
        // This short transaction starts after the reboot intent committed.
        // The root journal fsyncs its own barrier before normal /sbin/reboot.
        await prisma.$transaction(async tx => {
          const { host, state, intent } = await currentIntent(tx, hostId, deps, pending.intent.requestId, enrollment)
          if (intent.phase !== 'reboot-intent' || !intent.rebootIssued) throw Error('HARDENING_KERNEL_JOURNAL_CONFLICT')
          await emptyHost(tx, host, deps, intent)
          await authorizeHostMaintenance(tx, host, deps.held, enrollment)
          const reboot = checkReceipt(host, intent, await deps.command(host, originalOperation(intent, 'reboot')))
          if (reboot.phase !== 'reboot-intent') throw Error('HARDENING_KERNEL_REBOOT_UNCONFIRMED')
          intent.phase = 'waiting-boot'
          await persistProgress(tx, host, state, intent, reboot.plan, 'maintaining', null, 30_000)
        }, { maxWait: 3000, timeout: 90_000 })
        await deps.invalidate(hostId)
      } else if (pending.decision === 'verify' || pending.decision === 'complete') {
        await deps.invalidate(hostId)
        await prisma.$transaction(async tx => {
          const { host, state, intent } = await currentIntent(tx, hostId, deps, pending.intent.requestId, enrollment)
          const verifiedReport = await bootProof(tx, host, deps, intent, pending.receipt.bootId, enrollment)
          await authorizeHostMaintenance(tx, host, deps.held, enrollment)
          let activated: HostKernelReceipt
          try { activated = checkReceipt(host, intent, await deps.command(host, originalOperation(intent, 'verify'))) }
          catch (error) {
            if (code(error) !== 'HARDENING_KERNEL_BOOT_MISMATCH') throw error
            await emptyHost(tx, host, deps, intent)
            const rolled = checkReceipt(host, intent, await deps.command(host, originalOperation(intent, 'rollback')))
            if (rolled.phase !== 'rolled-back' || rolled.bootId === intent.bootId) throw Error('HARDENING_KERNEL_ROLLBACK_INCOMPLETE')
            intent.phase = 'aborted'; intent.rebootIssued = false; delete intent.error
            await persistProgress(tx, host, { ...state, environment: verifiedReport.preflight }, intent, rolled.plan, 'retry', 'HARDENING_KERNEL_INSTALLED_BOOT_REQUIRED', HOST_KERNEL_RETRY_DELAY)
            return
          }
          if (activated.phase !== 'activated' || activated.bootId !== pending.receipt.bootId) throw Error('HARDENING_KERNEL_BOOT_UNCONFIRMED')
          await emptyHost(tx, host, deps, intent)
          // Re-read the signed Agent heartbeat after root confirmation too.
          const agent = await tx.hostAgent.findUnique({ where: { hostId }, select: { enabled: true, lastSeenAt: true, lastReport: true } })
          if (!agent?.enabled || !agent.lastSeenAt || agent.lastSeenAt.getTime() > Date.now() + 1000 || Date.now() - agent.lastSeenAt.getTime() > 90_000 ||
            record(record(agent.lastReport).metrics).bootId !== activated.bootId || deps.held()) throw Error('HARDENING_KERNEL_RECONNECT_INCOMPLETE')
          intent.phase = 'verified'; delete intent.error
          await persistProgress(tx, host, { ...state, environment: verifiedReport.preflight }, intent, activated.plan, 'activated', null, 6 * 60 * 60_000)
        }, { maxWait: 3000, timeout: 120_000 })
      }
    } catch (error) {
      if (!original) throw error
      if (deps.held()) return
      await prisma.$transaction(async tx => {
        await tx.$executeRaw`SET LOCAL lock_timeout='2s'`
        await tx.$queryRaw`SELECT id FROM hosts WHERE id=${hostId} FOR NO KEY UPDATE`
        const host = await tx.host.findUnique({ where: { id: hostId }, include })
        if (!host || !enrollmentOwns(host, enrollment)) return
        const state = record(host.securityHardening), intent = readHostKernelIntent(state.maintenance)
        if (intent.requestId !== original!.requestId || intent.identityHash !== hardeningIdentityHash(host)) return
        const reason = code(error)
        intent.error = reason
        if (['HARDENING_IDENTITY_CHANGED', 'HARDENING_KERNEL_JOURNAL_CONFLICT', 'HARDENING_KERNEL_PLAN_CHANGED', 'HARDENING_KERNEL_CACHE_CHANGED'].includes(reason)) intent.phase = 'blocked'
        if (!intent.rebootIssued && ['HARDENING_KERNEL_STEP_TIMEOUT', 'HARDENING_KERNEL_PREPARE_FAILED'].includes(reason))
          intent.preparationRetries = Math.min(HOST_KERNEL_MAX_PREPARATION_RETRIES, (intent.preparationRetries || 0) + 1)
        let plan: HostKernelInspection | null = null
        try { if (record(state.kernel).plan) plan = readHostKernelInspection(record(state.kernel).plan) } catch { /* keep fixed error only */ }
        const waitingChannel = reason === HOST_KERNEL_CHANNEL_UPGRADE_REQUIRED
        await persistProgress(tx, host, state, intent, plan,
          waitingChannel ? 'waiting-channel' : 'retry', reason, waitingChannel ? HOST_KERNEL_CHANNEL_RECHECK_DELAY : 30_000)
      }, { maxWait: 3000, timeout: 8000 })
    }
  })
}
