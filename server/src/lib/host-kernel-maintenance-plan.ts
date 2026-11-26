import { readHostMaintenanceIntent, type HostMaintenanceIntent } from './host-maintenance-plan.js'

export const HOST_KERNEL_MAINTENANCE_RECIPE = 'alpine-kernel-patch-v1' as const
export const HOST_KERNEL_STATE_REVISION = 'host-kernel-v1' as const
export const HOST_KERNEL_PREPARATION_WINDOW = 20 * 60_000
export const HOST_KERNEL_RETRY_DELAY = 120_000
export const HOST_KERNEL_MAX_PREPARATION_RETRIES = 2
export const HOST_KERNEL_CHANNEL_UPGRADE_REQUIRED = 'HARDENING_KERNEL_CHANNEL_UPGRADE_REQUIRED'
export const HOST_KERNEL_CHANNEL_RECHECK_DELAY = 30 * 60_000

export type HostKernelArchitecture = 'x86_64' | 'aarch64'
export type HostKernelFlavor = 'linux-virt' | 'linux-lts'
export type HostKernelBootloader = 'grub' | 'extlinux'
export type HostKernelAction = 'inspect' | 'prepare' | 'status' | 'reboot' | 'rollback' | 'verify'
export type HostKernelPhase = 'inspected' | 'absent' | 'prepared-artifacts' | 'packages-installed' |
  'boot-staged' | 'prepared' | 'reboot-intent' | 'activated' | 'rolled-back'
export type HostKernelInspection = {
  status: 'available' | 'up-to-date' | 'blocked'
  branch: string | null
  flavor: HostKernelFlavor | null
  bootloader: HostKernelBootloader | null
  runningRelease: string | null
  installedVersion: string | null
  candidateVersion: string | null
  candidateRelease: string | null
  planHash: string | null
  reason: string | null
}
export type HostKernelReceipt = {
  version: 1
  nodeId: string
  requestId: string
  identityHash: string
  originalBootId: string
  bootId: string
  architecture: HostKernelArchitecture
  recipe: typeof HOST_KERNEL_MAINTENANCE_RECIPE
  prepareHash: string
  phase: HostKernelPhase
  plan: HostKernelInspection | null
}
export type HostKernelIntent = Omit<HostMaintenanceIntent, 'recipe' | 'customers'> & {
  recipe: typeof HOST_KERNEL_MAINTENANCE_RECIPE
  customers: []
  expectedPlanHash: string
}
export type HostKernelState = {
  revision: typeof HOST_KERNEL_STATE_REVISION
  identityHash: string
  status: 'available' | 'up-to-date' | 'waiting-empty' | 'waiting-native' | 'waiting-channel' | 'maintaining' | 'activated' | 'retry' | 'blocked'
  checkedAt: string
  nextCheckAt: string
  plan: HostKernelInspection | null
  reason: string | null
}

const hash = /^[a-f0-9]{64}$/
const uuid = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/
const version = /^([1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-r(0|[1-9][0-9]*)$/
const release = /^([1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-(0|[1-9][0-9]*)-(virt|lts)$/
const code = /^HARDENING_[A-Z_]{1,90}$/
const object = (value: unknown): Record<string, unknown> => value && typeof value === 'object' && !Array.isArray(value)
  ? value as Record<string, unknown> : {}
const fail = (): never => { throw new Error('HARDENING_KERNEL_RESULT_UNKNOWN') }
const keys = (value: Record<string, unknown>, required: readonly string[]) =>
  Object.keys(value).sort().join(',') === [...required].sort().join(',')

export function hostKernelVersionRelease(value: string, flavor: HostKernelFlavor): string {
  const match = value.length <= 64 ? version.exec(value) : null
  if (!match || !['linux-virt', 'linux-lts'].includes(flavor)) return fail()
  return match[1] + '.' + match[2] + '.' + match[3] + '-' + match[4] + '-' + flavor.slice(6)
}

export function hostKernelReleaseVersion(value: string, flavor: HostKernelFlavor): string {
  const match = value.length <= 64 ? release.exec(value) : null
  if (!match || !['linux-virt', 'linux-lts'].includes(flavor) || match[5] !== flavor.slice(6)) return fail()
  return match[1] + '.' + match[2] + '.' + match[3] + '-r' + match[4]
}

export function sameHostKernelPatchSeries(before: string, expected: string): boolean {
  const a = before.length <= 64 ? version.exec(before) : null
  const b = expected.length <= 64 ? version.exec(expected) : null
  return !!a && !!b && a[1] === b[1] && a[2] === b[2] &&
    (BigInt(b[3]) > BigInt(a[3]) || b[3] === a[3] && BigInt(b[4]) > BigInt(a[4]))
}

export function readHostKernelInspection(value: unknown): HostKernelInspection {
  const row = object(value)
  if (!keys(row, ['status', 'branch', 'flavor', 'bootloader', 'runningRelease', 'installedVersion',
    'candidateVersion', 'candidateRelease', 'planHash', 'reason']) ||
    typeof row.status !== 'string' || !['available', 'up-to-date', 'blocked'].includes(row.status) ||
    row.branch !== null && (typeof row.branch !== 'string' || !['3.22', '3.23', '3.24'].includes(row.branch)) ||
    row.flavor !== null && (typeof row.flavor !== 'string' || !['linux-virt', 'linux-lts'].includes(row.flavor)) ||
    row.bootloader !== null && (typeof row.bootloader !== 'string' || !['grub', 'extlinux'].includes(row.bootloader)) ||
    row.runningRelease !== null && (typeof row.runningRelease !== 'string' || row.runningRelease.length > 64 || !release.test(row.runningRelease)) ||
    row.installedVersion !== null && (typeof row.installedVersion !== 'string' || row.installedVersion.length > 64 || !version.test(row.installedVersion)) ||
    row.candidateVersion !== null && (typeof row.candidateVersion !== 'string' || row.candidateVersion.length > 64 || !version.test(row.candidateVersion)) ||
    row.candidateRelease !== null && (typeof row.candidateRelease !== 'string' || row.candidateRelease.length > 64 || !release.test(row.candidateRelease)) ||
    row.planHash !== null && (typeof row.planHash !== 'string' || !hash.test(row.planHash)) ||
    row.reason !== null && (typeof row.reason !== 'string' || !code.test(row.reason))) return fail()
  if (row.status !== 'blocked' && (!row.branch || !row.flavor || !row.bootloader || !row.runningRelease || !row.installedVersion || row.reason !== null)) return fail()
  if (row.status === 'available' && (!row.candidateVersion || !row.candidateRelease || !row.planHash ||
    row.candidateRelease !== hostKernelVersionRelease(String(row.candidateVersion), row.flavor as HostKernelFlavor) ||
    (row.runningRelease === hostKernelVersionRelease(String(row.installedVersion), row.flavor as HostKernelFlavor)
      ? !sameHostKernelPatchSeries(String(row.installedVersion), String(row.candidateVersion))
      : row.candidateVersion !== row.installedVersion || !sameHostKernelPatchSeries(
        hostKernelReleaseVersion(String(row.runningRelease), row.flavor as HostKernelFlavor), String(row.installedVersion))))) return fail()
  if (row.status === 'up-to-date' && (row.candidateVersion !== null || row.candidateRelease !== null || row.planHash !== null ||
    row.runningRelease !== hostKernelVersionRelease(String(row.installedVersion), row.flavor as HostKernelFlavor))) return fail()
  if (row.status === 'blocked' && (!row.reason || row.planHash !== null || row.candidateVersion !== null || row.candidateRelease !== null)) return fail()
  return { ...row } as HostKernelInspection
}

export function readHostKernelReceipt(value: unknown): HostKernelReceipt {
  const row = object(value)
  if (!keys(row, ['version', 'nodeId', 'requestId', 'identityHash', 'originalBootId', 'bootId', 'architecture',
    'recipe', 'prepareHash', 'phase', 'plan']) || row.version !== 1 ||
    row.recipe !== HOST_KERNEL_MAINTENANCE_RECIPE ||
    typeof row.architecture !== 'string' || !['x86_64', 'aarch64'].includes(row.architecture) ||
    ![row.nodeId, row.requestId, row.originalBootId, row.bootId].every(value => typeof value === 'string' && uuid.test(value)) ||
    ![row.identityHash, row.prepareHash].every(value => typeof value === 'string' && hash.test(value)) ||
    typeof row.phase !== 'string' || !['inspected', 'absent', 'prepared-artifacts', 'packages-installed', 'boot-staged', 'prepared', 'reboot-intent',
      'activated', 'rolled-back'].includes(row.phase)) return fail()
  const plan = row.plan === null ? null : readHostKernelInspection(row.plan)
  const preparation = ['prepared-artifacts', 'packages-installed', 'boot-staged']
  if (row.phase === 'absent' && (plan !== null || row.prepareHash !== '0'.repeat(64)) ||
    row.phase === 'inspected' && (!plan || row.prepareHash !== '0'.repeat(64)) ||
    preparation.includes(String(row.phase)) && (!plan || plan.status !== 'available' || row.prepareHash !== '0'.repeat(64)) ||
    ['prepared', 'reboot-intent', 'activated'].includes(String(row.phase)) && (!plan || plan.status !== 'available' || row.prepareHash === '0'.repeat(64)) ||
    row.phase === 'rolled-back' && (!plan || plan.status !== 'available') ||
    row.phase === 'activated' && row.bootId === row.originalBootId) return fail()
  return { ...row, plan } as HostKernelReceipt
}

export function readHostKernelIntent(value: unknown): HostKernelIntent {
  const row = object(value)
  const allowed = new Set(['revision', 'requestId', 'identityHash', 'bootId', 'prepareHash', 'recipe', 'architecture', 'phase',
    'rebootIssued', 'startedAt', 'deadline', 'customers', 'expectedPlanHash', 'error', 'history', 'preparationRetries'])
  if (Object.keys(row).some(key => !allowed.has(key)) || row.recipe !== HOST_KERNEL_MAINTENANCE_RECIPE ||
    !Array.isArray(row.customers) || row.customers.length !== 0 || typeof row.expectedPlanHash !== 'string' || !hash.test(row.expectedPlanHash) ||
    ![row.identityHash, row.prepareHash].every(value => typeof value === 'string' && hash.test(value)) ||
    typeof row.architecture !== 'string' || typeof row.phase !== 'string' ||
    row.error !== undefined && (typeof row.error !== 'string' || !code.test(row.error)) ||
    row.history !== undefined && (!Array.isArray(row.history) || row.history.length > 16 || row.history.some(value => {
      const event = object(value)
      return !keys(event, event.reason === undefined ? ['phase', 'at'] : ['phase', 'at', 'reason']) ||
        typeof event.phase !== 'string' || !['prepared', 'reboot-intent', 'waiting-boot', 'restoring', 'verified', 'blocked', 'aborted'].includes(event.phase) ||
        typeof event.at !== 'string' || !Number.isFinite(Date.parse(event.at)) ||
        event.reason !== undefined && (typeof event.reason !== 'string' || !code.test(event.reason))
    }))) return fail()
  const intent = readHostMaintenanceIntent(row)
  return { ...intent, recipe: HOST_KERNEL_MAINTENANCE_RECIPE, customers: [], expectedPlanHash: row.expectedPlanHash }
}

/** Empty until the exact branch/flavor/bootloader and both native architectures
 * have passed real VM boot, rollback and a subsequent patch transaction. */
export const NATIVE_VALIDATED_HOST_KERNEL_PAIRS: ReadonlyArray<string> = Object.freeze([])
export function automaticHostKernelPatchAllowed(plan: HostKernelInspection, architecture: HostKernelArchitecture): boolean {
  return plan.status === 'available' && NATIVE_VALIDATED_HOST_KERNEL_PAIRS.includes(
    [HOST_KERNEL_MAINTENANCE_RECIPE, plan.branch, plan.flavor, plan.bootloader, architecture].join(':'))
}

export function nextHostKernelAction(intent: HostKernelIntent, receipt: HostKernelReceipt, now = Date.now(), held = false):
  'prepare' | 'reboot' | 'verify' | 'rollback' | 'wait' | 'blocked' | 'abort' | 'complete' {
  if (held) return 'wait'
  if (receipt.recipe !== intent.recipe || receipt.identityHash !== intent.identityHash ||
    receipt.requestId !== intent.requestId || receipt.originalBootId !== intent.bootId || receipt.architecture !== intent.architecture ||
    receipt.plan !== null && receipt.plan.planHash !== intent.expectedPlanHash ||
    intent.prepareHash !== '0'.repeat(64) && receipt.prepareHash !== intent.prepareHash) return 'blocked'
  if (receipt.phase === 'activated') return intent.rebootIssued ? 'complete' : 'blocked'
  if (receipt.phase === 'rolled-back') return intent.rebootIssued && receipt.bootId === intent.bootId ? 'blocked' : 'abort'
  if (receipt.phase === 'reboot-intent') return !intent.rebootIssued ? 'blocked' : receipt.bootId === intent.bootId ? 'wait' : 'verify'
  if (receipt.bootId !== intent.bootId) return 'blocked'
  if (receipt.phase === 'absent') return now >= Date.parse(intent.deadline) ? 'abort' : 'prepare'
  if (now >= Date.parse(intent.deadline)) return 'rollback'
  // A committed controller intent with a still-prepared root journal proves
  // the remote single-use barrier was not crossed. Resend only this request.
  if (intent.rebootIssued) return intent.phase === 'reboot-intent' && receipt.phase === 'prepared' ? 'reboot' : 'blocked'
  if (receipt.phase === 'prepared') return 'reboot'
  if (['prepared-artifacts', 'packages-installed', 'boot-staged'].includes(receipt.phase)) return 'prepare'
  return 'blocked'
}
