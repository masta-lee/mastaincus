import { hostMaintenanceGatewayExchange } from './host-maintenance-channel.js'
import { gatewayCommand, type OnboardingGateway } from './onboarding-ssh.js'
import { OnboardingError } from '../lib/host-onboarding.js'
import type { HostSecurityTarget } from './host-security-inspection.js'
import { HOST_KERNEL_CHANNEL_UPGRADE_REQUIRED, HOST_KERNEL_MAINTENANCE_RECIPE, readHostKernelReceipt, type HostKernelAction,
  type HostKernelArchitecture, type HostKernelReceipt } from '../lib/host-kernel-maintenance-plan.js'

export type HostKernelOperation = {
  action: HostKernelAction
  requestId: string
  identityHash: string
  bootId: string
  prepareHash: string
  recipe: typeof HOST_KERNEL_MAINTENANCE_RECIPE
  architecture: HostKernelArchitecture
  expectedPlanHash: string | null
  customers: []
  deadline?: string
}
const uuid = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/
const hash = /^[a-f0-9]{64}$/
const zero = '0'.repeat(64)

export function hostKernelWireExpiry(operation: HostKernelOperation, now = Date.now()): number {
  if (!Number.isSafeInteger(now) || now <= 0) throw Error('HARDENING_REQUEST_EXPIRED')
  if (!['prepare', 'reboot'].includes(operation.action)) return now + 59_000
  const deadline = Date.parse(operation.deadline || '')
  if (!Number.isFinite(deadline) || deadline <= now) throw Error('HARDENING_REQUEST_EXPIRED')
  return Math.min(now + 59_000, deadline)
}

/** Deliberately select only fixed protocol fields from a larger DB intent. */
export function hostKernelWireOperation(operation: HostKernelOperation, nodeId: string, expiresAt: number) {
  if (!['inspect', 'prepare', 'status', 'reboot', 'rollback', 'verify'].includes(operation.action) ||
    operation.recipe !== HOST_KERNEL_MAINTENANCE_RECIPE || !['x86_64', 'aarch64'].includes(operation.architecture) ||
    ![nodeId, operation.requestId, operation.bootId].every(value => typeof value === 'string' && uuid.test(value)) ||
    ![operation.identityHash, operation.prepareHash].every(value => typeof value === 'string' && hash.test(value)) ||
    !Array.isArray(operation.customers) || operation.customers.length !== 0 ||
    !Number.isSafeInteger(expiresAt) || expiresAt <= 0 ||
    (operation.action === 'inspect'
      ? operation.expectedPlanHash !== null || operation.prepareHash !== zero
      : typeof operation.expectedPlanHash !== 'string' || !hash.test(operation.expectedPlanHash))) throw Error('HARDENING_KERNEL_REQUEST_UNKNOWN')
  return { action: operation.action, nodeId, requestId: operation.requestId, identityHash: operation.identityHash,
    bootId: operation.bootId, prepareHash: operation.prepareHash, recipe: operation.recipe,
    architecture: operation.architecture, expiresAt, customers: [], expectedPlanHash: operation.expectedPlanHash }
}

export const hostKernelMaintenanceChannelDependencies = { command: gatewayCommand,
  capable: async (gateway: OnboardingGateway) => (await import('./gateway-dns-channel.js')).gatewayMaintenanceChannelCurrent(gateway),
  exchange: hostMaintenanceGatewayExchange }

export async function hostKernelMaintenanceCommand(target: HostSecurityTarget, operation: HostKernelOperation,
  deps = hostKernelMaintenanceChannelDependencies): Promise<HostKernelReceipt> {
  const node = target.onboardingNode
  if (!node) throw Error('HARDENING_IDENTITY_MISSING')
  // Reject invalid intents before even the read-only gateway check. DNS v2 by
  // itself never authorizes this new wire schema or the fixed paired modules.
  hostKernelWireOperation(operation, node.id, hostKernelWireExpiry(operation))
  try {
    if (!await deps.capable(await deps.command())) throw Error(HOST_KERNEL_CHANNEL_UPGRADE_REQUIRED)
  } catch (error) {
    if (error instanceof OnboardingError && error.code === 'GATEWAY_MAINTENANCE_CAPABILITY_INVALID') throw Error(HOST_KERNEL_CHANNEL_UPGRADE_REQUIRED)
    throw error
  }
  const receipt = readHostKernelReceipt(await deps.exchange(target,
    hostKernelWireOperation(operation, node.id, hostKernelWireExpiry(operation))))
  if (receipt.nodeId !== node.id || receipt.requestId !== operation.requestId || receipt.identityHash !== operation.identityHash ||
    receipt.originalBootId !== operation.bootId || receipt.recipe !== operation.recipe || receipt.architecture !== operation.architecture ||
    (operation.action === 'inspect'
      ? receipt.phase !== 'inspected'
      : receipt.phase === 'inspected' || receipt.plan !== null && receipt.plan.planHash !== operation.expectedPlanHash) ||
    operation.prepareHash !== zero && receipt.prepareHash !== operation.prepareHash ||
    receipt.phase === 'absent' && (operation.action !== 'status' || operation.prepareHash !== zero)) throw Error('HARDENING_KERNEL_RESULT_UNKNOWN')
  return receipt
}
