import { prisma } from '../db/prisma.js'
import { lockCurrentHostAgent, type HostAgentRecord } from '../lib/host-agent-credentials.js'
import { recoveryHeld } from './platform-backup-core.js'
import { acceptHostProvisioningStatus } from '../lib/host-provisioning-tools.js'

export const LEGACY_APK_WORLD_CAPABILITY = 'legacy-apk-world-v1'
export const LEGACY_APK_WORLD_RECIPE = 'legacy-apk-world-owner-20261124-v1'
const legacyEnrollmentCutoff = Date.parse('2026-11-24T00:39:38Z')
const nodePattern = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/

export function legacyApkWorldEligible(host: { singleTenant: boolean; status: string; installPending: boolean; createdAt: Date }, node: { id: string; createdAt: Date; hostId: number | null } | null, hostId: number): boolean {
  return host.singleTenant && host.status === 'online' && !host.installPending && host.createdAt.getTime() <= legacyEnrollmentCutoff &&
    !!node && nodePattern.test(node.id) && node.hostId === hostId && node.createdAt.getTime() <= legacyEnrollmentCutoff
}

/** The signed heartbeat grants a short one-time adoption recipe only to hosts
 * enrolled before the owner's confirmation. No service, guest or package update
 * is permitted by this instruction; the original host node remains fixed. */
export async function legacyApkWorldPermit(agent: HostAgentRecord, capabilities: string[]) {
  if (recoveryHeld() || !capabilities.includes(LEGACY_APK_WORLD_CAPABILITY)) return null
  // A signed completed marker is advisory only and never makes stock
  // ready. Avoid another database transaction on every healthy heartbeat.
  const report = agent.lastReport && typeof agent.lastReport === 'object' && !Array.isArray(agent.lastReport) ? agent.lastReport as Record<string, unknown> : null
  const accepted = report && typeof report.signedAt === 'number' ? acceptHostProvisioningStatus(report.hostProvisioningStatus, report.signedAt, Date.now()) : null
  if ((accepted as { legacyWorld?: string } | null)?.legacyWorld === 'checked') return null
  return prisma.$transaction(async tx => {
    await lockCurrentHostAgent(tx, agent)
    const host = await tx.host.findUniqueOrThrow({ where: { id: agent.hostId }, select: { singleTenant: true, status: true, installPending: true, createdAt: true, onboardingNode: { select: { id: true, createdAt: true, hostId: true } } } })
    if (recoveryHeld() || !legacyApkWorldEligible(host, host.onboardingNode, agent.hostId)) return null
    return { node: host.onboardingNode!.id, recipe: LEGACY_APK_WORLD_RECIPE, expiresAt: new Date(Date.now() + 120_000).toISOString() }
  }, { maxWait: 2_000, timeout: 5_000 })
}
