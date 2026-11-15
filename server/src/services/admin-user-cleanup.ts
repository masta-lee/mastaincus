import { Prisma } from '@prisma/client'
import { prisma } from '../db/prisma.js'
import { lockAdministrativeUserMutation, authorizeUserWrite, revokeUserSessionsInTransaction, type WriteActor } from '../db/user-write-authorization.js'
import { advisoryTransactionLock, advisoryTransactionLockString, USER_BALANCE_LOCK_NAMESPACE, PAYMENT_SETTLEMENT_LOCK_NAMESPACE, INSTANCE_OPERATION_LOCK_NAMESPACE, tryAdvisoryTransactionLock } from '../db/advisory-locks.js'
import { requestInstanceDeletion, processInstanceDeletion, readDeletionIntent } from './instance-deletion.js'
import { getHostById } from '../db/hosts.js'
import { processHostRecoveryCheck } from './host-pool-cleanup.js'
import { verifyInstanceDeleted } from '../lib/incus/verify-instance-deleted.js'
import { getIncusClient } from '../lib/incus/incus-pool.js'
import { recoveryHeld } from './platform-backup-core.js'
import { closeUserSessions } from '../lib/terminal-proxy.js'
import { paymentTradeHash } from '../lib/deleted-payment-receipt.js'
import { randomUUID } from 'node:crypto'
import { cancelTransferForUserCleanup } from './transfer-cleanup.js'
import { failPoolProvision } from './pool-provisioning.js'
import { cancelInstanceTask } from '../db/instance-tasks.js'

type CleanupIntent = { version: 1; revision?: string; actor: WriteActor; requestedAt: string; nextAttemptAt?: string; stage: string; error?: string }
export class UserCleanupError extends Error {
  constructor(readonly code: string, readonly status = 409) { super(code) }
}
const intent = (value: unknown): CleanupIntent | null => {
  const v = value as CleanupIntent | null
  return v?.version === 1 && Number.isSafeInteger(v.actor?.id) && v.actor.id > 0 && typeof v.actor.sid === 'string' && v.actor.sid &&
    Number.isSafeInteger(v.actor.iat) && v.actor.iat! > 0 && Number.isFinite(Date.parse(v.requestedAt)) &&
    ['instances','transfers','billing'].includes(v.stage) ? v : null
}
const forbidden = async (tx: Prisma.TransactionClient, userId: number) => {
  // Customer account removal must never cascade-delete another person's host
  // or service. Infrastructure ownership needs an explicit transfer workflow.
  if (await tx.host.count({ where: { userId } }) || await tx.package.count({ where: { userId } }) ||
      await tx.hostingZone.count({ where: { ownerId: userId } }) || await tx.mailSubscription.count({ where: { userId } })) {
    throw new UserCleanupError('USER_CLEANUP_OWNED_SERVICES')
  }
}
export async function requestUserCleanup(userId: number, actor: WriteActor) {
  if (recoveryHeld()) throw new UserCleanupError('PLATFORM_RECOVERY_HELD')
  await prisma.$transaction(async tx => {
    const user = await lockAdministrativeUserMutation(tx, userId, actor, true)
    if (userId === actor.id) throw new UserCleanupError('CANNOT_DELETE_SELF', 400)
    if (user.role === 'admin') throw new UserCleanupError('CANNOT_DELETE_ADMIN', 400)
    await forbidden(tx, userId)
    const old = intent(user.deletionIntent)
    if (user.deletionIntent !== null && !old) throw new UserCleanupError('USER_CLEANUP_TARGET_CHANGED')
    const state: CleanupIntent = old ? { ...old, actor, revision: randomUUID(), error: undefined, nextAttemptAt: new Date().toISOString() } :
      { version: 1, revision: randomUUID(), actor, requestedAt: new Date().toISOString(), stage: 'instances' }
    await tx.user.update({ where: { id: userId }, data: { status: 'banned', banReason: '正在删除账户', deletionIntent: state as unknown as Prisma.InputJsonValue } })
    await revokeUserSessionsInTransaction(tx, userId)
    await tx.checkoutOrder.updateMany({ where: { userId, status: 'pending', paidAt: null }, data: { status: 'cancelled' } })
    await tx.checkoutReservation.deleteMany({ where: { order: { userId, status: 'cancelled', paidAt: null } } })
    await tx.log.create({ data: { userId: actor.id, module: 'user', action: 'user.delete_requested', result: 'pending',
      content: `管理员删除用户 #${userId}（${user.username}）已受理；先核实例彻底清理回池，再清余额、账单和账户` } })
  }, { timeout: 15000 })
  closeUserSessions(userId, 'User account deletion accepted')
  return { accepted: true, pending: true }
}
export async function userCleanupStatus(userId: number) {
  const user = await prisma.user.findUnique({ where: { id: userId }, select: { deletionIntent: true } })
  if (!user) return { status: 'done', stage: 'done' }
  const state = intent(user.deletionIntent)
  if (user.deletionIntent && !state) return {status:'pending',stage:'instances',error:'USER_CLEANUP_TARGET_CHANGED'}
  return { status: state ? 'pending' : 'none', stage: state?.stage, error: state?.error,
    nextAttemptAt: state?.nextAttemptAt, remainingInstances: await prisma.instance.count({ where: { userId, OR: [{status:{not:'deleted'}},{deletionBillingPending:true},{provisioningCleanupPending:true}] } }) }
}
const active = new Set<number>()
async function prepareInstanceCleanup(instanceId:number, userId:number, actor:WriteActor) {
  const queued=await prisma.instanceTask.findMany({where:{instanceId,status:'PENDING'},select:{id:true}})
  for(const task of queued)await cancelInstanceTask(task.id)
  await prisma.$transaction(async tx=>{
    await tx.$executeRaw`SET LOCAL lock_timeout = '5s'`
    if(!await tryAdvisoryTransactionLock(tx,INSTANCE_OPERATION_LOCK_NAMESPACE,instanceId))throw new UserCleanupError('USER_CLEANUP_INSTANCE_PENDING')
    await tx.$queryRaw`SELECT id FROM instances WHERE id=${instanceId} FOR UPDATE`
    const row=await tx.instance.findUniqueOrThrow({where:{id:instanceId}})
    const user=await lockAdministrativeUserMutation(tx,userId,actor,true)
    if(row.userId!==userId || !user.deletionIntent || recoveryHeld())throw new UserCleanupError('USER_CLEANUP_TARGET_CHANGED')
    if(await tx.instanceTask.count({where:{instanceId,status:{in:['PENDING','PROCESSING']}}}) ||
       await tx.restoreTask.count({where:{instanceId,status:{in:['PENDING','PROCESSING']}}}) ||
       await tx.backupUploadTask.count({where:{instanceId,status:{in:['PENDING','PROCESSING']}}}))throw new UserCleanupError('USER_CLEANUP_INSTANCE_PENDING')
    // Waiting for this shared lock proves no snapshot/proxy SQL attempt still
    // owns the instance. Preserve its real remote resources for verified delete.
    await tx.snapshotPolicy.updateMany({where:{instanceId},data:{enabled:false}})
    await tx.backupPolicy.updateMany({where:{instanceId},data:{enabled:false}})
    await tx.autoSnapshotOperation.updateMany({where:{instanceId,state:{in:['pending','applying','retry','blocked']}},
      data:{state:'cancelled',error:'管理员删除账户，由完整实例删除继续清理',nextRetryAt:null,completedAt:new Date()}})
    await tx.proxySiteOperation.updateMany({where:{instanceId,authority:{not:'lifecycle'},state:{in:['pending','applying','retry','blocked']}},
      data:{state:'superseded',error:'管理员删除账户，由实例删除重新核验并清理站点',nextRetryAt:null,completedAt:new Date()}})
  },{timeout:15000})
}
export async function processUserCleanup(userId: number): Promise<void> {
  if (active.has(userId) || recoveryHeld()) return
  active.add(userId)
  let state: CleanupIntent | null = null
  let step = 'transfers'
  try {
    const user = await prisma.user.findUnique({ where: { id: userId } })
    state = intent(user?.deletionIntent)
    if (!user || !state || state.nextAttemptAt && Date.parse(state.nextAttemptAt) > Date.now()) return
    const actor = state.actor
    await prisma.$transaction(async tx => {
      if (!await authorizeUserWrite(tx, actor.id, actor) ||
          (await tx.user.findUnique({ where: { id: actor.id } }))?.role !== 'admin') throw new UserCleanupError('USER_CLEANUP_AUTHORITY_CHANGED')
    })
    const transfers = await prisma.instanceTransfer.findMany({ where: { OR: [{fromUserId:userId},{toUserId:userId}], status:{in:['pending','processing']} }, select:{id:true} })
    let pending: unknown
    for (const transfer of transfers) try { await cancelTransferForUserCleanup(transfer.id, userId, actor) } catch(error) { pending ??= error }
    // The existing checkout worker owns committed payments and their refunds.
    // A stopped account cannot materialize new instances; it settles normally.
    const instances = await prisma.instance.findMany({ where: { userId }, orderBy: { id: 'asc' } })
    step = 'instances'
    for (const row of instances) {
      if (recoveryHeld()) return
      try {
      await prepareInstanceCleanup(row.id,userId,actor)
      if (row.purchaseBatchId && (row.status === 'creating' || row.provisioningCleanupPending)) {
        await failPoolProvision(row.id, await getHostById(row.hostId), '管理员删除账户，取消原开通任务')
        throw new UserCleanupError('USER_CLEANUP_PROVISIONING_PENDING')
      }
      const previousDeletion = readDeletionIntent(row.deletionIntent)
      if (previousDeletion && previousDeletion.status !== 'done' &&
          (previousDeletion.actor.id !== actor.id || previousDeletion.actor.sid !== actor.sid || previousDeletion.actor.iat !== actor.iat)) {
        // An administrator may renew the account deletion authorization after
        // logout. Preserve the exact remote UUID and all original cleanup steps.
        await prisma.instance.updateMany({where:{id:row.id,deletionIntent:{equals:row.deletionIntent as Prisma.InputJsonValue}},
          data:{deletionIntent:{...previousDeletion,actor,mode:'admin',nextAttemptAt:new Date().toISOString()} as unknown as Prisma.InputJsonValue}})
      }
      if (row.status !== 'deleted' || !row.deletionIntent) await requestInstanceDeletion(row, state.actor, { mode: 'admin', refund: false, deferRemote: true, accountCleanup:true })
      const current = await prisma.instance.findUniqueOrThrow({ where: { id: row.id } })
      if (current.deletionBillingPending) await processInstanceDeletion(row.id)
      const checked = await prisma.instance.findUniqueOrThrow({ where: { id: row.id } })
      if (checked.deletionBillingPending || checked.provisioningCleanupPending || checked.status !== 'deleted') throw new UserCleanupError('USER_CLEANUP_INSTANCE_PENDING')
      if (!readDeletionIntent(checked.deletionIntent) && row.status !== 'deleted') throw new UserCleanupError('USER_CLEANUP_INSTANCE_PENDING')
      const host = await getHostById(row.hostId)
      if (host) {
        await verifyInstanceDeleted(await getIncusClient(host, prisma, 5000), row.incusId)
        await processHostRecoveryCheck(row.hostId)
        if ((await prisma.host.findUniqueOrThrow({ where: { id: row.hostId } })).poolFaulted) throw new UserCleanupError('USER_CLEANUP_POOL_PENDING')
      }
      } catch (error) { pending ??= error }
    }
    if (pending) throw pending
    step = 'billing'
    await finalizeUserCleanup(userId, state)
  } catch (error) {
    if (state) {
      const code = error instanceof Error && /^USER_CLEANUP_[A-Z_]+$/.test(error.message) ? error.message : 'USER_CLEANUP_RETRY'
      const retry = { ...state, stage: step, error: code, nextAttemptAt: new Date(Date.now() + 30000).toISOString() }
      await prisma.user.updateMany({ where: { id: userId, deletionIntent: { equals: state as unknown as Prisma.InputJsonValue } }, data: { deletionIntent: retry as unknown as Prisma.InputJsonValue } })
    }
  } finally { active.delete(userId) }
}
async function finalizeUserCleanup(userId: number, state: CleanupIntent) {
  await prisma.$transaction(async tx => {
    // Payment evidence locks serialize tombstones with actual payment callbacks.
    const receipts = await tx.checkoutReceipt.findMany({ where: { payment: { order: { userId } } }, select: { providerId: true, tradeNo: true } })
    const recharges = await tx.rechargeRecord.findMany({ where: { userId }, select: { providerId: true, tradeNo: true } })
    const lateRecharges = await tx.rechargeLatePayment.findMany({where:{recharge:{userId}},select:{providerId:true,tradeNo:true}})
    const payments = [...receipts, ...lateRecharges, ...recharges.filter((r): r is {providerId:number;tradeNo:string} => !!r.tradeNo)]
      .sort((a,b)=>`${a.providerId}:${a.tradeNo}`.localeCompare(`${b.providerId}:${b.tradeNo}`))
    for (const receipt of payments) await advisoryTransactionLockString(tx, PAYMENT_SETTLEMENT_LOCK_NAMESPACE, `${receipt.providerId}:${receipt.tradeNo.trim()}`)
    await advisoryTransactionLock(tx, USER_BALANCE_LOCK_NAMESPACE, userId)
    const user = await lockAdministrativeUserMutation(tx, userId, state.actor, true)
    const currentIntent = intent(user.deletionIntent)
    if (user.role === 'admin' || userId === state.actor.id || !currentIntent || currentIntent.revision !== state.revision ||
        currentIntent.actor.id !== state.actor.id || currentIntent.actor.sid !== state.actor.sid || currentIntent.actor.iat !== state.actor.iat ||
        user.status !== 'banned' || recoveryHeld()) throw new UserCleanupError('USER_CLEANUP_TARGET_CHANGED')
    await forbidden(tx, userId)
    const latestReceipts = await tx.checkoutReceipt.findMany({where:{payment:{order:{userId}}},select:{providerId:true,tradeNo:true}})
    const latestRecharges = await tx.rechargeRecord.findMany({where:{userId},select:{providerId:true,tradeNo:true}})
    const latestLateRecharges = await tx.rechargeLatePayment.findMany({where:{recharge:{userId}},select:{providerId:true,tradeNo:true}})
    const latestTrades = [...latestReceipts,...latestLateRecharges,...latestRecharges.filter((r):r is {providerId:number;tradeNo:string}=>!!r.tradeNo)]
    const tradeKeys = new Set(payments.map(r=>`${r.providerId}:${r.tradeNo.trim()}`))
    if(latestTrades.some(r=>!tradeKeys.has(`${r.providerId}:${r.tradeNo.trim()}`))) throw new UserCleanupError('USER_CLEANUP_PAYMENT_PENDING')
    if (await tx.instance.count({ where: { userId, OR: [{ status: { not: 'deleted' } }, { deletionBillingPending: true }, { provisioningCleanupPending: true }] } })) throw new UserCleanupError('USER_CLEANUP_INSTANCE_PENDING')
    const orderIds = (await tx.checkoutOrder.findMany({ where: { userId }, select: { id: true, status: true } }))
    if (orderIds.some(o=>['paid','fulfilling','refund_pending'].includes(o.status)) ||
      await tx.checkoutRefund.count({ where: { orderId: { in: orderIds.map(o=>o.id) }, status: { notIn: ['refunded','rejected','resolved'] } } }) ||
      await tx.rechargeRecord.count({ where: { userId, status: 'paid' } }) ||
      await tx.instanceTransfer.count({ where: { OR: [{fromUserId:userId},{toUserId:userId}],status:{in:['pending','processing']} } })) throw new UserCleanupError('USER_CLEANUP_PAYMENT_PENDING')
    for (const receipt of payments) await tx.deletedPaymentReceipt.upsert({ where: { providerId_tradeHash: { providerId: receipt.providerId, tradeHash: paymentTradeHash(receipt.tradeNo) } },
      create: { providerId: receipt.providerId, tradeHash: paymentTradeHash(receipt.tradeNo) }, update: {} })
    await tx.registrationReceipt.updateMany({ where: { userId }, data: { userId: null } })
    // External receipt tombstones contain only hashed trade IDs. Clear user
    // bill/receipt rows while retaining cross-channel duplicate protection.
    await tx.checkoutRefund.updateMany({ where: { orderId:{notIn:orderIds.map(o=>o.id)}, instance:{userId} }, data:{instanceId:null,billingRecordId:null} })
    await tx.checkoutRefund.updateMany({ where: { orderId:{notIn:orderIds.map(o=>o.id)}, billingRecord:{userId} }, data:{billingRecordId:null} })
    await tx.checkoutRefund.deleteMany({ where: { orderId:{in:orderIds.map(o=>o.id)} } })
    await tx.checkoutReceipt.deleteMany({ where: { payment: { order: { userId } } } })
    await tx.checkoutPayment.deleteMany({ where: { orderId: { in: orderIds.map(o=>o.id) } } })
    await tx.checkoutReservation.deleteMany({ where: { orderId: { in: orderIds.map(o=>o.id) } } })
    await tx.checkoutOrder.deleteMany({ where: { userId } })
    if (await tx.instanceTransfer.count({ where: { OR: [{fromUserId:userId},{toUserId:userId}],status:'processing' } })) throw new UserCleanupError('USER_CLEANUP_INSTANCE_PENDING')
    await tx.instanceTransfer.deleteMany({ where: { OR: [{fromUserId:userId},{toUserId:userId}] } })
    await tx.inviteCode.updateMany({ where: { usedBy: userId }, data: { usedBy: null } })
    await tx.inviteCode.deleteMany({ where: { createdBy: userId } })
    await tx.poolOrder.deleteMany({ where: { userId } })
    // Transferred instances can have another payer's bills. Keep only a deleted
    // administrative history row for those references; no live guest survives.
    const historical = await tx.instance.findMany({where:{userId,OR:[
      {billingRecords:{some:{userId:{not:userId}}}},
      {checkoutRefunds:{some:{order:{userId:{not:userId}}}}}
    ]},select:{id:true}})
    const historicalIds=historical.map(row=>row.id)
    await tx.instance.updateMany({where:{id:{in:historicalIds}},data:{userId:state.actor.id,name:'已删除账户的实例记录',rootPassword:null,autoRenew:false}})
    await tx.instance.deleteMany({ where: { userId } })
    await tx.instanceBillingRecord.deleteMany({ where: { userId } })
    await tx.platformRecoveryReconciliation.deleteMany({ where: { userId } })
    await tx.platformRecoveryReconciliation.updateMany({ where: { actorId:userId }, data:{actorId:state.actor.id} })
    await tx.oAuthClientApp.deleteMany({ where: { createdByUserId: userId } })
    await tx.systemUpdateTask.updateMany({where:{startedByUserId:userId},data:{startedByUserId:state.actor.id}})
    await tx.balanceAdjustmentRequest.updateMany({ where: { requestedByUserId: userId }, data:{requestedByUserId:state.actor.id} })
    await tx.orderOperationCase.updateMany({ where: { createdByUserId: userId }, data:{createdByUserId:state.actor.id} })
    await tx.giftCard.deleteMany({ where: { ownerId: userId } })
    await tx.giftCard.updateMany({ where: { createdById: userId }, data: { createdById: null } })
    await tx.giftCard.updateMany({ where: { usedById: userId }, data: { usedById: null } })
    if(user.email) await tx.emailVerificationCode.deleteMany({where:{email:{equals:user.email,mode:'insensitive'}}})
    await tx.user.update({ where: { id: userId }, data: { balance: 0, hostingBalance: 0, affBalance: 0 } })
    await tx.log.create({ data: { userId: state.actor.id, module: 'user', action: 'user.delete', result: 'success',
      content: `用户 #${userId}（${user.username}）已删除；实例彻底清理、宿主回池、余额清零及全部账户账单清理完成` } })
    await tx.user.delete({ where: { id: userId } })
  }, { timeout: 20000 })
}
let timer: ReturnType<typeof setTimeout> | undefined, stopped = true, work: Promise<void> | undefined, cursor=0
export function startUserCleanupWorker() {
  if (!stopped) return
  stopped = false
  const run = async () => {
    const users = await prisma.user.findMany({ where: { id:{gt:cursor},deletionIntent: { not: Prisma.DbNull } }, orderBy: { id: 'asc' }, take: 20, select: { id: true } })
    if(!users.length){cursor=0;return}
    for (const user of users) { if (stopped) return;cursor=user.id;try{await processUserCleanup(user.id)}catch{console.warn(`[UserCleanup] 用户 #${user.id} 任务继续保留，后续自动重试`)} }
  }
  const tick = () => { work = run().catch(()=>console.warn('[UserCleanup] 清理未完成，将自动续接')).finally(()=>{work=undefined;if(!stopped){timer=setTimeout(tick,30000);timer.unref()}}) }
  timer = setTimeout(tick,5000);timer.unref()
}
export async function stopUserCleanupWorker() { stopped=true;clearTimeout(timer);await work }
