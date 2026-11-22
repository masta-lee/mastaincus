import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtemp, rm, readFile, writeFile, unlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Pool } from 'pg'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const url = new URL(process.env.DATABASE_URL || '')
assert.equal(url.hostname, '127.0.0.1')
assert.ok(url.pathname.endsWith('_pool_test'))
process.env.NODE_ENV = 'test'
process.env.ENCRYPTION_KEY = 'financial-integrity-isolated-test-key'
const directory = await mkdtemp(join(tmpdir(), 'finance-integrity-'))
process.env.FINANCIAL_INTEGRITY_STATE_DIR = directory
const { prisma, initializeFinancialDatabaseIntegrity, closePrismaDatabase } = await import('../src/db/prisma.js')
const { disableFinancialIntegrityForShutdown, verifyFinancialDatabaseSeals, financialIntegrityStatePath, legacyFinancialBaseline, sealRecoveryOperatorWallet, prepareRecoveryCheckoutStatuses, changeRecoveryOperatorRole } = await import('../src/lib/financial-integrity.js')
const { changeBalanceInTransaction } = await import('../src/db/balance.js')
const raw = new Pool({ connectionString: url.href })
const tag = 'finance-seal-' + randomUUID()
let userId = 0
let hostId = 0, providerId = 0, instanceId = 0
const additionalUsers: number[] = []
try {
  const user = await prisma.user.create({ data: { username: tag, passwordHash: 'unused-test-password', balance: 100 } })
  userId = user.id
  await initializeFinancialDatabaseIntegrity()
  const read = () => prisma.user.findUniqueOrThrow({ where: { id: userId }, select: { balance: true } })
  assert.equal((await read()).balance.toFixed(2), '100.00')
  await raw.query("UPDATE users SET role='admin' WHERE id=$1",[userId])
  await assert.rejects(read(), /FINANCIAL_INTEGRITY_INVALID/)
  await raw.query("UPDATE users SET role='user' WHERE id=$1",[userId])
  const move = (amount: number) => prisma.$transaction(tx => changeBalanceInTransaction(tx, { userId, type: 'admin_adjust', amount, remark: 'isolated seal test' }))
  await move(-10)
  assert.equal((await read()).balance.toFixed(2), '90.00')
  const log = await prisma.balanceLog.findFirstOrThrow({ where: { userId }, orderBy: { id: 'desc' } })
  await raw.query('UPDATE users SET balance=999 WHERE id=$1', [userId])
  await assert.rejects(read(), /FINANCIAL_INTEGRITY_INVALID/)
  await assert.rejects(move(-1), /FINANCIAL_INTEGRITY_INVALID/)
  await raw.query('UPDATE users SET balance=90 WHERE id=$1', [userId])
  assert.equal((await read()).balance.toFixed(2), '90.00')
  await raw.query('UPDATE balance_logs SET amount=-1 WHERE id=$1', [log.id])
  await assert.rejects(read(), /FINANCIAL_INTEGRITY_INVALID/)
  await assert.rejects(prisma.balanceLog.findUnique({ where: { id: log.id } }), /FINANCIAL_INTEGRITY_INVALID/)
  await raw.query('UPDATE balance_logs SET amount=-10 WHERE id=$1', [log.id])
  await assert.rejects(prisma.balanceLog.update({ where: { id: log.id }, data: { amount: -1 } }), /FINANCIAL_INTEGRITY_INVALID/)
  await assert.rejects(prisma.$transaction(tx => tx.user.update({ where: { id: userId }, data: { balance: { increment: 5 } } })), /FINANCIAL_INTEGRITY_INVALID/)
  assert.equal((await read()).balance.toFixed(2), '90.00', 'missing ledger rolls back the wallet')
  await prisma.$transaction(async tx => {
    await moveSafe(tx, -1)
    await moveSafe(tx, 2)
  })
  assert.equal((await read()).balance.toFixed(2), '91.00')
  await prisma.$transaction(async tx => {
    const changed = await tx.user.update({ where: { id: userId }, data: { balance: { increment: 1 } }, select: { balance: true } })
    await tx.balanceLog.create({ data: { userId, type: 'gift', amount: 1, balanceBefore: changed.balance.minus(1), balanceAfter: changed.balance, remark: 'legacy writer' } })
  })
  assert.equal((await read()).balance.toFixed(2), '92.00')
  await assert.rejects(async () => prisma.$transaction([
    prisma.user.update({ where: { id: userId }, data: { balance: 999 } })
  ]), /(?:FINANCIAL|AUTHENTICATION)_INTEGRITY_INVALID/)
  assert.equal((await read()).balance.toFixed(2), '92.00', 'array transactions do not start standalone financial writes')
  hostId = (await prisma.host.create({ data: { userId, name: tag, url: 'https://127.0.0.1:1' } })).id
  providerId = (await prisma.paymentProvider.create({ data: { name: tag, type: 'manual', config: {} } })).id
  await raw.query('UPDATE payment_providers SET config=$2::jsonb WHERE id=$1', [providerId, JSON.stringify({ replaced: true })])
  await assert.rejects(prisma.paymentProvider.findUnique({ where: { id: providerId } }), /FINANCIAL_INTEGRITY_INVALID/)
  await raw.query("UPDATE payment_providers SET config='{}'::jsonb WHERE id=$1", [providerId])
  instanceId = (await prisma.instance.create({ data: { userId, hostId, name: tag, incusId: tag, image: 'fixture', cpu: 1, memory: 64, disk: 1024,
    billingPrice: 10, renewalPrice: 12, billingCycle: 1, expiresAt: new Date(Date.now() + 86400000) } })).id
  await raw.query('UPDATE instances SET renewal_price=1 WHERE id=$1', [instanceId])
  await assert.rejects(prisma.instance.findUnique({ where: { id: instanceId }, select: { renewalPrice: true } }), /FINANCIAL_INTEGRITY_INVALID/)
  await raw.query('UPDATE instances SET renewal_price=12 WHERE id=$1', [instanceId])
  const recharge = await prisma.rechargeRecord.create({ data: { userId, providerId, orderNo: tag, amount: 10, actualAmount: 9 } })
  const rechargeSaved = (await raw.query('SELECT to_jsonb(t) row FROM recharge_records t WHERE id=$1', [recharge.id])).rows[0].row
  await raw.query('DELETE FROM recharge_records WHERE id=$1', [recharge.id])
  await assert.rejects(prisma.rechargeRecord.findUnique({ where: { id: recharge.id } }), /FINANCIAL_INTEGRITY_INVALID/)
  await raw.query('INSERT INTO recharge_records SELECT * FROM json_populate_record(NULL::recharge_records,$1)', [JSON.stringify(rechargeSaved)])
  await raw.query('UPDATE recharge_records SET actual_amount=100 WHERE id=$1', [recharge.id])
  await assert.rejects(prisma.rechargeRecord.findUnique({ where: { id: recharge.id } }), /FINANCIAL_INTEGRITY_INVALID/)
  await raw.query('UPDATE recharge_records SET actual_amount=9 WHERE id=$1', [recharge.id])
  const renewal = await prisma.renewalRequest.create({ data: { userId, requestKey: tag, inputHash: tag } })
  await raw.query("UPDATE renewal_requests SET results='{}'::jsonb || '{\"1\":true}'::jsonb WHERE user_id=$1 AND request_key=$2", [userId, renewal.requestKey])
  await assert.rejects(prisma.renewalRequest.findUnique({ where: { userId_requestKey: { userId, requestKey: tag } } }), /FINANCIAL_INTEGRITY_INVALID/)
  await raw.query("UPDATE renewal_requests SET results='{}'::jsonb WHERE user_id=$1 AND request_key=$2", [userId, tag])
  const bill = await prisma.instanceBillingRecord.create({ data: { userId, instanceId, type: 'renew', amount: 10, periodStart: new Date(), periodEnd: new Date(Date.now() + 86400000) } })
  const removed = (await raw.query('SELECT to_jsonb(t) row FROM instance_billing_records t WHERE id=$1', [bill.id])).rows[0].row
  await raw.query('DELETE FROM instance_billing_records WHERE id=$1', [bill.id])
  await assert.rejects(verifyFinancialDatabaseSeals(url.pathname.slice(1), process.env.ENCRYPTION_KEY), /FINANCIAL_INTEGRITY_INVALID/, 'deleted business rows are detected by orphan seals')
  await raw.query('INSERT INTO instance_billing_records SELECT * FROM json_populate_record(NULL::instance_billing_records,$1)', [JSON.stringify(removed)])
  await prisma.instance.delete({ where: { id: instanceId } }); instanceId = 0
  await verifyFinancialDatabaseSeals(url.pathname.slice(1), process.env.ENCRYPTION_KEY)
  for (const field of ['aff_balance', 'hosting_balance']) {
    await raw.query(`UPDATE users SET ${field}=1000 WHERE id=$1`, [userId])
    await assert.rejects(read(), /FINANCIAL_INTEGRITY_INVALID/)
    await raw.query(`UPDATE users SET ${field}=0 WHERE id=$1`, [userId])
  }
  const deleted = await prisma.user.create({ data: { username: tag + '-deleted', passwordHash: 'fixture', balance: 2 } })
  additionalUsers.push(deleted.id)
  await prisma.$transaction(async tx => {
    const user = await tx.user.update({ where: { id: deleted.id }, data: { balance: 3 } })
    await tx.balanceLog.create({ data: { userId: deleted.id, type: 'gift', amount: 1, balanceBefore: 2, balanceAfter: user.balance } })
    await tx.rechargeRecord.create({ data: { userId: deleted.id, providerId, orderNo: tag + '-deleted', amount: 1 } })
  })
  await prisma.user.delete({ where: { id: deleted.id } })
  await verifyFinancialDatabaseSeals(url.pathname.slice(1), process.env.ENCRYPTION_KEY)
  const operator = (await raw.query("INSERT INTO users(username,password_hash,role,updated_at) VALUES($1,'fixture','admin',NOW()) RETURNING id", ['recovery-' + tag])).rows[0].id
  additionalUsers.push(operator)
  await sealRecoveryOperatorWallet(url.pathname.slice(1), operator, process.env.ENCRYPTION_KEY)
  const changeRole = async(role:string,status:string)=>{
    const client=await raw.connect()
    try{await client.query('BEGIN');await changeRecoveryOperatorRole(async(sql,params=[]) => (await client.query(sql,params)).rows,operator,role,status);await client.query('COMMIT')}
    catch(error){await client.query('ROLLBACK');throw error}finally{client.release()}
  }
  await changeRole('user','banned');await changeRole('admin','active')
  await verifyFinancialDatabaseSeals(url.pathname.slice(1), process.env.ENCRYPTION_KEY)
  await prisma.user.delete({ where: { id: operator } })
  // The current B recovery actor must use real password/hold/batch checks.
  const { captureRecoveryOperator, installRecoveryOperator } = await import('../src/services/platform-recovery-operator.js')
  const { registerRecoveryRecharge } = await import('../src/services/platform-recovery-registration.js')
  const { serializeBackupMutation, writeJson } = await import('../src/services/platform-backup-core.js')
  const { default: bcrypt } = await import('bcryptjs')
  const backupState=join(directory,'recovery');process.env.PLATFORM_BACKUP_STATE_DIR=backupState
  await (await import('node:fs/promises')).mkdir(backupState,{recursive:true})
  await (await import('node:fs/promises')).mkdir(join(backupState,'inbox'),{recursive:true})
  const actorPassword='isolated-recovery-password', actor=await prisma.user.create({data:{username:tag+'-admin',role:'admin',passwordHash:await bcrypt.hash(actorPassword,4)}})
  additionalUsers.push(actor.id);process.env.PLATFORM_BACKUP_ALLOWED_ADMIN_IDS=String(actor.id)
  const batch=randomUUID();await captureRecoveryOperator(actor.id,batch)
  const recoveredActor=await installRecoveryOperator(batch,batch,'restore');additionalUsers.push(recoveredActor)
  await sealRecoveryOperatorWallet(url.pathname.slice(1),recoveredActor,process.env.ENCRYPTION_KEY)
  const { backupRoot }=await import('../src/services/platform-backup-core.js')
  const now=new Date(),snapshotAt=new Date(now.getTime()-3600000).toISOString()
  await writeJson(join(backupRoot(),'recovery-hold.json'),{taskId:batch,batchId:batch,mode:'restore',createdAt:new Date(now.getTime()-1000).toISOString(),snapshot:{createdAt:snapshotAt,version:'1.8.14'}})
  await prisma.paymentProvider.update({where:{id:providerId},data:{type:'yipay'}})
  const proof={id:randomUUID(),reference:'finance-recovery-'+randomUUID(),evidenceHash:'a'.repeat(64),observedAt:new Date().toISOString(),userId,orderNo:'recovered-'+tag,
    providerId,method:'alipay',tradeNo:'recovered-trade-'+tag,amount:'10.00',creditedAmount:'9.00',fee:'1.00',paidAt:new Date(now.getTime()-500).toISOString(),
    expectedBalance:'92.00',targetBalance:'101.00',expectedLatestLogId:(await prisma.balanceLog.findFirstOrThrow({where:{userId},orderBy:{id:'desc'}})).id,currency:'CNY',receivedAmount:'10.00'}
  await assert.rejects(serializeBackupMutation(()=>registerRecoveryRecharge(proof,recoveredActor,{password:'wrong-password'})),/CREDENTIALS_INVALID/)
  const accepted=await serializeBackupMutation(()=>registerRecoveryRecharge(proof,recoveredActor,{password:actorPassword}))
  assert.equal(accepted.replayed,false)
  assert.equal((await serializeBackupMutation(()=>registerRecoveryRecharge(proof,recoveredActor,{password:actorPassword}))).replayed,true)
  assert.equal((await read()).balance.toFixed(2),'101.00')
  await verifyFinancialDatabaseSeals(url.pathname.slice(1),process.env.ENCRYPTION_KEY)
  await unlink(join(backupRoot(),'recovery-hold.json'))
  await raw.query('DELETE FROM platform_recovery_evidence WHERE batch_id=$1',[batch]);await raw.query('DELETE FROM platform_recovery_batches WHERE id=$1',[batch])
  await prisma.user.delete({where:{id:recoveredActor}});await prisma.user.delete({where:{id:actor.id}})
  console.log('PASS current synthetic B recovery actor: real password reauthentication, durable trade evidence, one credit on replay, all seals verified')
  const checkout = await prisma.checkoutOrder.create({ data: { id: tag, userId, requestHash: tag, source: 'direct', totalCents: 1000,
    snapshot: 'fixture', display: [], expiresAt: new Date(Date.now() + 60000) } })
  await prepareRecoveryCheckoutStatuses(url.pathname.slice(1), process.env.ENCRYPTION_KEY, false)
  assert.equal((await prisma.checkoutOrder.findUniqueOrThrow({ where: { id: checkout.id } })).status, 'recovery_review')
  await verifyFinancialDatabaseSeals(url.pathname.slice(1), process.env.ENCRYPTION_KEY)
  await prisma.checkoutOrder.delete({ where: { id: checkout.id } })
  if (process.env.FINANCE_PG_TOOLS_DIR && process.env.FINANCE_RESTORE_DATABASE_URL) {
    const target = new URL(process.env.FINANCE_RESTORE_DATABASE_URL)
    assert.equal(target.hostname, '127.0.0.1'); assert.ok(target.pathname.endsWith('_recovery_test'))
    const exec = promisify(execFile), suffix = process.platform === 'win32' ? '.exe' : ''
    const environment = (value: URL) => ({ ...process.env, PGHOST: value.hostname, PGPORT: value.port || '5432', PGUSER: decodeURIComponent(value.username),
      PGPASSWORD: decodeURIComponent(value.password), PGDATABASE: value.pathname.slice(1) })
    const dump = join(directory, 'signed.dump')
    await exec(join(process.env.FINANCE_PG_TOOLS_DIR, 'pg_dump' + suffix), ['-Fc', '-f', dump], { env: environment(url) })
    const { encryptBackup, decryptBackup } = await import('../src/services/platform-backup-archive.js')
    const archive = join(directory, 'finance.enc'), env = join(directory, 'runtime.env')
    await writeFile(env, `ENCRYPTION_KEY=${process.env.ENCRYPTION_KEY}\n`)
    await encryptBackup([{ name: 'database.dump', path: dump }, { name: 'runtime.env', path: env }, { name: 'finance-baseline.json', path: financialIntegrityStatePath() }],
      { format: 1, id: randomUUID(), installationId: randomUUID(), createdAt: new Date().toISOString(), version: '1.8.14', migrationHash: 'a'.repeat(64), postgresMajor: 16, databaseBytes: 1000000 }, 'isolated-backup-password', archive)
    const restored = await decryptBackup(archive, 'isolated-backup-password', join(directory, 'restored'))
    await assert.rejects(decryptBackup(archive, 'wrong-backup-password', join(directory, 'wrong-password')))
    await exec(join(process.env.FINANCE_PG_TOOLS_DIR, 'pg_restore' + suffix), ['--no-owner', '--no-acl', '-d', target.pathname.slice(1), restored.files.get('database.dump')!], { env: environment(target) })
    const saved = process.env.DATABASE_URL
    try {
      process.env.DATABASE_URL = target.href
      await verifyFinancialDatabaseSeals(target.pathname.slice(1), process.env.ENCRYPTION_KEY)
      await assert.rejects(verifyFinancialDatabaseSeals(target.pathname.slice(1), 'incorrect-restored-key'), /FINANCIAL_INTEGRITY_INVALID/)
    } finally { process.env.DATABASE_URL = saved }
    console.log('PASS signed pg_dump -> authenticated backup archive -> actual isolated pg_restore; all money records and original key verified')
  }
  // Authenticated legacy recovery is explicit, and never permits existing
  // signed rows to be silently re-baselined under a different key.
  disableFinancialIntegrityForShutdown()
  await raw.query('DELETE FROM platform_recovery_evidence WHERE actor_id=ANY($1::int[])',[additionalUsers])
  await raw.query('DELETE FROM platform_recovery_batches WHERE operator_id=ANY($1::int[])',[additionalUsers])
  await raw.query('DELETE FROM financial_integrity_seals')
  await unlink(financialIntegrityStatePath())
  await writeFile(financialIntegrityStatePath(), legacyFinancialBaseline(process.env.ENCRYPTION_KEY))
  await verifyFinancialDatabaseSeals(url.pathname.slice(1), process.env.ENCRYPTION_KEY, true)
  await initializeFinancialDatabaseIntegrity()
  assert.equal(JSON.parse(await readFile(financialIntegrityStatePath(), 'utf8')).version, 1)
  await verifyFinancialDatabaseSeals(url.pathname.slice(1), process.env.ENCRYPTION_KEY)
  await assert.rejects(verifyFinancialDatabaseSeals(url.pathname.slice(1), 'wrong-recovered-encryption-key'), /FINANCIAL_INTEGRITY_INVALID/)
  const seal = await raw.query("SELECT signature FROM financial_integrity_seals WHERE kind='ledger' AND record_id=$1", [String(log.id)])
  await raw.query("DELETE FROM financial_integrity_seals WHERE kind='ledger' AND record_id=$1", [String(log.id)])
  await assert.rejects(read(), /FINANCIAL_INTEGRITY_INVALID/)
  await assert.rejects(initializeFinancialDatabaseIntegrity(), /FINANCIAL_INTEGRITY_INVALID/, 'existing external baseline never re-signs lost seals')
  await raw.query("INSERT INTO financial_integrity_seals(kind,record_id,signature,updated_at) VALUES('ledger',$1,$2,NOW())", [String(log.id), seal.rows[0].signature])
  assert.equal((await read()).balance.toFixed(2), '101.00')
  console.log('PASS money seals: actual PG balance/ledger mutation and deleted seal detection, transaction rollback, legacy writers, full restore key verification and no automatic resealing')
} finally {
  disableFinancialIntegrityForShutdown()
  await raw.query('DELETE FROM platform_recovery_evidence WHERE actor_id=ANY($1::int[])',[additionalUsers])
  await raw.query('DELETE FROM platform_recovery_batches WHERE operator_id=ANY($1::int[])',[additionalUsers])
  await raw.query('DELETE FROM balance_logs WHERE user_id=$1', [userId])
  await raw.query('DELETE FROM instances WHERE id=$1', [instanceId])
  await raw.query('DELETE FROM hosts WHERE id=$1', [hostId])
  await raw.query('DELETE FROM checkout_orders WHERE user_id=$1', [userId])
  await raw.query('DELETE FROM recharge_records WHERE provider_id=$1', [providerId])
  await raw.query('DELETE FROM payment_providers WHERE id=$1', [providerId])
  await raw.query('DELETE FROM users WHERE id=ANY($1::int[])', [additionalUsers])
  await raw.query('DELETE FROM users WHERE id=$1', [userId])
  await raw.query('DELETE FROM financial_integrity_seals')
  await raw.end(); await closePrismaDatabase(); await rm(directory, { recursive: true, force: true })
}
async function moveSafe(tx: any, amount: number) { return changeBalanceInTransaction(tx, { userId, type: 'admin_adjust', amount, remark: 'multiple entry test' }) }
process.exit(0)
