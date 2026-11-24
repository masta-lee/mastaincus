import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { generateKeyPairSync, sign, createHash } from 'node:crypto'
import { createEpayClient } from '../src/lib/epay.js'
import { buildRechargeProviderConfigSnapshot, resolveRechargeProviderConfigSnapshot } from '../src/lib/recharge-provider-snapshot.js'
import { legacyFinancialBaseline, verifyFinancialBaseline } from '../src/lib/financial-integrity.js'

process.env.ENCRYPTION_KEY = 'isolated-financial-guards-secret'
const files = await Promise.all(['lib/financial-integrity.ts','db/prisma.ts','app.ts','services/platform-backup-worker.ts','services/platform-backup-database.ts','services/platform-recovery-registration.ts','services/platform-recovery-reconciliation.ts','scripts/run-platform-backup-task.ts']
  .map(path => readFile(new URL('../src/' + path, import.meta.url), 'utf8')))
const [integrity, database, app, backup, dump, registration, reconcile, worker] = files
assert.ok(database.includes('protectFinancialClient(rawPrisma)') && database.includes('protectAuthenticationClient(financialPrisma)'))
assert.ok(app.indexOf('await initializeFinancialDatabaseIntegrity()') < app.indexOf('if (recoveryHeld()) {\n      startRecoveryReviewWorker()'))
for (const kind of ['rechargeLatePayment','deletedPaymentReceipt','balanceAdjustmentRequest','instanceBillingRecord','checkoutReceipt','checkoutRefund','renewalRequest']) assert.ok(integrity.includes(kind))
assert.ok(integrity.includes('assertNoOrphanSeals') && integrity.includes('trackCascade') && integrity.includes('trackNullableRelations'))
assert.ok(integrity.includes('financialOperation') && integrity.includes("AT TIME ZONE 'UTC'"))
assert.ok(backup.includes('finance-baseline.json') && backup.includes('verifyFinancialBaseline') && backup.includes('prepareRecoveryCheckoutStatuses'))
assert.ok(worker.includes("request.kind === 'backup' || request.kind === 'resume'") && backup.includes('await initializeFinancialDatabaseIntegrity()'))
assert.ok(integrity.includes("wallet: ['id','username','email','passwordHash','role','status'") && integrity.includes('sealedFields'))
assert.ok(dump.includes('verifyFinancialDatabaseSeals(staging'))
for (const source of [registration,reconcile]) assert.ok(source.includes('PAYMENT_SETTLEMENT_LOCK_NAMESPACE') && source.includes('assertPaymentNotDeleted'))
const snapshot = buildRechargeProviderConfigSnapshot('yipay', { pid: 'test-merchant', key: 'fixture-secret' })
assert.equal(resolveRechargeProviderConfigSnapshot('yipay', {}, snapshot).source, 'snapshot')
// Flip a bit in each authenticated component. Replacing a random byte with
// a constant occasionally leaves the original ciphertext unchanged.
const tamperedSnapshots = snapshot.split(':').map((_, index, parts) => {
  const changed = [...parts]
  const bytes = Buffer.from(changed[index], 'hex')
  bytes[bytes.length - 1] ^= 1
  changed[index] = bytes.toString('hex')
  const tampered = changed.join(':')
  assert.notEqual(tampered, snapshot)
  return tampered
})
for (const invalid of ['plaintext', ...tamperedSnapshots, buildRechargeProviderConfigSnapshot('antom', {})]) assert.throws(() => resolveRechargeProviderConfigSnapshot('yipay', { pid: 'replacement' }, invalid), /SNAPSHOT_INVALID/)
assert.equal(resolveRechargeProviderConfigSnapshot('yipay', {}, null).source, 'provider')
assert.throws(() => verifyFinancialBaseline(legacyFinancialBaseline(process.env.ENCRYPTION_KEY!), process.env.ENCRYPTION_KEY!), /FINANCIAL_INTEGRITY_INVALID/)
const keys = generateKeyPairSync('rsa', { modulusLength: 2048 })
const client = createEpayClient({ version: 'v2', apiurl: 'https://1.1.1.1', pid: '123', platform_public_key: keys.publicKey.export({type:'spki',format:'der'}).toString('base64'), merchant_private_key: keys.privateKey.export({type:'pkcs8',format:'der'}).toString('base64') })
const signed = (timestamp: unknown) => {
  const fields: any = { pid:'123', out_trade_no:'fixture', trade_no:'fixture', money:'10.00', trade_status:'TRADE_SUCCESS', timestamp }
  const text = Object.keys(fields).filter(key=>fields[key]!==undefined&&fields[key]!==null&&fields[key]!=='').sort().map(key=>`${key}=${fields[key]}`).join('&')
  fields.sign=sign('sha256',Buffer.from(text),keys.privateKey).toString('base64');return fields
}
assert.equal(client.verifyWithStatus(signed(String(Math.floor(Date.now()/1000)))).tradeSuccess, true)
for (const timestamp of ['NaN','Infinity','123junk',String(Date.now()),{},[],String(Math.floor(Date.now()/1000)-301)]) assert.equal(client.verifyWithStatus(signed(timestamp)).valid,false)
const v1=createEpayClient({version:'v1',apiurl:'https://1.1.1.1',pid:'123',key:'fixture'})
const fields:any={pid:'123',out_trade_no:'test',trade_no:'test',money:'10.00',trade_status:'TRADE_SUCCESS'}
fields.sign=createHash('md5').update(Object.keys(fields).sort().map(key=>`${key}=${fields[key]}`).join('&')+'fixture').digest('hex')
assert.equal(v1.verify(fields),true);assert.equal(v1.verify({...fields,money:['10.00']}),false)
console.log('PASS financial guards: application/restore seal boundaries, encrypted snapshots, malformed signed timestamps and scalar callback fields')
process.exit(0)
