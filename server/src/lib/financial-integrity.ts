import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto'
import { existsSync } from 'node:fs'
import { mkdir, readFile, rename, open, lstat, unlink } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { Prisma, type PrismaClient } from '@prisma/client'
import { Pool } from 'pg'

type Db = Prisma.TransactionClient
type Kind = 'wallet' | 'ledger' | 'recharge' | 'billing' | 'checkout' | 'payment' | 'receipt' | 'refund' | 'renewal' |
  'late' | 'deletedReceipt' | 'adjustment' | 'instance' | 'poolOrder' | 'affLedger' | 'hostingLedger' | 'provider' | 'poolPrice' | 'plan' | 'giftCard'
const models: Record<Kind, string> = { wallet: 'user', ledger: 'balanceLog', recharge: 'rechargeRecord', billing: 'instanceBillingRecord',
  checkout: 'checkoutOrder', payment: 'checkoutPayment', receipt: 'checkoutReceipt', refund: 'checkoutRefund', renewal: 'renewalRequest',
  late: 'rechargeLatePayment', deletedReceipt: 'deletedPaymentReceipt', adjustment: 'balanceAdjustmentRequest', instance: 'instance',
  poolOrder: 'poolOrder', affLedger: 'affLog', hostingLedger: 'hostingBalanceLog', provider: 'paymentProvider', poolPrice: 'hostPoolPrice', plan: 'packagePlan', giftCard: 'giftCard' }
const kinds = new Map(Object.entries(models).map(([kind, model]) => [model, kind as Kind]))
const metadata = new Map(Prisma.dmmf.datamodel.models.map(model => [model.name[0].toLowerCase() + model.name.slice(1), model]))
// Signature v1 is a persistent wire format. Adding an unrelated database
// column in a later release must not invalidate existing OSS backups/seals.
const sealedFields: Record<Kind, string[]> = {
  wallet: ['id','username','email','passwordHash','role','status','twoFactorEnabled','twoFactorSecret','balance','affBalance','hostingBalance'],
  ledger: ['id','userId','type','amount','balanceBefore','balanceAfter','orderId','instanceId','remark','createdAt'],
  recharge: ['id','userId','providerId','orderNo','creationRequestId','creationRequestHash','tradeNo','amount','actualAmount','fee','paymentMethod','status','cancelReason','callbackData','callbackAt','providerConfigSnapshot','paymentDetails','failReason','ip','userAgent','createdAt','expiredAt','completedAt'],
  billing: ['id','instanceId','userId','type','amount','months','periodStart','periodEnd','balanceLogId','remark','createdAt','purchaseBatchId'],
  checkout: ['id','userId','requestHash','source','status','totalCents','snapshot','display','expiresAt','paidAt','paymentId','error','attempts','nextAttemptAt','createdAt'],
  payment: ['id','orderId','providerId','providerType','providerName','method','payableCents','feeCents','configSnapshot','details','payUrl','status','createdAt'],
  receipt: ['id','paymentId','providerId','tradeNo','amountCents','currency','proof','createdAt'],
  refund: ['id','orderId','paymentId','receiptId','instanceId','billingRecordId','amountCents','principalCents','reason','status','resolution','handledById','handledAt','createdAt'],
  renewal: ['userId','requestKey','inputHash','results','createdAt'],
  late: ['id','rechargeId','providerId','gatewayOrderNo','tradeNo','receivedAmount','currency','eligible','reason','status','proof','expectedPaymentDetails','note','handledById','handledAt','createdAt'],
  deletedReceipt: ['providerId','tradeHash','createdAt'],
  adjustment: ['id','userId','requestedByUserId','reviewedByUserId','amount','requestType','status','sourceType','sourceId','orderNo','reason','reviewRemark','balanceLogId','createdAt','reviewedAt'],
  instance: ['id','userId','purchaseBatchId','packagePlanId','billingPrice','renewalPrice','billingCycle','expiresAt'],
  poolOrder: ['id','userId','requestHash','totalCents','createdAt'],
  affLedger: ['id','userId','affCodeId','instanceId','mailSubscriptionId','type','amount','originalAmount','balanceBefore','balanceAfter','remark','createdAt'],
  hostingLedger: ['id','userId','type','actionType','amount','frozen','unfreezeAt','relatedId','remark','snapshotBuyerName','snapshotBuyerEmail','snapshotBuyerAvatar','snapshotInstanceName','snapshotHostName','snapshotPackageName','snapshotPlanName','createdAt'],
  provider: ['id','name','type','status','config','methods','feeRate','feeFixed','minAmount','maxAmount','sortOrder','createdAt'],
  poolPrice: ['id','machineGroupId','resourcePreset','regionGroupId','diskGiB','name','monthlyPrice','setupFee','active','shadowPlanId','sortOrder','createdAt'],
  plan: ['id','packageId','name','description','cpu','memory','disk','portLimit','snapshotLimit','backupLimit','siteLimit','swapSize','trafficLimit','trafficLimitSpeed','price','billingCycle','setupFee','trafficResetPrice','isActive','isSoldOut','sortOrder','slaGuarantee','createdAt'],
  giftCard: ['id','code','faceValue','balanceValue','status','createdById','ownerId','usedById','usedAt','expiresAt','remark','batchId','createdAt']
}
const ledgerSqlFacts = "jsonb_build_array(l.id,l.user_id,l.type,l.amount,l.balance_before,l.balance_after,l.order_id,l.instance_id,l.remark,l.created_at)"
const root = () => process.env.NODE_ENV === 'production' ? '/var/lib/incudal-finance' : resolve(process.env.FINANCIAL_INTEGRITY_STATE_DIR || '.cache/financial-integrity')
export const financialIntegrityStatePath = () => join(root(), 'baseline.json')
export function legacyFinancialBaseline(secret: string) { return JSON.stringify({ version: 0, signature: signature('baseline', 'legacy', { version: 0 }, secret) }) }
export function verifyFinancialBaseline(value: string, secret: string) {
  const marker = JSON.parse(value)
  if (marker.version !== 1 || !matches(marker.signature, signature('baseline', 'v1', { version: 1 }, secret))) throw new FinancialIntegrityError()
}
let enabled = false

export class FinancialIntegrityError extends Error {
  constructor() { super('FINANCIAL_INTEGRITY_INVALID') }
}
function canonical(value: any): any {
  if (value instanceof Date) return value.toISOString()
  if (Prisma.Decimal.isDecimal(value)) return value.toString()
  if (typeof value === 'bigint') return value.toString()
  if (Array.isArray(value)) return value.map(canonical)
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]))
  return value
}
function facts(kind: Kind, row: any) {
  return Object.fromEntries(sealedFields[kind].map(key => [key, row[key]]))
}
function assertNoNestedFinancialWrites(model: string, args: any) {
  for (const operation of [args.data, args.create, args.update]) if (operation) {
    for (const relation of metadata.get(model)?.fields.filter(field => field.kind === 'object') || []) {
      const nested = operation[relation.name]
      if (!nested || typeof nested !== 'object') continue
      const child = relation.type[0].toLowerCase() + relation.type.slice(1)
      if (kinds.has(child) && ['create','createMany','update','updateMany','upsert','delete','deleteMany','connectOrCreate'].some(key => Object.hasOwn(nested, key))) throw new FinancialIntegrityError()
      for (const key of ['create','update','upsert','connectOrCreate']) if (nested[key]) for (const value of Array.isArray(nested[key]) ? nested[key] : [nested[key]]) assertNoNestedFinancialWrites(child, value.data ? value : { data: value })
    }
  }
}
function recordId(kind: Kind, row: any): string {
  if (kind === 'renewal') return JSON.stringify([row.userId, row.requestKey])
  if (kind === 'deletedReceipt') return JSON.stringify([row.providerId, row.tradeHash])
  return String(row.id)
}
function where(kind: Kind, row: any): any {
  if (kind === 'renewal') return { userId_requestKey: { userId: row.userId, requestKey: row.requestKey } }
  if (kind === 'deletedReceipt') return { providerId_tradeHash: { providerId: row.providerId, tradeHash: row.tradeHash } }
  return { id: row.id }
}
function signature(kind: string, id: string, value: unknown, secret = process.env.ENCRYPTION_KEY): string {
  if (!secret || secret.length < 16) throw new FinancialIntegrityError()
  return createHmac('sha256', secret).update('payincus/financial-integrity/v1\n').update(kind).update('\n').update(id).update('\n')
    .update(JSON.stringify(canonical(value))).digest('hex')
}
function matches(actual: unknown, expected: string): boolean {
  return typeof actual === 'string' && /^[a-f0-9]{64}$/.test(actual) && timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'))
}
async function verify(db: Db, kind: Kind, row: any) {
  const id = recordId(kind, row)
  const seal = await db.financialIntegritySeal.findUnique({ where: { kind_recordId: { kind, recordId: id } } })
  const value = kind === 'wallet' ? { ...facts(kind, row), ledger: await ledgerHead(db, row.id) } : facts(kind, row)
  if (!seal || !matches(seal.signature, signature(kind, id, value))) throw new FinancialIntegrityError()
}
async function seal(db: Db, kind: Kind, row: any) {
  const id = recordId(kind, row), value = kind === 'wallet' ? { ...facts(kind, row), ledger: await ledgerHead(db, row.id) } : facts(kind, row)
  const signed = signature(kind, id, value)
  await db.financialIntegritySeal.upsert({ where: { kind_recordId: { kind, recordId: id } }, create: { kind, recordId: id, signature: signed }, update: { signature: signed } })
}
async function ledgerHead(db: Db, userId: number) {
  const [value] = await db.$queryRaw<Array<{ count: bigint; sealed: bigint; hash: string }>>(Prisma.sql`
    SELECT count(*) AS count, count(s.signature) AS sealed,
      encode(sha256(convert_to(COALESCE(string_agg(l.id::text || ':' || s.signature || ':' ||
        encode(sha256(convert_to(${Prisma.raw(ledgerSqlFacts)}::text,'UTF8')),'hex'), ',' ORDER BY l.id), ''),'UTF8')),'hex') AS hash
    FROM balance_logs l LEFT JOIN financial_integrity_seals s ON s.kind='ledger' AND s.record_id=l.id::text WHERE l.user_id=${userId}`)
  if (value.count !== value.sealed) throw new FinancialIntegrityError()
  return { count: value.count.toString(), hash: value.hash }
}
const orderedKinds: Kind[] = [...[...kinds.values()].filter(kind => kind !== 'wallet'), 'wallet']
function parseIdentity(kind: Kind, id: string) {
  if (kind === 'renewal') { const [userId, requestKey] = JSON.parse(id); return { userId, requestKey } }
  if (kind === 'deletedReceipt') { const [providerId, tradeHash] = JSON.parse(id); return { providerId, tradeHash } }
  const numeric = metadata.get(models[kind])!.fields.find(field => field.name === 'id')!.type === 'Int'
  return { id: numeric ? Number(id) : id }
}
async function assertNoOrphanSeals(db: Db) {
  for (const receipt of await db.financialIntegritySeal.findMany()) {
    if (receipt.kind === 'baseline' && receipt.recordId === 'v1') {
      if (!matches(receipt.signature, signature('baseline', 'v1', { version: 1 }))) throw new FinancialIntegrityError()
      continue
    }
    if (!orderedKinds.includes(receipt.kind as Kind)) throw new FinancialIntegrityError()
    const kind = receipt.kind as Kind, identity = parseIdentity(kind, receipt.recordId)
    if (!await (db as any)[models[kind]].findUnique({ where: where(kind, identity) })) throw new FinancialIntegrityError()
  }
}

// Bootstrap is explicitly persisted outside PostgreSQL. Deleting seal rows
// cannot cause an already initialized installation to trust altered money.
export async function initializeFinancialIntegrity(raw: PrismaClient) {
  const path = financialIntegrityStatePath()
  if (existsSync(path)) {
    const marker = JSON.parse(await readFile(path, 'utf8'))
    if (marker.version === 0 && matches(marker.signature, signature('baseline', 'legacy', { version: 0 }))) {
      if (await raw.financialIntegritySeal.count()) throw new FinancialIntegrityError()
    } else {
      verifyFinancialBaseline(JSON.stringify(marker), process.env.ENCRYPTION_KEY || '')
      await raw.$transaction(async tx => {
        const baseline = await tx.financialIntegritySeal.findUnique({ where: { kind_recordId: { kind: 'baseline', recordId: 'v1' } } })
        if (!baseline || !matches(baseline.signature, signature('baseline', 'v1', { version: 1 }))) throw new FinancialIntegrityError()
        for (const kind of orderedKinds) {
          const rows = await (tx as any)[models[kind]].findMany()
          for (const row of rows) await verify(tx, kind, row)
        }
        await assertNoOrphanSeals(tx)
      }, { timeout: 120000, isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead })
      enabled = true
      return
    }
  }
  // Existing data is a one-time migration baseline, not independently proven
  // historic payments. No balance, expiry or original ledger row is altered.
  await raw.$transaction(async tx => {
    await tx.$queryRaw`SELECT true FROM pg_advisory_xact_lock(4130, 1)`
    for (const kind of orderedKinds) {
      const rows = await (tx as any)[models[kind]].findMany()
      for (const row of rows) {
        if (kind === 'wallet' && (row.balance.lessThan(0) || row.balance.greaterThan('99999999.99'))) throw new FinancialIntegrityError()
        const existing = await tx.financialIntegritySeal.findUnique({ where: { kind_recordId: { kind, recordId: recordId(kind, row) } } })
        if (existing) await verify(tx, kind, row)
        else await seal(tx, kind, row)
      }
    }
    await assertNoOrphanSeals(tx)
    const signed = signature('baseline', 'v1', { version: 1 })
    await tx.financialIntegritySeal.upsert({ where: { kind_recordId: { kind: 'baseline', recordId: 'v1' } },
      create: { kind: 'baseline', recordId: 'v1', signature: signed }, update: { signature: signed } })
  }, { timeout: 120000, isolationLevel: Prisma.TransactionIsolationLevel.Serializable })
  await mkdir(root(), { recursive: true, mode: 0o700 })
  const directory = await lstat(root())
  if (!directory.isDirectory() || directory.isSymbolicLink()) throw new FinancialIntegrityError()
  const temporary = path + '.' + randomUUID() + '.new'
  const file = await open(temporary, 'wx', 0o600)
  try {
    if (process.platform !== 'win32' && process.getuid?.() === 0) await file.chown(directory.uid, directory.gid)
    await file.writeFile(JSON.stringify({ version: 1, signature: signature('baseline', 'v1', { version: 1 }) }))
    await file.chmod(0o600); await file.sync()
  } finally { await file.close() }
  try { await rename(temporary, path) } finally { await unlink(temporary).catch(() => {}) }
  if (process.platform !== 'win32') { const folder = await open(root(), 'r'); try { await folder.sync() } finally { await folder.close() } }
  enabled = true
}

export function financialIntegrityEnabled() { return enabled }
export function disableFinancialIntegrityForShutdown() { enabled = false }
export async function verifyFinancialDatabaseSeals(database: string, secret: string, allowLegacy = false) {
  const url = new URL(process.env.DATABASE_URL || '')
  url.pathname = '/' + database
  const pool = new Pool({ connectionString: url.href, max: 1 })
  const client = await pool.connect()
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
    const seals = (await client.query('SELECT kind,record_id,signature FROM financial_integrity_seals')).rows
    if (allowLegacy && !seals.length) return
    const index = new Map(seals.map(row => [`${row.kind}:${row.record_id}`, row.signature]))
    if (!matches(index.get('baseline:v1'), signature('baseline', 'v1', { version: 1 }, secret))) throw new FinancialIntegrityError()
    index.delete('baseline:v1')
    // SQL names/columns are from the installed Prisma model, never the archive.
    for (const kind of orderedKinds) {
      const model = metadata.get(models[kind])!
      const columns = model.fields.filter(field => sealedFields[kind].includes(field.name))
      const rows = (await client.query(`SELECT ${columns.map(field => '"' + (field.dbName || field.name) + '"' + (field.type === 'DateTime' ? " AT TIME ZONE 'UTC'" : '') + ' AS "' + field.name + '"').join(',')} FROM "${model.dbName}"`)).rows
      for (const row of rows) {
        for (const field of columns) if (row[field.name] !== null) {
          if (field.type === 'Decimal') row[field.name] = new Prisma.Decimal(row[field.name])
          if (field.type === 'BigInt') row[field.name] = BigInt(row[field.name])
        }
        const id = recordId(kind, row)
        let value = facts(kind, row)
        if (kind === 'wallet') {
          const logs = (await client.query(`SELECT l.id,s.signature,encode(sha256(convert_to(${ledgerSqlFacts}::text,'UTF8')),'hex') hash FROM balance_logs l LEFT JOIN financial_integrity_seals s ON s.kind='ledger' AND s.record_id=l.id::text WHERE l.user_id=$1 ORDER BY l.id`, [row.id])).rows
          if (logs.some(log => !log.signature)) throw new FinancialIntegrityError()
          value = { ...value, ledger: { count: String(logs.length), hash: createHash('sha256').update(logs.map(log => `${log.id}:${log.signature}:${log.hash}`).join(',')).digest('hex') } }
        }
        if (!matches(index.get(`${kind}:${id}`), signature(kind, id, value, secret))) throw new FinancialIntegrityError()
        index.delete(`${kind}:${id}`)
      }
    }
    if (index.size) throw new FinancialIntegrityError()
  } finally { await client.query('ROLLBACK'); client.release(); await pool.end() }
}
export async function sealRecoveryOperatorWallet(database: string, id: number, secret: string) {
  const url = new URL(process.env.DATABASE_URL || ''); url.pathname = '/' + database
  const pool = new Pool({ connectionString: url.href, max: 1 })
  try {
    const columns = metadata.get('user')!.fields.filter(field => sealedFields.wallet.includes(field.name))
    const { rows: [user] } = await pool.query(`SELECT ${columns.map(field=>'"'+(field.dbName||field.name)+'" AS "'+field.name+'"').join(',')} FROM users WHERE id=$1`, [id])
    const { rows: [logs] } = await pool.query('SELECT count(*)::int count FROM balance_logs WHERE user_id=$1', [id])
    if (!user || logs.count || new Prisma.Decimal(user.balance).toNumber() !== 0) throw new FinancialIntegrityError()
    const value = { ...facts('wallet', {...user,balance:new Prisma.Decimal(user.balance),affBalance:new Prisma.Decimal(user.affBalance),hostingBalance:new Prisma.Decimal(user.hostingBalance)}), ledger: { count: '0', hash: createHash('sha256').update('').digest('hex') } }
    await pool.query('INSERT INTO financial_integrity_seals(kind,record_id,signature,updated_at) VALUES(\'wallet\',$1,$2,NOW()) ON CONFLICT(kind,record_id) DO UPDATE SET signature=EXCLUDED.signature,updated_at=NOW()', [String(id), signature('wallet', String(id), value, secret)])
  } finally { await pool.end() }
}
export async function changeRecoveryOperatorRole(query: (sql:string,params?:any[])=>Promise<any[]>, id:number, role:string, status:string, secret=process.env.ENCRYPTION_KEY||'') {
  const fields = metadata.get('user')!.fields.filter(field => sealedFields.wallet.includes(field.name))
  const [user] = await query(`SELECT ${fields.map(field=>'"'+(field.dbName||field.name)+'" AS "'+field.name+'"').join(',')} FROM users WHERE id=$1 FOR UPDATE`,[id])
  if (!user || !user.username.startsWith('recovery-') || !['admin','user'].includes(role) || !['active','banned'].includes(status)) throw new FinancialIntegrityError()
  const [count] = await query('SELECT count(*)::int count FROM balance_logs WHERE user_id=$1',[id])
  if (count.count || !new Prisma.Decimal(user.balance).isZero()) throw new FinancialIntegrityError()
  for(const field of ['balance','affBalance','hostingBalance'])user[field]=new Prisma.Decimal(user[field])
  const value={...facts('wallet',user),ledger:{count:'0',hash:createHash('sha256').update('').digest('hex')}}
  const [seal]=await query("SELECT signature FROM financial_integrity_seals WHERE kind='wallet' AND record_id=$1",[String(id)])
  if(!matches(seal?.signature,signature('wallet',String(id),value,secret)))throw new FinancialIntegrityError()
  await query('UPDATE users SET role=$2,status=$3 WHERE id=$1',[id,role,status])
  await query("UPDATE financial_integrity_seals SET signature=$2,updated_at=NOW() WHERE kind='wallet' AND record_id=$1",[String(id),signature('wallet',String(id),{...value,role,status},secret)])
}
export async function prepareRecoveryCheckoutStatuses(database: string, secret: string, legacy: boolean) {
  const url = new URL(process.env.DATABASE_URL || ''); url.pathname = '/' + database
  const pool = new Pool({ connectionString: url.href, max: 1 }), client = await pool.connect()
  const model = metadata.get('checkoutOrder')!
  const projection = model.fields.filter(field => field.kind !== 'object').map(field => '"' + (field.dbName || field.name) + '"' +
    (field.type === 'DateTime' ? " AT TIME ZONE 'UTC'" : '') + ' AS "' + field.name + '"').join(',')
  try {
    await client.query('BEGIN')
    const rows = (await client.query(`SELECT ${projection} FROM checkout_orders WHERE status IN ('pending','paid','fulfilling','partial','refund_pending') FOR UPDATE`)).rows
    for (const row of rows) {
      const id = recordId('checkout', row)
      if (!legacy) {
        const { rows: [seal] } = await client.query("SELECT signature FROM financial_integrity_seals WHERE kind='checkout' AND record_id=$1", [id])
        if (!matches(seal?.signature, signature('checkout', id, facts('checkout', row), secret))) throw new FinancialIntegrityError()
      }
      await client.query("UPDATE checkout_orders SET status='recovery_review' WHERE id=$1", [id])
      if (!legacy) await client.query("UPDATE financial_integrity_seals SET signature=$2,updated_at=NOW() WHERE kind='checkout' AND record_id=$1",
        [id, signature('checkout', id, facts('checkout', { ...row, status: 'recovery_review' }), secret)])
    }
    await client.query('COMMIT')
  } catch (error) { await client.query('ROLLBACK'); throw error }
  finally { client.release(); await pool.end() }
}
type State = { rows: Map<string, { kind: Kind; row: any }>; wallets: Map<number, Prisma.Decimal>; createdLogs: Set<number> }
const writes = new Set(['create', 'createMany', 'createManyAndReturn', 'update', 'updateMany', 'updateManyAndReturn', 'upsert', 'delete', 'deleteMany'])
const reads = new Set(['findUnique', 'findUniqueOrThrow', 'findFirst', 'findFirstOrThrow', 'findMany'])
const summaries = new Set(['aggregate', 'groupBy', 'count'])

async function finalize(db: Db, state: State) {
  for (const [id, before] of state.wallets) {
    const user = await db.user.findUnique({ where: { id } })
    if (!user) continue // Authorized account deletion retains payment tombstones.
    const logs = await db.balanceLog.findMany({ where: { userId: id, id: { in: [...state.createdLogs] } }, orderBy: { id: 'asc' } })
    let current = before
    for (const log of logs) {
      if (!log.balanceBefore.equals(current) || !log.balanceAfter.minus(log.balanceBefore).equals(log.amount)) throw new FinancialIntegrityError()
      current = log.balanceAfter
    }
    if (!user.balance.equals(current) || user.balance.lessThan(0) || user.balance.greaterThan('99999999.99')) throw new FinancialIntegrityError()
  }
  for (const { kind, row } of [...state.rows.values()].filter(value => value.kind !== 'wallet')) {
    const current = await (db as any)[models[kind]].findUnique({ where: where(kind, row) })
    if (current) await seal(db, kind, current)
    else await db.financialIntegritySeal.deleteMany({ where: { kind, recordId: recordId(kind, row) } })
  }
  for (const id of state.wallets.keys()) {
    const user = await db.user.findUnique({ where: { id } })
    if (user) await seal(db, 'wallet', user)
    else await db.financialIntegritySeal.deleteMany({ where: { kind: 'wallet', recordId: String(id) } })
  }
}
async function lockRows(db: Db, kind: Kind, rows: any[], mode: 'UPDATE' | 'SHARE') {
  if (!rows.length) return
  const model = metadata.get(models[kind])!
  const ids = kind === 'renewal' ? ['userId', 'requestKey'] : kind === 'deletedReceipt' ? ['providerId', 'tradeHash'] : ['id']
  const conditions = rows.map(row => Prisma.sql`(${Prisma.join(ids.map(id => Prisma.sql`${Prisma.raw('"' + (model.fields.find(field => field.name === id)!.dbName || id) + '"')} = ${row[id]}`), ' AND ')})`)
  await db.$queryRaw(Prisma.sql`SELECT ${Prisma.join(ids.map(id => Prisma.raw('"' + (model.fields.find(field => field.name === id)!.dbName || id) + '"')))} FROM ${Prisma.raw('"' + model.dbName + '"')} WHERE ${Prisma.join(conditions, ' OR ')} ORDER BY ${Prisma.join(ids.map(id => Prisma.raw('"' + (model.fields.find(field => field.name === id)!.dbName || id) + '"')))} FOR ${Prisma.raw(mode)}`)
}
async function trackCascade(db: Db, state: State, kind: Kind, rows: any[]) {
  // Track only children of the exact authorized deletion. Never sweep unrelated
  // orphaned seals, which could otherwise hide a database-side deletion.
  const cascades: Partial<Record<Kind, Array<[Kind, string]>>> = {
    wallet: [['ledger', 'userId'], ['recharge', 'userId'], ['renewal', 'userId'], ['affLedger', 'userId'], ['hostingLedger', 'userId'], ['poolOrder', 'userId'], ['adjustment', 'userId']],
    instance: [['billing', 'instanceId']], recharge: [['late', 'rechargeId']]
  }
  for (const [childKind, field] of cascades[kind] || []) {
    const children = await (db as any)[models[childKind]].findMany({ where: { [field]: { in: rows.map(row => row.id) } } })
    for (const row of children) {
      const key = `${childKind}:${recordId(childKind, row)}`
    if (!state.rows.has(key)) await verify(db, childKind, row)
      state.rows.set(key, { kind: childKind, row })
    }
    if (children.length) await trackCascade(db, state, childKind, children)
  }
}
const nullableFinancialRelations: Record<string, Array<[Kind, string]>> = {
  user: [['adjustment', 'reviewedByUserId']], balanceLog: [['adjustment', 'balanceLogId']],
  packagePlan: [['instance', 'packagePlanId'], ['poolPrice', 'shadowPlanId']], affCode: [['affLedger', 'affCodeId']], mailSubscription: [['affLedger', 'mailSubscriptionId']]
}
async function trackNullableRelations(db: Db, state: State, model: string, rows: any[]) {
  for (const [kind, field] of nullableFinancialRelations[model] || []) {
    const children = await (db as any)[models[kind]].findMany({ where: { [field]: { in: rows.map(row => row.id) } } })
    await lockRows(db, kind, children, 'UPDATE')
    for (const row of children) {
      const key = `${kind}:${recordId(kind, row)}`
      if (!state.rows.has(key)) await verify(db, kind, row)
      state.rows.set(key, { kind, row })
    }
  }
}
function includeFinancialFacts(model: string, args: any): any {
  const result = { ...args }
  for (const mode of ['select', 'include']) if (args[mode]) {
    result[mode] = { ...args[mode] }
    for (const relation of metadata.get(model)?.fields.filter(field => field.kind === 'object') || []) {
      const chosen = args[mode][relation.name]
      if (!chosen) continue
      const child = relation.type[0].toLowerCase() + relation.type.slice(1)
      result[mode][relation.name] = includeFinancialFacts(child, chosen === true ? {} : chosen)
    }
  }
  if (kinds.has(model) && args.select) {
    result.select = { ...result.select, ...Object.fromEntries(metadata.get(model)!.fields.filter(field => field.kind !== 'object').map(field => [field.name, true])) }
  }
  delete result.omit
  return result
}
async function verifyIncludedFacts(db: Db, state: State, model: string, row: any) {
  if (!row) return
  if (Array.isArray(row)) { for (const item of row) await verifyIncludedFacts(db, state, model, item); return }
  const kind = kinds.get(model)
  if (kind && !state.rows.has(`${kind}:${recordId(kind, row)}`) && !(kind === 'wallet' && state.wallets.has(row.id))) await verify(db, kind, row)
  for (const relation of metadata.get(model)?.fields.filter(field => field.kind === 'object') || []) if (row[relation.name]) {
    await verifyIncludedFacts(db, state, relation.type[0].toLowerCase() + relation.type.slice(1), row[relation.name])
  }
}
function projectIncludedFacts(model: string, args: any, result: any): any {
  if (!result) return result
  if (Array.isArray(result)) return result.map(row => projectIncludedFacts(model, args, row))
  return Object.fromEntries(Object.entries(result).filter(([key]) => args.select ? !!args.select[key] : !args.omit?.[key]).map(([key, value]) => {
    const relation = metadata.get(model)?.fields.find(field => field.name === key && field.kind === 'object')
    const nested = args.select?.[key] ?? args.include?.[key]
    return [key, relation && nested ? projectIncludedFacts(relation.type[0].toLowerCase() + relation.type.slice(1), nested === true ? {} : nested, value) : value]
  }))
}
function transactionProxy(db: Db, state: State): Db {
  const cache = new Map<string, any>()
  return new Proxy(db, { get(target, property) {
    const kind = kinds.get(String(property))
    if (!kind) {
      const value = Reflect.get(target, property)
      if (nullableFinancialRelations[String(property)] || ['package', 'hostMachineGroup', 'hostRegionGroup'].includes(String(property))) return new Proxy(value, { get(delegate, op) {
        if (op === 'delete' || op === 'deleteMany') return async (args: any) => {
          const rows = await delegate.findMany({ where: args.where })
          await trackNullableRelations(db, state, String(property), rows)
          const children = String(property) === 'package' ? await db.packagePlan.findMany({ where: { packageId: { in: rows.map((row: any) => row.id) } } })
            : ['hostMachineGroup', 'hostRegionGroup'].includes(String(property)) ? await db.hostPoolPrice.findMany({ where: { [property === 'hostMachineGroup' ? 'machineGroupId' : 'regionGroupId']: { in: rows.map((row: any) => row.id) } } }) : []
          const childKind = property === 'package' ? 'plan' : 'poolPrice'
          for (const row of children) {
            if (!state.rows.has(`${childKind}:${row.id}`)) await verify(db, childKind, row)
            state.rows.set(`${childKind}:${row.id}`, { kind: childKind, row })
          }
          if (children.length && property === 'package') await trackNullableRelations(db, state, 'packagePlan', children)
          return delegate[op](args)
        }
        const method = Reflect.get(delegate, op); return typeof method === 'function' ? method.bind(delegate) : method
      } })
      return typeof value === 'function' ? value.bind(target) : value
    }
    if (cache.has(String(property))) return cache.get(String(property))
    const model = (target as any)[property]
    const overrides = new Map<PropertyKey, any>()
    const proxy = new Proxy(model, { get(delegate, operation) {
      if (overrides.has(operation)) return overrides.get(operation)
      const method = Reflect.get(delegate, operation)
      if (typeof method === 'function' && summaries.has(String(operation))) return async (args: any = {}) => {
        const rows = await model.findMany({ where: args.where })
        for (const row of rows) if (!state.rows.has(`${kind}:${recordId(kind, row)}`) && !(kind === 'wallet' && state.wallets.has(row.id))) await verify(db, kind, row)
        return method.call(delegate, args)
      }
      if (typeof method === 'function' && reads.has(String(operation))) return async (args: any = {}) => {
        const query = includeFinancialFacts(models[kind], args)
        let result: any
        for (let attempt = 0; ; attempt++) {
          result = await method.call(delegate, query)
          try {
            if (!result && ['findUnique', 'findUniqueOrThrow'].includes(String(operation))) {
              const identity = kind === 'renewal' ? args.where.userId_requestKey : kind === 'deletedReceipt' ? args.where.providerId_tradeHash : args.where
              if (identity && (identity.id !== undefined || kind === 'renewal' || kind === 'deletedReceipt')) {
                const lost = await db.financialIntegritySeal.findUnique({ where: { kind_recordId: { kind, recordId: recordId(kind, identity) } } })
                if (lost && !state.rows.has(`${kind}:${lost.recordId}`)) throw new FinancialIntegrityError()
              }
            }
            await verifyIncludedFacts(db, state, models[kind], result)
            break
          } catch (error) {
            // At read committed a legitimate writer can commit between the
            // row and seal reads. Re-read once, never re-sign failed evidence.
            if (!(error instanceof FinancialIntegrityError) || attempt >= 1) throw error
          }
        }
        return projectIncludedFacts(models[kind], args, result)
      }
      if (typeof method !== 'function' || !writes.has(String(operation))) return typeof method === 'function' ? method.bind(delegate) : method
      return async (args: any) => {
        const op = String(operation)
        assertNoNestedFinancialWrites(String(property), args)
        if (op === 'createMany' || op === 'createManyAndReturn') throw new FinancialIntegrityError()
        if (kind === 'wallet' && !['create', 'upsert', 'delete', 'deleteMany'].includes(op) && !sealedFields.wallet.some(field => Object.hasOwn(args.data || {}, field))) return method.call(delegate, args)
        if (kind === 'instance' && !['create', 'upsert', 'delete', 'deleteMany'].includes(op) && !Object.keys(facts('instance', {})).some(field => Object.hasOwn(args.data || {}, field))) return method.call(delegate, args)
        const candidates = op === 'create' ? [] : ['upsert', 'update', 'delete'].includes(op)
          ? [await model.findUnique({ where: args.where })].filter(Boolean) : await model.findMany({ where: args.where })
        await lockRows(db, kind, candidates, 'UPDATE')
        const before: any[] = []
        for (const row of candidates) { const current = await model.findUnique({ where: where(kind, row) }); if (current) before.push(current) }
        if (op === 'delete' || op === 'deleteMany') {
          await trackCascade(db, state, kind, before)
          await trackNullableRelations(db, state, String(property), before)
        }
        if (kind === 'ledger') {
          const ids = [...new Set([...before.map((row: any) => row.userId), ...(args.data?.userId ? [args.data.userId] : [])])] as number[]
          await lockRows(db, 'wallet', ids.sort((a,b)=>a-b).map(id=>({id})), 'UPDATE')
          for (const id of ids) if (!state.wallets.has(id)) {
            const user = await db.user.findUniqueOrThrow({ where: { id } })
            await verify(db, 'wallet', user)
            state.wallets.set(id, user.balance)
          }
        }
        for (const row of before) {
          const key = `${kind}:${recordId(kind, row)}`
          if (!state.rows.has(key)) await verify(db, kind, row)
          state.rows.set(key, { kind, row })
          if (kind === 'wallet' && !state.wallets.has(row.id)) state.wallets.set(row.id, row.balance)
        }
        const result = await method.call(delegate, args)
        if (kind === 'ledger' && !['delete', 'deleteMany'].includes(op)) for (const row of before) {
          if (state.createdLogs.has(row.id)) continue
          const current = await model.findUnique({ where: { id: row.id } })
          if (current && ['userId', 'amount', 'balanceBefore', 'balanceAfter', 'orderId'].some(field => JSON.stringify(canonical(current[field])) !== JSON.stringify(canonical(row[field])))) throw new FinancialIntegrityError()
        }
        const rows = ['create', 'update', 'upsert'].includes(op) ? [await model.findUnique({ where: op === 'create' ? where(kind, result) : args.where })]
          : op === 'createManyAndReturn' || op === 'updateManyAndReturn' ? result : []
        if (kind === 'ledger' && rows.some((row: any) => row && !before.some((old: any) => old.id === row.id) && !state.wallets.has(row.userId))) throw new FinancialIntegrityError()
        for (const row of rows.filter(Boolean)) {
          state.rows.set(`${kind}:${recordId(kind, row)}`, { kind, row })
          if (kind === 'wallet' && !before.length) state.wallets.set(row.id, row.balance)
          if (kind === 'ledger' && !before.some((old: any) => old.id === row.id)) {
            state.createdLogs.add(row.id)
            if (!state.wallets.has(row.userId)) {
              const user = await db.user.findUniqueOrThrow({ where: { id: row.userId } })
              await verify(db, 'wallet', user)
              state.wallets.set(row.userId, user.balance)
            }
          }
        }
        return result
      }
    }, set(_delegate, operation, value) { overrides.set(operation, value); return true } })
    cache.set(String(property), proxy)
    return proxy
  } }) as Db
}

// One integration point covers legacy money writers without bypassable hooks
// scattered across recharge, purchase, renewals, refunds, gifts and transfers.
export function protectFinancialClient(raw: PrismaClient): PrismaClient {
  const cache = new Map<string, any>()
  const nativeTransaction = (...args: any[]) => (raw.$transaction as any)(...args)
  const overrides = new Map<PropertyKey, any>()
  const transaction = async (action: (tx: Db) => Promise<any>, options?: any) => nativeTransaction(async (db: Db) => {
    const state: State = { rows: new Map(), wallets: new Map(), createdLogs: new Set() }
    const value = await action(transactionProxy(db, state))
    await finalize(db, state)
    return value
  }, options)
  return new Proxy(raw, { get(target, property) {
    if (overrides.has(property)) return overrides.get(property)
    if (property === '$transaction') return (action: any, options: any) => {
      if (!enabled) return nativeTransaction(action, options)
      if (Array.isArray(action)) {
        if (action.some(value => value?.financialOperation)) throw new FinancialIntegrityError()
        return nativeTransaction(action, options)
      }
      return transaction(action, options)
    }
    if (!kinds.has(String(property)) && !nullableFinancialRelations[String(property)] && !['package', 'hostMachineGroup', 'hostRegionGroup'].includes(String(property))) { const value = Reflect.get(target, property); return typeof value === 'function' ? value.bind(target) : value }
    if (cache.has(String(property))) return cache.get(String(property))
    const model = (target as any)[property]
    const methods = new Map<PropertyKey, any>()
    const proxy = new Proxy(model, { get(delegate, operation) {
      if (methods.has(operation)) return methods.get(operation)
      const value = Reflect.get(delegate, operation)
      if (typeof value !== 'function') return value
      return (...args: any[]) => {
        if (!enabled || !(writes.has(String(operation)) || reads.has(String(operation)) || summaries.has(String(operation)))) return value.apply(delegate, args)
        // Prisma operations are lazy. An unsupported array transaction must
        // fail before a protected operation can commit outside that array.
        let pending: Promise<any> | undefined
        const run = () => pending ??= transaction(tx => (tx as any)[property][operation](...args), {
          isolationLevel: writes.has(String(operation)) ? Prisma.TransactionIsolationLevel.ReadCommitted : Prisma.TransactionIsolationLevel.RepeatableRead
        })
        return { financialOperation: true, [Symbol.toStringTag]: 'PrismaPromise', then: (ok: any, fail: any) => run().then(ok, fail),
          catch: (fail: any) => run().catch(fail), finally: (action: any) => run().finally(action) }
      }
    }, set(_delegate, operation, value) { methods.set(operation, value); return true } })
    cache.set(String(property), proxy)
    return proxy
  }, set(_target, property, value) { overrides.set(property, value); return true } }) as PrismaClient
}
