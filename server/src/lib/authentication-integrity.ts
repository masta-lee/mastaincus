import { createHmac, timingSafeEqual, createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import { Prisma, type PrismaClient } from '@prisma/client'
import { readFile, open, rename, unlink } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import { dirname } from 'node:path'
import { financialIntegrityStatePath } from './financial-integrity.js'
import { Pool, type PoolClient } from 'pg'

type Db = Prisma.TransactionClient
// Versioned independently from financial v1: old money seals and signed OSS
// archives retain their original facts. Unsealed legacy sessions are retired.
const fields: Record<string, string[]> = {
  user: ['id','username','email','passwordHash','role','status','deletionIntent','twoFactorEnabled','twoFactorSecret','twoFactorRecoveryCodes'],
  refreshToken: ['id','token','userId','username','role','createdAt','expiresAt','lastActiveAt'],
  tokenInvalidation: ['id','userId','sessionId','invalidatedAt','createdAt'],
  publicApiToken: ['id','userId','tokenPrefix','tokenHash','scopes','revokedAt','expiresAt','createdAt'],
  userOAuthBinding: ['id','userId','provider','providerUserId','accessToken','refreshToken','createdAt'],
  oAuthClientApp: ['id','clientId','clientSecretHash','redirectUris','scopes','enabled','createdByUserId','createdAt'],
  oAuthGrant: ['id','appId','userId','scopes','revokedAt','createdAt'],
  oAuthAuthorizationCode: ['id','appId','userId','codeHash','redirectUri','scopes','expiresAt','usedAt','createdAt'],
  oAuthAccessToken: ['id','appId','userId','grantId','tokenPrefix','tokenHash','scopes','revokedAt','expiresAt','createdAt'],
  oAuthRefreshToken: ['id','appId','userId','grantId','tokenPrefix','tokenHash','scopes','revokedAt','expiresAt','createdAt'],
  notificationChannel: ['id','userId','type','config','enabled','isGlobal','alertCategory','createdAt'],
  lotteryNotificationConfig: ['id','lotteryId','type','config','enabled','notifyBalance','notifyInstance','createdAt'],
  storageConfig: ['id','userId','type','host','port','username','password','basePath','extra','createdAt'],
  oAuthConfig: ['id','provider','clientId','clientSecret','enabled','createdAt'],
  userTelegramBinding: ['id','userId','telegramUserId','notifyEnabled','boundAt'],
  telegramBindToken: ['id','userId','tokenHash','expiresAt','usedAt','createdAt'],
  sshKey: ['id','userId','publicKey','fingerprint','createdAt'],
  operationVerification: ['id','userId','operationType','code','channel','resourceId','resourceType','verified','verifiedAt','attempts','expiresAt','createdAt'],
  emailVerificationCode: ['id','email','purpose','code','expiresAt','attempts','consumedAt','createdAt'],
  systemConfig: ['id','key','value','type'],
  hostAgent: ['id','hostId','agentId','secretHash','secretEncrypted','installTokenHash','installTokenExpiresAt','installTokenUsedAt','installTokenKeepsIdentity','enabled','createdAt']
}
const metadata = new Map(Prisma.dmmf.datamodel.models.map(model => [model.name[0].toLowerCase() + model.name.slice(1), model]))
let enabled = false
export class AuthenticationIntegrityError extends Error { constructor() { super('AUTHENTICATION_INTEGRITY_INVALID') } }
function canonical(value: any): any {
  if (value instanceof Date) return value.toISOString()
  if (Array.isArray(value)) return value.map(canonical)
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]))
  return value
}
function signature(model: string, row: any, key = process.env.ENCRYPTION_KEY): string {
  if (!key || key.length < 16) throw new AuthenticationIntegrityError()
  return createHmac('sha256', key).update('payincus/authentication-integrity/v1\n').update(model).update('\n')
    .update(JSON.stringify(canonical(Object.fromEntries(fields[model].map(key => [key, row[key]]))))).digest('hex')
}
async function verify(db: Db, model: string, row: any) {
  const seal = await db.authenticationIntegritySeal.findUnique({ where: { model_recordId: { model, recordId: String(row.id) } } })
  const expected = signature(model, row)
  if (!seal || !/^[a-f0-9]{64}$/.test(seal.signature) || !timingSafeEqual(Buffer.from(seal.signature, 'hex'), Buffer.from(expected, 'hex'))) throw new AuthenticationIntegrityError()
}
async function verifyNoDeletedEvidence(db: Db, state: State, model: string) {
  const table=metadata.get(model)!.dbName!
  const lost=await db.$queryRaw<Array<{recordId:string}>>(Prisma.sql`SELECT s.record_id AS "recordId" FROM authentication_integrity_seals s LEFT JOIN ${Prisma.raw('"'+table+'"')} t ON t.id::text=s.record_id WHERE s.model=${model} AND t.id IS NULL`)
  if(lost.some(row=>!state.has(`${model}:${row.recordId}`)))throw new AuthenticationIntegrityError()
}
async function seal(db: Db, model: string, row: any) {
  const data = { model, recordId: String(row.id), signature: signature(model, row) }
  await db.authenticationIntegritySeal.upsert({ where: { model_recordId: { model, recordId: data.recordId } }, create: data, update: { signature: data.signature } })
}
export async function initializeAuthenticationIntegrity(raw: PrismaClient) {
  const path = financialIntegrityStatePath(), marker = JSON.parse(await readFile(path, 'utf8'))
  const expected = baselineSignature()
  if (marker.authenticationSignature !== undefined && marker.authenticationSignature !== expected) throw new AuthenticationIntegrityError()
  await raw.$transaction(async tx => {
    await tx.$queryRaw`SELECT true FROM pg_advisory_xact_lock(4130, 2)`
    const baseline = await tx.authenticationIntegritySeal.findUnique({ where: { model_recordId: { model: 'baseline', recordId: 'v1' } } })
    if (!baseline) {
      // Never promote database-controlled pre-upgrade bearer rows to trusted
      // sessions. Credentials stay unchanged; users authenticate again.
      if (marker.authenticationSignature || await tx.authenticationIntegritySeal.count()) throw new AuthenticationIntegrityError()
      for (const model of ['refreshToken','publicApiToken','oAuthAuthorizationCode','oAuthAccessToken','oAuthRefreshToken','operationVerification','emailVerificationCode','telegramBindToken']) await (tx as any)[model].deleteMany()
      const invalidatedAt = Math.floor(Date.now()/1000)
      for (const user of await tx.user.findMany({ select: { id: true } })) await tx.tokenInvalidation.upsert({
        where: { userId_sessionId: { userId: user.id, sessionId: '__USER_LEVEL__' } },
        create: { userId: user.id, sessionId: '__USER_LEVEL__', invalidatedAt }, update: { invalidatedAt }
      })
      for (const model of Object.keys(fields)) for (const row of await (tx as any)[model].findMany()) await seal(tx, model, row)
      await tx.authenticationIntegritySeal.create({ data: { model: 'baseline', recordId: 'v1', signature: baselineSignature() } })
    } else {
      if (baseline.signature !== baselineSignature()) throw new AuthenticationIntegrityError()
      for (const model of Object.keys(fields)) for (const row of await (tx as any)[model].findMany()) await verify(tx, model, row)
      for (const receipt of await tx.authenticationIntegritySeal.findMany({ where: { model: { not: 'baseline' } } })) {
        if (!fields[receipt.model] || !await (tx as any)[receipt.model].findUnique({ where: { id: Number(receipt.recordId) } })) throw new AuthenticationIntegrityError()
      }
    }
  }, { maxWait:30000, timeout: 120000, isolationLevel: Prisma.TransactionIsolationLevel.Serializable })
  if (!marker.authenticationSignature) {
    const temporary = path + '.' + randomUUID() + '.auth-new', file = await open(temporary, 'wx', 0o600)
    try {
      await file.writeFile(JSON.stringify({ ...marker, authenticationSignature: expected })); await file.sync()
    } finally { await file.close() }
    try {
      await rename(temporary, path)
      if(process.platform!=='win32'){const directory=await open(dirname(path),'r');try{await directory.sync()}finally{await directory.close()}}
    } finally { await unlink(temporary).catch(() => {}) }
  }
  enabled = true
}
function baselineSignature(key = process.env.ENCRYPTION_KEY) {
  if (!key || key.length < 16) throw new AuthenticationIntegrityError()
  return createHmac('sha256', key).update('payincus/authentication-integrity/baseline/v1').digest('hex')
}
export async function verifyAuthenticationDatabaseSeals(client: PoolClient, key: string, required = false) {
  const exists = (await client.query("SELECT to_regclass('public.authentication_integrity_seals') IS NOT NULL present")).rows[0].present
  if (!exists) { if (required) throw new AuthenticationIntegrityError(); return }
  const receipts = (await client.query('SELECT model,record_id,signature FROM authentication_integrity_seals')).rows
  if (!receipts.length) { if (required) throw new AuthenticationIntegrityError(); return }
  const index = new Map(receipts.map(row => [row.model + ':' + row.record_id, row.signature]))
  if (index.get('baseline:v1') !== baselineSignature(key)) throw new AuthenticationIntegrityError()
  index.delete('baseline:v1')
  for (const model of Object.keys(fields)) {
    const schema = metadata.get(model)!, columns = schema.fields.filter(field => fields[model].includes(field.name))
    const query = columns.map(field => '"'+(field.dbName || field.name)+'"'+(field.type === 'DateTime' ? " AT TIME ZONE 'UTC'" : '')+' AS "'+field.name+'"').join(',')
    for (const row of (await client.query('SELECT '+query+' FROM "'+schema.dbName+'"')).rows) {
      if (index.get(`${model}:${row.id}`) !== signature(model, row, key)) throw new AuthenticationIntegrityError()
      index.delete(`${model}:${row.id}`)
    }
  }
  if (index.size) throw new AuthenticationIntegrityError()
}
export async function verifyRecoveryAuthenticationActor(id: number) {
  const marker=JSON.parse(await readFile(financialIntegrityStatePath(),'utf8'))
  if(marker.authenticationSignature!==baselineSignature())throw new AuthenticationIntegrityError()
  const pool=new Pool({connectionString:process.env.DATABASE_URL,max:1})
  const client=await pool.connect()
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
    const columns=metadata.get('user')!.fields.filter(field=>fields.user.includes(field.name))
    const [row]=(await client.query('SELECT '+columns.map(field=>'"'+(field.dbName||field.name)+'" AS "'+field.name+'"').join(',')+' FROM users WHERE id=$1',[id])).rows
    const [receipt]=(await client.query("SELECT signature FROM authentication_integrity_seals WHERE model='user' AND record_id=$1",[String(id)])).rows
    if(!row||receipt?.signature!==signature('user',row)||row.role!=='admin'||row.status!=='active'||row.deletionIntent!==null)throw new AuthenticationIntegrityError()
    return row as {id:number;username:string;passwordHash:string;role:string;status:string;twoFactorEnabled:boolean;twoFactorSecret:string|null}
  } finally { await client.query('ROLLBACK');client.release();await pool.end() }
}
// The restore worker has authenticated the complete archive before any SQL
// edits. Only its disposable staging database can create the new baseline.
export async function resealRestoredAuthentication(database: string, key: string, taskId: string) {
  if (!/^incudal_restore_[a-f0-9]{32}$/.test(database) || database !== 'incudal_restore_'+taskId.replace(/-/g,'')) throw new AuthenticationIntegrityError()
  const url = new URL(process.env.DATABASE_URL || ''); url.pathname = '/'+database
  const pool = new Pool({ connectionString: url.href, max: 1 }), client = await pool.connect()
  try {
    await client.query('BEGIN')
    if (!(await client.query("SELECT to_regclass('public.authentication_integrity_seals') IS NOT NULL present")).rows[0].present) { await client.query('ROLLBACK'); return }
    await client.query('DELETE FROM authentication_integrity_seals')
    // Retained legacy secrets must be authenticated before the staging seal
    // becomes the new live baseline, otherwise the next startup cannot safely
    // distinguish old plaintext from a database-side replacement.
    const { SENSITIVE_CONFIG_KEYS } = await import('../db/system-config.js')
    const encryptionKey=createHash('sha256').update(key).digest()
    const protect=(value:string)=>{
      if(/^[a-f0-9]{32}:[a-f0-9]{32}:/i.test(value)){
        const [iv,tag,data]=value.split(':');const decipher=createDecipheriv('aes-256-gcm',encryptionKey,Buffer.from(iv,'hex'));decipher.setAuthTag(Buffer.from(tag,'hex'));decipher.update(Buffer.from(data,'hex'));decipher.final();return value
      }
      const iv=randomBytes(16),cipher=createCipheriv('aes-256-gcm',encryptionKey,iv),bytes=Buffer.concat([cipher.update(value,'utf8'),cipher.final()])
      return iv.toString('hex')+':'+cipher.getAuthTag().toString('hex')+':'+bytes.toString('hex')
    }
    for(const row of (await client.query('SELECT id,key,value FROM system_configs')).rows)if(SENSITIVE_CONFIG_KEYS.has(row.key)&&row.value)await client.query('UPDATE system_configs SET value=$2 WHERE id=$1',[row.id,protect(row.value)])
    for(const row of (await client.query('SELECT id,client_secret FROM oauth_configs')).rows)if(row.client_secret)await client.query('UPDATE oauth_configs SET client_secret=$2 WHERE id=$1',[row.id,protect(row.client_secret)])
    for (const table of ['notification_channels','lottery_notification_configs']) for(const row of (await client.query('SELECT id,config FROM '+table)).rows){
      const config=typeof row.config==='string'?JSON.parse(row.config):row.config
      if(config?.version===1&&typeof config.sealed==='string')protect(config.sealed)
      else {if(!config||typeof config!=='object'||Array.isArray(config))throw new AuthenticationIntegrityError();await client.query('UPDATE '+table+' SET config=$2 WHERE id=$1',[row.id,{version:1,sealed:protect(JSON.stringify(config))}])}
    }
    for (const model of Object.keys(fields)) {
      const schema = metadata.get(model)!, columns = schema.fields.filter(field => fields[model].includes(field.name))
      const query = columns.map(field => '"'+(field.dbName || field.name)+'"'+(field.type === 'DateTime' ? " AT TIME ZONE 'UTC'" : '')+' AS "'+field.name+'"').join(',')
      for (const row of (await client.query('SELECT '+query+' FROM "'+schema.dbName+'"')).rows) await client.query('INSERT INTO authentication_integrity_seals(model,record_id,signature,updated_at) VALUES($1,$2,$3,NOW())', [model,String(row.id),signature(model,row,key)])
    }
    await client.query("INSERT INTO authentication_integrity_seals(model,record_id,signature,updated_at) VALUES('baseline','v1',$1,NOW())",[baselineSignature(key)])
    await client.query('COMMIT')
  } catch(error) { await client.query('ROLLBACK'); throw error }
  finally { client.release(); await pool.end() }
}
export async function updateRecoveryAuthentication(query: (sql:string,args?:any[])=>Promise<any[]>, id: number, key: string) {
  const table = await query("SELECT to_regclass('public.authentication_integrity_seals') IS NOT NULL present")
  if (!table[0]?.present) return
  const columns=metadata.get('user')!.fields.filter(field=>fields.user.includes(field.name))
  const [row]=await query('SELECT '+columns.map(field=>'"'+(field.dbName||field.name)+'"'+(field.type==='DateTime'?" AT TIME ZONE 'UTC'":'')+' AS "'+field.name+'"').join(',')+' FROM users WHERE id=$1',[id])
  if (!row || !row.username.startsWith('recovery-')) throw new AuthenticationIntegrityError()
  await query("INSERT INTO authentication_integrity_seals(model,record_id,signature,updated_at) VALUES('user',$1,$2,NOW()) ON CONFLICT(model,record_id) DO UPDATE SET signature=EXCLUDED.signature,updated_at=NOW()",[String(id),signature('user',row,key)])
}
const reads = new Set(['findUnique','findUniqueOrThrow','findFirst','findFirstOrThrow','findMany'])
const summaries = new Set(['aggregate','groupBy','count'])
export function authenticationIntegrityEnabled() { return enabled }
const writes = new Set(['create','createMany','createManyAndReturn','update','updateMany','updateManyAndReturn','upsert','delete','deleteMany'])
type State = Map<string, { model: string; id: number }>
function queryFacts(model: string, args: any) {
  const query = { ...args }
  for (const mode of ['select','include']) if (args[mode]) {
    query[mode] = { ...args[mode] }
    for (const field of metadata.get(model)?.fields.filter(field => field.kind === 'object') || []) if (args[mode][field.name]) {
      const chosen = args[mode][field.name], child = field.type[0].toLowerCase() + field.type.slice(1)
      query[mode][field.name] = queryFacts(child, chosen === true ? {} : chosen)
    }
  }
  if (fields[model] && args.select) query.select = { ...query.select, ...Object.fromEntries(fields[model].map(key => [key, true])) }
  delete query.omit
  return query
}
function project(model: string, args: any, result: any): any {
  if (!result) return result
  if (Array.isArray(result)) return result.map(row => project(model, args, row))
  return Object.fromEntries(Object.entries(result).filter(([key]) => args.select ? !!args.select[key] : !args.omit?.[key]).map(([key, value]) => {
    const relation = metadata.get(model)?.fields.find(field => field.name === key && field.kind === 'object'), choice = args.select?.[key] ?? args.include?.[key]
    return [key, relation && choice ? project(relation.type[0].toLowerCase() + relation.type.slice(1), choice === true ? {} : choice, value) : value]
  }))
}
async function verifyResult(db: Db, state: State, model: string, result: any): Promise<void> {
  if (!result) return
  if (Array.isArray(result)) { for (const row of result) await verifyResult(db, state, model, row); return }
  if (fields[model] && !state.has(`${model}:${result.id}`)) await verify(db, model, result)
  for (const field of metadata.get(model)?.fields.filter(field => field.kind === 'object') || []) if (result[field.name]) await verifyResult(db, state, field.type[0].toLowerCase() + field.type.slice(1), result[field.name])
}
async function rememberCascades(db: Db, state: State, model: string, rows: any[]) {
  const children = model === 'user' ? Object.keys(fields).filter(key => metadata.get(key)?.fields.some(field => field.name === 'userId' || key === 'oAuthClientApp' && field.name === 'createdByUserId')).map(key => [key, key === 'oAuthClientApp' ? 'createdByUserId' : 'userId'])
    : model === 'oAuthClientApp' ? ['oAuthGrant','oAuthAuthorizationCode','oAuthAccessToken','oAuthRefreshToken'].map(key => [key, 'appId'])
    : model === 'host' ? [['hostAgent','hostId']] : model === 'lottery' ? [['lotteryNotificationConfig','lotteryId']] : []
  for (const [child, foreign] of children) for (const row of await (db as any)[child].findMany({ where: { [foreign]: { in: rows.map(row => row.id) } } })) {
    if (!state.has(`${child}:${row.id}`)) await verify(db, child, row)
    state.set(`${child}:${row.id}`, { model: child, id: row.id })
  }
  if (model === 'oAuthGrant') for (const child of ['oAuthAccessToken','oAuthRefreshToken']) for (const row of await (db as any)[child].findMany({ where: { grantId: { in: rows.map(row => row.id) } } })) {
    if (!state.has(`${child}:${row.id}`)) await verify(db, child, row)
    state.set(`${child}:${row.id}`, { model: child, id: row.id })
  }
}
function wrappedTransaction(db: Db, state: State): Db {
  return new Proxy(db, { get(target, property) {
    const model = String(property), delegate = (target as any)[property]
    if (!fields[model]) {
      if(metadata.has(model)&&delegate)return new Proxy(delegate,{get(object,operation){
        const method=object[operation]
        if(typeof method!=='function')return method
        if(reads.has(String(operation)))return async(args:any={})=>{const result=await method.call(object,queryFacts(model,args));await verifyResult(db,state,model,result);return project(model,args,result)}
        if(writes.has(String(operation)))return async(args:any)=>{
          assertNoNestedWrites(model,args)
          if(['host','lottery'].includes(model)&&['delete','deleteMany'].includes(String(operation)))await rememberCascades(db,state,model,await object.findMany({where:args.where}))
          return method.call(object,args)
        }
        return method.bind(object)
      }})
      return typeof delegate === 'function' ? delegate.bind(target) : delegate
    }
    return new Proxy(delegate, { get(object, operation) {
      const method = object[operation], op = String(operation)
      if (typeof method !== 'function') return method
      if (summaries.has(op)) return async (args: any = {}) => {
        await verifyNoDeletedEvidence(db,state,model)
        await verifyResult(db, state, model, await object.findMany({ where: args.where }))
        return method.call(object, args)
      }
      if (reads.has(op)) return async (args: any = {}) => {
        for (let attempt = 0; ; attempt++) {
          const value = await method.call(object, queryFacts(model, args))
          try {
            if(!value&&['findUnique','findUniqueOrThrow'].includes(op))await verifyNoDeletedEvidence(db,state,model)
            if (!value && args.where?.id !== undefined && !state.has(`${model}:${args.where.id}`) && await db.authenticationIntegritySeal.findUnique({where:{model_recordId:{model,recordId:String(args.where.id)}}})) throw new AuthenticationIntegrityError()
            await verifyResult(db, state, model, value)
            return project(model, args, value)
          } catch (error) {
            // A legitimate writer can commit between row and seal reads at
            // read committed. Retry the entire pair once; never re-sign it.
            if (!(error instanceof AuthenticationIntegrityError) || attempt >= 1) throw error
          }
        }
      }
      if (!writes.has(op)) return method.bind(object)
      return async (args: any) => {
        if (op === 'createMany' || op === 'createManyAndReturn') throw new AuthenticationIntegrityError()
        assertNoNestedWrites(model,args)
        // Compound unique selectors are accepted by findUnique, not findMany.
        // Serialize creates/upserts so a concurrent insert cannot be promoted
        // to trusted data by the upsert's update branch without verification.
        if (op === 'upsert') await db.$queryRaw`SELECT true FROM pg_advisory_xact_lock(4130, hashtext(${model + ':' + JSON.stringify(canonical(args.where))}))`
        const rows = op === 'create' ? [] : ['upsert','update','delete'].includes(op)
          ? [await object.findUnique({ where: args.where })].filter(Boolean)
          : await object.findMany({ where: args.where })
        if (rows.length) {
          const table = metadata.get(model)!.dbName!
          await db.$queryRaw(Prisma.sql`SELECT id FROM ${Prisma.raw('"'+table+'"')} WHERE id IN (${Prisma.join(rows.map((row: any) => row.id))}) ORDER BY id FOR UPDATE`)
          for (const row of rows) {
            const current = await object.findUnique({ where: { id: row.id } })
            if (current && !state.has(`${model}:${row.id}`)) await verify(db, model, current)
            if(current)state.set(`${model}:${row.id}`, { model, id: row.id })
          }
        }
        if (op === 'delete' || op === 'deleteMany') await rememberCascades(db, state, model, rows)
        const query = queryFacts(model, args)
        // Preserve the original compare-and-set predicate while limiting a
        // bulk write to the exact rows whose seals were checked under lock.
        if (['updateMany','updateManyAndReturn','deleteMany'].includes(op)) query.where = { AND: [args.where || {}, { id: { in: rows.map((row: any) => row.id) } }] }
        const result = op === 'upsert' ? rows.length
          ? await object.update({ where: args.where, data: args.update, ...(query.select ? { select: query.select } : {}), ...(query.include ? { include: query.include } : {}) })
          : await object.create({ data: args.create, ...(query.select ? { select: query.select } : {}), ...(query.include ? { include: query.include } : {}) })
          : await method.call(object, query)
        if (op === 'create' || op === 'update' || op === 'upsert') {
          const row = await object.findUnique({ where: { id: result.id } })
          if (row) state.set(`${model}:${row.id}`, { model, id: row.id })
        }
        if (reads.has(op) || ['create','update','upsert','updateManyAndReturn'].includes(op)) await verifyResult(db,state,model,result)
        return project(model, args, result)
      }
    } })
  } }) as Db
}
function assertNoNestedWrites(model: string, args: any) {
  for (const data of [args.data,args.create,args.update]) for (const field of metadata.get(model)?.fields.filter(field => field.kind === 'object') || []) {
    const child = field.type[0].toLowerCase() + field.type.slice(1), nested = data?.[field.name]
    if (fields[child] && nested && ['create','createMany','update','updateMany','delete','deleteMany','upsert','connectOrCreate'].some(key => Object.hasOwn(nested, key))) throw new AuthenticationIntegrityError()
    for (const key of ['create','update','upsert','connectOrCreate']) if (nested?.[key]) for (const value of Array.isArray(nested[key]) ? nested[key] : [nested[key]]) assertNoNestedWrites(child,value.data?value:{data:value})
  }
}
function includesAuthentication(model: string, args: any): boolean {
  if (fields[model]) return true
  return (metadata.get(model)?.fields.filter(field => field.kind === 'object') || []).some(field => {
    const choice = args.select?.[field.name] ?? args.include?.[field.name]
    return choice && includesAuthentication(field.type[0].toLowerCase() + field.type.slice(1), choice === true ? {} : choice)
  })
}
export function protectAuthenticationClient(raw: PrismaClient): PrismaClient {
  const nativeTransaction=raw.$transaction.bind(raw)
  const overrides=new Map<PropertyKey,any>()
  const transaction = (action: (db: Db) => Promise<any>, options?: any) => nativeTransaction(async db => {
    const state: State = new Map(), result = await action(wrappedTransaction(db, state))
    for (const { model, id } of state.values()) {
      const row = await (db as any)[model].findUnique({ where: { id } })
      if (row) await seal(db, model, row)
      else await db.authenticationIntegritySeal.deleteMany({ where: { model, recordId: String(id) } })
    }
    return result
  }, {maxWait:5000,timeout:30000,...options})
  return new Proxy(raw, { get(target, property) {
    if(overrides.has(property))return overrides.get(property)
    if (property === '$transaction') return (action: any, options?: any) => {
      if (!enabled) return (nativeTransaction as any)(action, options)
      if (Array.isArray(action)) {
        if (action.some(value => value?.authenticationOperation)) throw new AuthenticationIntegrityError()
        return (nativeTransaction as any)(action, options)
      }
      return transaction(action, options)
    }
    const delegate = (target as any)[property]
    if(!delegate || typeof delegate!=='object'&&typeof delegate!=='function')return delegate
    if (!fields[String(property)]) {
      if (metadata.has(String(property)) && delegate) return new Proxy(delegate,{get(object,operation){
        const method=object[operation]
        if(typeof method!=='function')return method
        if(reads.has(String(operation)))return (...args:any[])=>{
          if(!enabled || !includesAuthentication(String(property),args[0]||{}))return method.apply(object,args)
          return transaction(db=>(db as any)[property][operation](args[0]||{}), {isolationLevel:Prisma.TransactionIsolationLevel.RepeatableRead})
        }
        if(writes.has(String(operation)))return (args:any)=>{
          if(enabled)assertNoNestedWrites(String(property),args)
          if(enabled&&['host','lottery'].includes(String(property))&&['delete','deleteMany'].includes(String(operation)))return transaction(db=>(db as any)[property][operation](args))
          return method.call(object,args)
        }
        return method.bind(object)
      }})
      return typeof delegate === 'function' ? delegate.bind(target) : delegate
    }
    return new Proxy(delegate, { get(object, operation) {
      const method = object[operation], op = String(operation)
      if (typeof method !== 'function') return method
      return (...args: any[]) => {
        if (!enabled || !reads.has(op) && !writes.has(op) && !summaries.has(op)) return method.apply(object, args)
        let pending: Promise<any> | undefined
        const run = () => pending ??= transaction(db => (db as any)[property][operation](...args), { isolationLevel: writes.has(op) ? Prisma.TransactionIsolationLevel.ReadCommitted : Prisma.TransactionIsolationLevel.RepeatableRead })
        return { authenticationOperation: true, [Symbol.toStringTag]: 'PrismaPromise', then: (ok: any, fail: any) => run().then(ok, fail), catch: (fail: any) => run().catch(fail), finally: (action: any) => run().finally(action) }
      }
    } })
  },set(_target,property,value){overrides.set(property,value);return true} }) as PrismaClient
}
