import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtemp,rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { readFileSync } from 'node:fs'
import Fastify from 'fastify'
import jwt from '@fastify/jwt'
import ts from 'typescript'
const url=new URL(process.env.DATABASE_URL||'');assert.ok(['127.0.0.1','localhost'].includes(url.hostname)&&url.pathname.endsWith('_pool_test'))
process.env.NODE_ENV='test';const root=await mkdtemp(join(tmpdir(),'account-cleanup-'));process.env.PLATFORM_BACKUP_STATE_DIR=root
const{prisma,closePrismaDatabase}=await import('../src/db/prisma.js')
const{createRegisteredUser}=await import('../src/db/users.js')
const{requestUserCleanup,processUserCleanup,userCleanupStatus}=await import('../src/services/admin-user-cleanup.js')
const{assertPaymentNotDeleted,paymentTradeHash}=await import('../src/lib/deleted-payment-receipt.js')
const{completeRecharge}=await import('../src/db/recharge-records.js')
const{default:userRoutes}=await import('../src/routes/users.js')
const{isAccessTokenInvalidated}=await import('../src/lib/security.js')
const{recoveryHeld}=await import('../src/services/platform-backup-core.js')
const{validateRecoverySession}=await import('../src/services/platform-recovery-operator.js')
const tag='account-review-'+randomUUID().slice(0,10),admin=await prisma.user.create({data:{username:tag+'-admin',role:'admin',passwordHash:'fixture'}})
const actor={id:admin.id,sid:tag,iat:Math.floor(Date.now()/1000)+1},ids:number[]=[]
const app=Fastify();await app.register(jwt,{secret:'account-cleanup-http-signature-only'})
const appSource=readFileSync(new URL('../src/app.ts',import.meta.url),'utf8'),start=appSource.indexOf('async function ensureActiveAccessToken('),end=appSource.indexOf('// 注意: 安全响应头',start)
assert.ok(start>=0&&end>start)
new Function('fastify','prisma','isAccessTokenInvalidated','recoveryHeld','validateRecoverySession',ts.transpileModule(appSource.slice(start,end),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText)(app,prisma,isAccessTokenInvalidated,recoveryHeld,validateRecoverySession)
await app.register(userRoutes,{prefix:'/api/users'})
const headers={authorization:'Bearer '+app.jwt.sign({...actor,role:'admin'})}
const settings=['registration_ip_daily_limit','free_site_register_gift_enabled','require_invite_code'];const old=await prisma.systemConfig.findMany({where:{key:{in:settings}}})
try{
// Exercise the exact upgrade SQL in an isolated namespace, including live
// pre-upgrade registration evidence and malformed legacy audit content.
const schema='reg_upgrade_'+randomUUID().replace(/-/g,'')
await prisma.$transaction(async tx=>{
 await tx.$executeRawUnsafe('CREATE SCHEMA '+schema)
 await tx.$executeRawUnsafe('SET LOCAL search_path TO '+schema)
 await tx.$executeRawUnsafe('CREATE TABLE users(id integer PRIMARY KEY); CREATE TABLE logs(id integer PRIMARY KEY,user_id integer,content text,action text,created_at timestamptz)')
 await tx.$executeRawUnsafe("INSERT INTO logs VALUES (1,1,'fixture [IP: 203.0.113.1]','register_success',now()),(2,2,'fixture [IP: 2001:db8:0:0::1]','register_success',now()),(3,3,'fixture [IP: broken]','register_success',now()),(4,4,'fixture [IP: 192.0.2.4]','register_success',now()-interval '2 days')")
 const migration=readFileSync(new URL('../prisma/migrations/20261115031000_registration_and_user_cleanup/migration.sql',import.meta.url),'utf8')
 for(const statement of migration.split(';').map(s=>s.trim()).filter(Boolean))await tx.$executeRawUnsafe(statement)
 const receipts=await tx.$queryRawUnsafe<Array<{source:string}>>('SELECT source FROM registration_receipts ORDER BY source')
 assert.deepEqual(receipts.map(row=>row.source),['2001:db8::/64','203.0.113.1'])
 await tx.$executeRawUnsafe('DROP SCHEMA '+schema+' CASCADE')
},{timeout:15000})
console.log('PASS exact upgrade migration: valid 24-hour IPv4/IPv6 audit evidence retained, old/malformed addresses excluded')
for(const[key,value]of [['registration_ip_daily_limit','3'],['free_site_register_gift_enabled','false']])await prisma.systemConfig.upsert({where:{key},create:{key,value,type:key.includes('limit')?'number':'boolean'},update:{value}})
const source='203.0.113.99'
const attempts=await Promise.allSettled(Array.from({length:7},(_,n)=>createRegisteredUser({username:tag+n,email:`${tag}${n}@example.test`,passwordHash:'fixture',registrationIp:source})))
const accepted=attempts.filter((r):r is PromiseFulfilledResult<Awaited<ReturnType<typeof createRegisteredUser>>>=>r.status==='fulfilled');ids.push(...accepted.map(r=>r.value.userId));assert.equal(accepted.length,3)
assert.equal(await prisma.registrationReceipt.count({where:{source}}),3)
assert.ok(attempts.filter(r=>r.status==='rejected').every(r=>(r as PromiseRejectedResult).reason.message==='REGISTRATION_SOURCE_LIMIT'))
const target=ids[0]
await prisma.user.update({where:{id:target},data:{balance:12.34,hostingBalance:3,affBalance:4}})
await prisma.balanceLog.create({data:{userId:target,type:'admin_adjust',amount:12.34,balanceBefore:0,balanceAfter:12.34}})
await prisma.loginRecord.create({data:{userId:target,ip:source,userAgent:'fixture'}})
const provider=await prisma.paymentProvider.create({data:{name:tag,type:'manual',status:'disabled',config:{}}})
await prisma.rechargeRecord.create({data:{orderNo:tag,userId:target,providerId:provider.id,amount:12.34,actualAmount:12.34,status:'completed',tradeNo:'cleanup-original-trade'}})
const lateRecharge=await prisma.rechargeRecord.findUniqueOrThrow({where:{orderNo:tag}})
await prisma.rechargeLatePayment.create({data:{rechargeId:lateRecharge.id,providerId:provider.id,gatewayOrderNo:tag,tradeNo:'cleanup-late-trade',reason:'additional_payment',status:'pending',proof:{}}})
const ordinary={id:ids[1],sid:'fake',iat:actor.iat}
for(const invalid of ['0','-1','1.2','999999999999999999'])assert.equal((await app.inject({method:'POST',url:'/api/users/'+invalid+'/cleanup',headers,payload:{confirm:true}})).statusCode,400)
for(const confirm of [false,null,'true'])assert.equal((await app.inject({method:'POST',url:'/api/users/'+target+'/cleanup',headers,payload:{confirm}})).statusCode,400)
assert.equal((await app.inject({method:'POST',url:'/api/users/'+target+'/cleanup',payload:{confirm:true}})).statusCode,401)
const forged={authorization:'Bearer '+app.jwt.sign({...ordinary,role:'admin'})}
assert.equal((await app.inject({method:'POST',url:'/api/users/'+target+'/cleanup',headers:forged,payload:{confirm:true}})).statusCode,403)
assert.equal((await app.inject({method:'GET',url:'/api/users/'+target+'/cleanup',headers:forged})).statusCode,403)
assert.equal((await prisma.user.findUniqueOrThrow({where:{id:target}})).status,'active')
const owned=await prisma.host.create({data:{name:tag,userId:ids[1],url:'https://127.0.0.1:18443'}})
assert.equal((await app.inject({method:'POST',url:'/api/users/'+ids[1]+'/cleanup',headers,payload:{confirm:true}})).json().code,'USER_CLEANUP_OWNED_SERVICES')
assert.equal((await prisma.user.findUniqueOrThrow({where:{id:ids[1]}})).status,'active');await prisma.host.delete({where:{id:owned.id}})
await assert.rejects(requestUserCleanup(target,ordinary),/ADMIN_ACTOR_FORBIDDEN/)
await assert.rejects(requestUserCleanup(admin.id,actor),/CANNOT_DELETE_SELF/)
await requestUserCleanup(target,actor)
assert.equal((await prisma.user.findUniqueOrThrow({where:{id:target}})).status,'banned')
assert.ok(await prisma.tokenInvalidation.count({where:{userId:target}}))
await processUserCleanup(target)
assert.equal(await prisma.user.findUnique({where:{id:target}}),null)
assert.equal((await userCleanupStatus(target)).status,'done')
assert.equal(await prisma.balanceLog.count({where:{userId:target}}),0);assert.equal(await prisma.rechargeRecord.count({where:{userId:target}}),0)
assert.equal(await prisma.registrationReceipt.count({where:{source}}),3,'account removal does not reset successful registration count')
await assert.rejects(prisma.$transaction(tx=>assertPaymentNotDeleted(tx,provider.id,'cleanup-original-trade')),/PAYMENT_TRADE_ALREADY_CREDITED/)
await assert.rejects(prisma.$transaction(tx=>assertPaymentNotDeleted(tx,provider.id,'cleanup-late-trade')),/PAYMENT_TRADE_ALREADY_CREDITED/)
const repeat=await prisma.rechargeRecord.create({data:{orderNo:tag+'repeat',userId:ids[1],providerId:provider.id,amount:12.34,status:'pending'}})
const beforeRepeat=await prisma.user.findUniqueOrThrow({where:{id:ids[1]}})
await assert.rejects(completeRecharge(repeat.orderNo,{tradeNo:'cleanup-original-trade'}),/PAYMENT_TRADE_ALREADY_CREDITED/)
assert.equal((await prisma.user.findUniqueOrThrow({where:{id:ids[1]}})).balance.toString(),beforeRepeat.balance.toString())
await prisma.rechargeRecord.delete({where:{id:repeat.id}})
await prisma.deletedPaymentReceipt.deleteMany({where:{providerId:provider.id}});await prisma.paymentProvider.delete({where:{id:provider.id}})
await assert.rejects(createRegisteredUser({username:tag+'again',email:tag+'again@example.test',passwordHash:'fixture',registrationIp:source}),/REGISTRATION_SOURCE_LIMIT/)
console.log('PASS real PostgreSQL: concurrent per-source registration cap, deletion revocation/balance/bills, retained hashed payment de-duplication, quota not reset')
}finally{await app.close();await prisma.registrationReceipt.deleteMany({where:{source:'203.0.113.99'}});await prisma.user.deleteMany({where:{id:{in:[admin.id,...ids]}}});for(const key of settings){const prior=old.find(r=>r.key===key);if(prior)await prisma.systemConfig.update({where:{key},data:{value:prior.value}});else await prisma.systemConfig.deleteMany({where:{key}})}await closePrismaDatabase();await rm(root,{recursive:true,force:true})}
process.exit(0)
