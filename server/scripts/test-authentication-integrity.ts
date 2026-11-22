import assert from 'node:assert/strict'
import {createRequire} from 'node:module'
import {randomUUID} from 'node:crypto'
import {mkdtemp,rm} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
const req=createRequire(import.meta.url),{Pool}=req('../node_modules/pg')
const url=new URL(process.env.DATABASE_URL||'');assert.equal(url.hostname,'127.0.0.1');assert.ok(url.pathname.endsWith('_pool_test'));const name=url.pathname.slice(1)
const raw=new Pool({connectionString:url.href}),state=await mkdtemp(join(tmpdir(),'security-regression-'))
assert.equal((await raw.query('SELECT count(*)::int count FROM users')).rows[0].count,0,'regression requires an empty disposable database')
Object.assign(process.env,{DATABASE_URL:url.href,NODE_ENV:'test',JWT_SECRET:'isolated-auth-repair-jwt-key',ENCRYPTION_KEY:'isolated-auth-repair-encryption-key',FINANCIAL_INTEGRITY_STATE_DIR:state,PLATFORM_BACKUP_STATE_DIR:join(state,'empty')})
const {prisma,closePrismaDatabase,initializeFinancialDatabaseIntegrity}=await import('../src/db/prisma.ts')
const {generateRefreshToken,verifyRefreshToken,encodeRecoveryCodes,encryptSensitiveData,getRefreshTokenStorageKey}=await import('../src/lib/security.ts')
const {verifyFinancialDatabaseSeals}=await import('../src/lib/financial-integrity.ts')
const {default:Fastify}=await import('../node_modules/fastify/fastify.js'),{default:cookie}=await import('../node_modules/@fastify/cookie/plugin.js'),jwt=req('../node_modules/@fastify/jwt'),{default:bcrypt}=await import('../node_modules/bcryptjs/index.js')
const {default:routes}=await import('../src/routes/auth.ts')
const app=Fastify();await app.register(cookie);await app.register(jwt,{secret:process.env.JWT_SECRET!});app.decorate('authenticate',async()=>{});await app.register(routes,{prefix:'/auth'})
try{
 await initializeFinancialDatabaseIntegrity()
 const user=await prisma.user.create({data:{username:'repair-'+randomUUID(),passwordHash:await bcrypt.hash('OriginalSyntheticPassword9',4),role:'admin',twoFactorEnabled:true,twoFactorSecret:encryptSensitiveData('JBSWY3DPEHPK3PXP'),twoFactorRecoveryCodes:encodeRecoveryCodes(['GOOD-AAAA','GOOD-BBBB'])}})
 const token=await generateRefreshToken(user.id,user.username,'admin'),record=await prisma.refreshToken.findUniqueOrThrow({where:{token:getRefreshTokenStorageKey(token)}})
 const refresh=async(t:string)=>app.inject({method:'POST',url:'/auth/refresh',headers:{cookie:'refreshToken='+encodeURIComponent(t)}})
 assert.equal((await refresh(record.token)).statusCode,401)
 assert.equal((await refresh(token)).statusCode,200)
 const fake='rt_'+randomUUID()
 await raw.query("INSERT INTO refresh_tokens(token,user_id,username,role,expires_at,last_active_at) VALUES($1,$2,$3,'admin',NOW()+INTERVAL '1 hour',NOW())",[getRefreshTokenStorageKey(fake),user.id,user.username])
 assert.equal(await verifyRefreshToken(fake),null);assert.equal((await refresh(fake)).statusCode,401)
 await raw.query('DELETE FROM refresh_tokens WHERE token=$1',[getRefreshTokenStorageKey(fake)])
 const original=(await raw.query('SELECT two_factor_recovery_codes FROM users WHERE id=$1',[user.id])).rows[0].two_factor_recovery_codes
 await raw.query('UPDATE users SET two_factor_recovery_codes=$2 WHERE id=$1',[user.id,JSON.stringify(['FAKE-AAAA'])])
 const rejected=await app.inject({method:'POST',url:'/auth/login',payload:{username:user.username,password:'OriginalSyntheticPassword9',recoveryCode:'FAKE-AAAA'}})
 assert.notEqual(rejected.statusCode,200)
 await raw.query('UPDATE users SET two_factor_recovery_codes=$2 WHERE id=$1',[user.id,original])
 const login=()=>app.inject({method:'POST',url:'/auth/login',payload:{username:user.username,password:'OriginalSyntheticPassword9',recoveryCode:'GOOD-AAAA'}})
 const concurrent=await Promise.all([login(),login()]);assert.equal(concurrent.filter(x=>x.statusCode===200).length,1)
 await verifyFinancialDatabaseSeals(name,process.env.ENCRYPTION_KEY!)
 await initializeFinancialDatabaseIntegrity()
 await prisma.user.delete({where:{id:user.id}})
 await verifyFinancialDatabaseSeals(name,process.env.ENCRYPTION_KEY!)
 console.log(JSON.stringify({localOnly:true,externalDigestRejected:true,rawTokenAccepted:true,dbForgedSessionRejected:true,dbRecoveryCodeTamperingRejected:true,recoveryCodeConcurrentSingleUse:true,repeatInitializationValid:true,accountDeletionSealsClean:true}))
}finally{await app.close();await closePrismaDatabase();await raw.query("DO $$ DECLARE t record; BEGIN FOR t IN SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> '_prisma_migrations' LOOP EXECUTE format('TRUNCATE %I CASCADE',t.tablename); END LOOP; END $$");await raw.end();await rm(state,{recursive:true,force:true})}
process.exit(0)
