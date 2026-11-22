import assert from 'node:assert/strict'
import {createRequire} from 'node:module'
import {randomUUID} from 'node:crypto'
import {mkdtemp,rm} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
const req=createRequire(import.meta.url),{Pool}=req('../node_modules/pg')
const base=new URL(process.env.DATABASE_URL||'');assert.equal(base.hostname,'127.0.0.1');assert.ok(base.pathname.endsWith('_pool_test'));const name=base.pathname.slice(1)
const raw=new Pool({connectionString:base.href}),folder=await mkdtemp(join(tmpdir(),'security-regression-'))
assert.equal((await raw.query('SELECT count(*)::int count FROM users')).rows[0].count,0,'regression requires an empty disposable database')
Object.assign(process.env,{NODE_ENV:'test',DATABASE_URL:base.href,ENCRYPTION_KEY:'isolated-oauth-repair-encryption-key',JWT_SECRET:'isolated-oauth-repair-jwt-key',FINANCIAL_INTEGRITY_STATE_DIR:folder})
const {prisma,initializeFinancialDatabaseIntegrity,closePrismaDatabase}=await import('../src/db/prisma.ts')
const {hashOAuthSecret,exchangeOAuthAuthorizationCode,exchangeOAuthRefreshToken}=await import('../src/lib/oauth-provider.ts')
try{
 await initializeFinancialDatabaseIntegrity()
 const user=await prisma.user.create({data:{username:'oauth-repair-'+randomUUID(),passwordHash:'fixture'}})
 const secret='posec_'+randomUUID(),clientId='pocli_'+randomUUID(),redirectUri='https://oauth-client.example/callback'
 const app=await prisma.oAuthClientApp.create({data:{name:'repair',clientId,clientSecretHash:hashOAuthSecret(secret),redirectUris:[redirectUri],scopes:['services:operate'],createdByUserId:user.id}})
 await prisma.oAuthGrant.create({data:{userId:user.id,appId:app.id,scopes:['services:operate']}})
 const code='poc_'+randomUUID()
 await prisma.oAuthAuthorizationCode.create({data:{userId:user.id,appId:app.id,codeHash:hashOAuthSecret(code),redirectUri,scopes:['services:operate'],expiresAt:new Date(Date.now()+60000)}})
 const inputs={clientId,clientSecret:secret,code,redirectUri}
 const results=await Promise.allSettled([exchangeOAuthAuthorizationCode(inputs),exchangeOAuthAuthorizationCode(inputs)])
 assert.equal(results.filter(x=>x.status==='fulfilled').length,1)
 const refresh=(results.find(x=>x.status==='fulfilled') as PromiseFulfilledResult<any>).value.refreshToken
 const refreshes=await Promise.allSettled([exchangeOAuthRefreshToken({clientId,clientSecret:secret,refreshToken:refresh}),exchangeOAuthRefreshToken({clientId,clientSecret:secret,refreshToken:refresh})])
 assert.equal(refreshes.filter(x=>x.status==='fulfilled').length,1)
 const banned='poc_'+randomUUID();await prisma.user.update({where:{id:user.id},data:{status:'banned'}})
 await prisma.oAuthAuthorizationCode.create({data:{userId:user.id,appId:app.id,codeHash:hashOAuthSecret(banned),redirectUri,scopes:['services:operate'],expiresAt:new Date(Date.now()+60000)}})
 await assert.rejects(exchangeOAuthAuthorizationCode({...inputs,code:banned}),/not active/)
 await prisma.user.update({where:{id:user.id},data:{status:'active'}})
 const grant=await prisma.oAuthGrant.upsert({where:{appId_userId:{appId:app.id,userId:user.id}},create:{appId:app.id,userId:user.id,scopes:['services:operate']},update:{revokedAt:null}})
 await prisma.oAuthClientApp.update({where:{id:app.id},data:{enabled:false}})
 await assert.rejects(exchangeOAuthAuthorizationCode({...inputs,code:banned}))
 await prisma.oAuthClientApp.update({where:{id:app.id},data:{enabled:true}})
 await prisma.oAuthGrant.update({where:{id:grant.id},data:{revokedAt:new Date()}})
 await assert.rejects(exchangeOAuthAuthorizationCode({...inputs,code:banned}))
 await prisma.oAuthGrant.update({where:{id:grant.id},data:{revokedAt:null}})
 const sealed=(await raw.query('SELECT signature FROM authentication_integrity_seals WHERE model=$1 AND record_id=$2',['oAuthClientApp',String(app.id)])).rows[0].signature
 await raw.query('UPDATE oauth_client_apps SET enabled=false WHERE id=$1',[app.id])
 await assert.rejects(prisma.oAuthClientApp.count({where:{id:app.id}}))
 await raw.query('UPDATE oauth_client_apps SET enabled=true WHERE id=$1',[app.id])
 assert.equal((await raw.query('SELECT signature FROM authentication_integrity_seals WHERE model=$1 AND record_id=$2',['oAuthClientApp',String(app.id)])).rows[0].signature,sealed)
 const projected=await prisma.oAuthClientApp.findUniqueOrThrow({where:{id:app.id},select:{name:true,createdBy:{select:{username:true}}}})
 assert.deepEqual(Object.keys(projected).sort(),['createdBy','name']);assert.deepEqual(Object.keys(projected.createdBy),['username'])
 await prisma.oAuthClientApp.delete({where:{id:app.id}})
 const {verifyFinancialDatabaseSeals}=await import('../src/lib/financial-integrity.ts')
 await verifyFinancialDatabaseSeals(name,process.env.ENCRYPTION_KEY!)
 console.log(JSON.stringify({localDbOnly:true,authorizationCodeSingleUse:true,refreshSingleUse:true,bannedCodeRejected:true,disabledClientRejected:true,revokedGrantRejected:true,compoundUpsertWorks:true,selectedRelationPreservesProjection:true,tamperedAggregateRejected:true,appCascadeSealsClean:true,authenticationSealsEnabled:true}))
}finally{await closePrismaDatabase();await raw.query("DO $$ DECLARE t record; BEGIN FOR t IN SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> '_prisma_migrations' LOOP EXECUTE format('TRUNCATE %I CASCADE',t.tablename); END LOOP; END $$");await raw.end();await rm(folder,{recursive:true,force:true})}
process.exit(0)
