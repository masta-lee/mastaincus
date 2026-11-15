import assert from 'node:assert/strict'
import {randomUUID} from 'node:crypto'
import {mkdtemp,rm} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import Fastify from 'fastify'
import cookie from '@fastify/cookie'
import jwt from '@fastify/jwt'
const url=new URL(process.env.DATABASE_URL||'');assert.ok(['127.0.0.1','localhost'].includes(url.hostname)&&url.pathname.endsWith('_pool_test'))
process.env.NODE_ENV='test';const root=await mkdtemp(join(tmpdir(),'registration-http-'));process.env.PLATFORM_BACKUP_STATE_DIR=root
const{prisma,closePrismaDatabase}=await import('../src/db/prisma.js')
const{updateSystemConfigs}=await import('../src/db/system-config.js')
const{createVerificationCode}=await import('../src/db/email-verification.js')
const{default:routes}=await import('../src/routes/auth.js')
const{stopSessionCleanup}=await import('../src/lib/terminal-proxy.js')
const keys=['registration_enabled','require_invite_code','smtp_enabled','smtp_host','smtp_username','smtp_password','turnstile_enabled','free_site_register_gift_enabled','email_domain_whitelist_enabled','registration_ip_daily_limit']
const saved=await prisma.systemConfig.findMany({where:{key:{in:keys}}}),tag='reghttp'+randomUUID().replace(/-/g,'').slice(0,12),ids:number[]=[],source='203.0.113.88'
const fetchOriginal=globalThis.fetch;globalThis.fetch=async()=>Response.json({success:false})
const app=Fastify({trustProxy:false});await app.register(cookie);await app.register(jwt,{secret:'registration-http-fixture-only'})
app.decorate('authenticate',async()=>{throw Error('unused protected fixture')});app.decorate('authenticateAdmin',app.authenticate)
const config=async(values:Record<string,string>)=>{for(const[key,value]of Object.entries(values))await prisma.systemConfig.upsert({where:{key},create:{key,value,type:'string'},update:{value}});await updateSystemConfigs(Object.entries(values).map(([key,value])=>({key,value})))}
const payload=(n:string)=>({username:tag+n,password:'Fixture#Secure2928',email:tag+n+'@example.test'})
const post=(n:string,ip=source,extra={})=>app.inject({method:'POST',url:'/api/auth/register',remoteAddress:ip,headers:{'x-forwarded-for':'198.51.100.'+(ids.length+1)},payload:{...payload(n),...extra}})
try{
 await config({registration_enabled:'true',require_invite_code:'false',smtp_enabled:'false',turnstile_enabled:'false',free_site_register_gift_enabled:'false',email_domain_whitelist_enabled:'false',registration_ip_daily_limit:'3'})
 await app.register(routes,{prefix:'/api/auth'});await app.ready()
 for(const n of ['a','b','c']){const response=await post(n);assert.equal(response.statusCode,201,response.body);ids.push(response.json().user.id);assert.ok(response.headers['set-cookie'])}
 const rejected=await post('d');assert.equal(rejected.statusCode,429);assert.equal(rejected.json().code,'REGISTRATION_SOURCE_LIMIT')
 assert.equal(await prisma.user.count({where:{username:tag+'d'}}),0)
 await config({registration_enabled:'false'});assert.equal((await post('off','203.0.113.89')).statusCode,403)
 await config({registration_enabled:'true',require_invite_code:'true'});assert.equal((await post('invite','203.0.113.89')).json().code,'INVALID_INVITE_CODE')
 await config({require_invite_code:'false',smtp_enabled:'true',smtp_host:'',smtp_username:'',smtp_password:''})
 assert.equal((await post('smtp','203.0.113.89')).json().code,'REGISTRATION_VERIFICATION_UNAVAILABLE')
 await config({smtp_host:'smtp.example.test',smtp_username:'fixture',smtp_password:'unused-fixture'})
 assert.equal((await post('verified','203.0.113.89')).json().code,'EMAIL_CODE_REQUIRED')
 const code=await createVerificationCode(payload('verified').email,'register');assert.ok(code)
 assert.equal((await post('verified','203.0.113.89',{emailCode:'999999'})).json().code,'INVALID_EMAIL_CODE')
 const verified=await post('verified','203.0.113.89',{emailCode:code.code});assert.equal(verified.statusCode,201,verified.body);ids.push(verified.json().user.id)
 assert.equal((await post('reuse','203.0.113.90',{email:payload('verified').email,emailCode:code.code})).statusCode,400)
 assert.equal(await prisma.registrationReceipt.count({where:{source}}),3)
 console.log('PASS actual registration HTTP: three successes, spoofed source rejected, disabled/invite/SMTP configuration closed, incorrect/consumed codes rejected and valid code commits one user/session/source receipt')
}finally{
 globalThis.fetch=fetchOriginal;await app.close();stopSessionCleanup()
 await prisma.registrationReceipt.deleteMany({where:{userId:{in:ids}}});await prisma.user.deleteMany({where:{id:{in:ids}}});await prisma.emailVerificationCode.deleteMany({where:{email:{startsWith:tag}}})
 for(const key of keys){const row=saved.find(r=>r.key===key);if(row)await prisma.systemConfig.update({where:{key},data:{value:row.value,type:row.type}});else await prisma.systemConfig.deleteMany({where:{key}})}
 await closePrismaDatabase();await rm(root,{recursive:true,force:true})
}process.exit(0)
