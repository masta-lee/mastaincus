import assert from 'node:assert/strict'
import { randomUUID,X509Certificate } from 'node:crypto'
import { mkdtemp,readFile,rm } from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {execFileSync} from 'node:child_process'
import {createServer} from 'node:https'
import {protectedAgentFixture} from './fixtures/guest-protection.js'
const url=new URL(process.env.DATABASE_URL||'');assert.ok(['127.0.0.1','localhost'].includes(url.hostname)&&url.pathname.endsWith('_pool_test'))
process.env.NODE_ENV='test';const dir=await mkdtemp(join(tmpdir(),'user-cleanup-incus-'));process.env.PLATFORM_BACKUP_STATE_DIR=dir
const{prisma,closePrismaDatabase}=await import('../src/db/prisma.js')
const{requestUserCleanup,processUserCleanup}=await import('../src/services/admin-user-cleanup.js')
const{closeAllClients}=await import('../src/lib/incus/incus-pool.js')
const{transferHostIdentity}=await import('../src/lib/transfer-host-identity.js')
const tag='cleanup-incus-'+randomUUID(),key=join(dir,'key'),cert=join(dir,'cert')
execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=fixture','-keyout',key,'-out',cert],{stdio:'pipe',windowsHide:true})
const certificate=await readFile(cert),guests=new Map<string,any>(),calls:string[]=[];let rejectDelete=false
const server=createServer({key:await readFile(key),cert:certificate,ca:certificate,requestCert:true,rejectUnauthorized:true},async(req,res)=>{
const path=new URL(req.url!,'https://fixture').pathname,method=req.method!;calls.push(method+' '+path);res.setHeader('content-type','application/json');const ok=(metadata:any={})=>res.end(JSON.stringify({type:'sync',metadata})),bad=(code:number)=>{res.statusCode=code;res.end(JSON.stringify({type:'error',error:'fixture failure'}))}
if(path==='/1.0')return ok({api_version:'1.0'})
if(path==='/1.0/instances')return ok(req.url!.includes('recursion=1')?[...guests.values()]:[...guests.keys()].map(name=>'/1.0/instances/'+name))
if(path==='/1.0/operations')return ok({})
if(path==='/1.0/projects')return ok([{name:'default'}])
if(path==='/1.0/networks')return ok([{name:'incusbr0',managed:true,type:'bridge'}])
if(path==='/1.0/storage-pools')return ok([{name:'payincus-pool',status:'Created'}])
if(path.endsWith('/volumes'))return ok([...guests.values()].map(g=>({name:g.name,type:'container'})))
if(path.includes('/forwards')||path.endsWith('/snapshots')||path.endsWith('/backups'))return ok([])
const match=/^\/1.0\/instances\/([^/]+)(\/state)?$/.exec(path),guest=match&&guests.get(match[1]);if(!match||!guest)return bad(404)
if(method==='GET')return ok(structuredClone(guest))
if(method==='PUT'){guest.status='Stopped';return ok()}
if(method==='POST'){let raw='';for await(const part of req)raw+=part;const name=JSON.parse(raw).name;guests.delete(guest.name);guest.name=name;guests.set(name,guest);return ok()}
if(method==='DELETE'){if(rejectDelete)return bad(503);assert.equal(guest.status,'Stopped');guests.delete(guest.name);return ok()}
return bad(500)
});await new Promise<void>(r=>server.listen(0,'127.0.0.1',r))
const admin=await prisma.user.create({data:{username:tag+'admin',role:'admin',passwordHash:'fixture'}}),ids:number[]=[]
const actor={id:admin.id,sid:tag,iat:Math.floor(Date.now()/1000)+1}
try{for(const initial of ['running','deleted','creating','incoming_transfer','foreign_bill']){
const user=await prisma.user.create({data:{username:tag+initial,passwordHash:'fixture',balance:25}});ids.push(user.id)
const host=await prisma.host.create({data:{userId:admin.id,name:tag,singleTenant:true,status:'online',isInstalled:true,instanceType:'container',architecture:'x86_64',resourcePreset:'E2',customerDiskGiB:30,storageSize:34,cpuAllowanceMax:200,memoryMax:768,cpuUsed:200,memoryUsed:768,diskUsed:30720,natPublicIp:'192.0.2.9',natBindIp:'10.0.0.9',natPortStart:1,natPortEnd:65535,portProtocol:'tcp',portProtocolApplied:'tcp',portProtocolRevision:1,portProtocolAppliedRevision:1,
url:`https://127.0.0.1:${(server.address() as any).port}`,certPath:cert,keyPath:key,serverCertificate:certificate.toString(),serverFingerprint:new X509Certificate(certificate).fingerprint256,agent:{create:protectedAgentFixture(['ingress-port-protocol-v1'])},storagePools:{create:{name:'payincus-pool',driver:'lvm',purpose:'instance_data',config:{'volume.block.filesystem':'btrfs'}}}}})
const sourceOwner=initial==='incoming_transfer'?await prisma.user.create({data:{username:tag+'payer',passwordHash:'fixture',balance:17}}):null
if(sourceOwner)ids.push(sourceOwner.id)
const instance=await prisma.instance.create({data:{userId:sourceOwner?.id||user.id,hostId:host.id,name:tag,incusId:tag+initial,image:'fixture',status:initial==='incoming_transfer'?'stopped':initial==='foreign_bill'?'running':initial as any,cpu:200,memory:768,disk:30720}})
const foreignBill=initial==='foreign_bill'?await prisma.instanceBillingRecord.create({data:{userId:admin.id,instanceId:instance.id,type:'newPurchase',amount:11,months:1,periodStart:new Date(),periodEnd:new Date(Date.now()+86400000)}}):null
if(initial==='running')await prisma.autoSnapshotOperation.create({data:{id:randomUUID(),instanceId:instance.id,ownerId:user.id,hostId:host.id,incusId:instance.incusId,identityHash:transferHostIdentity(host),snapshotName:'auto-'+randomUUID(),state:'blocked',stage:'prepared'}})
if(initial==='running')await prisma.instanceTask.create({data:{instanceId:instance.id,hostId:host.id,userId:user.id,taskType:'restart',status:'PENDING'}})
guests.set(instance.incusId,{name:instance.incusId,status:'Running',project:'default',created_at:'2020-01-01T00:00:00Z',config:{'volatile.uuid':randomUUID()}})
if(sourceOwner){
 const remote=guests.get(instance.incusId);remote.status='Stopped';guests.delete(remote.name);remote.name=instance.incusId+'renamed';guests.set(remote.name,remote)
 await prisma.instanceTransfer.create({data:{instanceId:instance.id,fromUserId:sourceOwner.id,toUserId:user.id,status:'processing',fee:3,
 snapshot:{},cleanupState:{version:1,stage:'renamed',sourceOwnerId:sourceOwner.id,targetOwnerId:user.id,hostId:host.id,
 oldIncusId:instance.incusId,newIncusId:remote.name,newName:'renamed',dedicated:false,hostIdentity:transferHostIdentity(host),remoteUuid:remote.config['volatile.uuid'],sites:[],ports:[],snapshots:[],backups:[]}}})
 await requestUserCleanup(user.id,actor);await processUserCleanup(user.id)
 assert.equal(await prisma.user.findUnique({where:{id:user.id}}),null)
 assert.equal((await prisma.user.findUniqueOrThrow({where:{id:sourceOwner.id}})).balance.toNumber(),20)
 assert.equal((await prisma.instance.findUniqueOrThrow({where:{id:instance.id}})).userId,sourceOwner.id)
 assert.ok(guests.has(instance.incusId));assert.equal(guests.size,1);assert.ok(!calls.some(c=>c==='DELETE /1.0/instances/'+instance.incusId))
 await requestUserCleanup(sourceOwner.id,actor);await processUserCleanup(sourceOwner.id)
 assert.equal(await prisma.user.findUnique({where:{id:sourceOwner.id}}),null)
 await prisma.host.delete({where:{id:host.id}})
 console.log('PASS incoming transfer: pinned original UUID rename restored, foreign guest retained, fee refunded once, target account removed')
 continue
}
await requestUserCleanup(user.id,actor);rejectDelete=true;await processUserCleanup(user.id)
assert.ok(await prisma.user.findUnique({where:{id:user.id}}),'remote failure must preserve user and bills')
assert.equal((await prisma.host.findUniqueOrThrow({where:{id:host.id}})).diskUsed,30720)
rejectDelete=false
for(let retry=0;retry<4&&await prisma.user.findUnique({where:{id:user.id}});retry++){
const u=await prisma.user.findUniqueOrThrow({where:{id:user.id}});await prisma.user.update({where:{id:user.id},data:{deletionIntent:{...(u.deletionIntent as any),nextAttemptAt:new Date(0).toISOString()}}})
const i=await prisma.instance.findUniqueOrThrow({where:{id:instance.id}});if(i.deletionIntent)await prisma.instance.update({where:{id:instance.id},data:{deletionIntent:{...(i.deletionIntent as any),nextAttemptAt:new Date(0).toISOString()}}});await processUserCleanup(user.id)
}
assert.equal(await prisma.user.findUnique({where:{id:user.id}}),null)
assert.equal(guests.has(instance.incusId),false);assert.equal((await prisma.host.findUniqueOrThrow({where:{id:host.id}})).poolFaulted,false)
if(foreignBill){assert.ok(await prisma.instanceBillingRecord.findUnique({where:{id:foreignBill.id}}));const retained=await prisma.instance.findUniqueOrThrow({where:{id:instance.id}});assert.equal(retained.status,'deleted');assert.equal(retained.userId,admin.id);assert.equal(retained.rootPassword,null);await prisma.instance.delete({where:{id:retained.id}})}
await prisma.host.delete({where:{id:host.id}})
console.log('PASS '+initial+': real mTLS stop/delete, failure preserves account/allocation, resumes and releases original pool before account removal')
}}finally{await closeAllClients();await prisma.instance.deleteMany({where:{userId:{in:ids}}});await prisma.host.deleteMany({where:{userId:admin.id}});await prisma.user.deleteMany({where:{id:{in:[admin.id,...ids]}}});await closePrismaDatabase();await new Promise<void>(r=>server.close(()=>r()));await rm(dir,{recursive:true,force:true})}
process.exit(0)
