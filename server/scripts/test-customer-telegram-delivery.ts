import assert from 'node:assert/strict'
import {randomUUID} from 'node:crypto'
import {mkdtemp,rm} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
const url=new URL(process.env.DATABASE_URL||'');assert.ok(['127.0.0.1','localhost'].includes(url.hostname)&&url.pathname.endsWith('_pool_test'))
process.env.NODE_ENV='test'
const state=await mkdtemp(join(tmpdir(),'security-telegram-'))
Object.assign(process.env,{FINANCIAL_INTEGRITY_STATE_DIR:state,ENCRYPTION_KEY:'isolated-telegram-security-key'})
const{prisma,closePrismaDatabase,initializeFinancialDatabaseIntegrity}=await import('../src/db/prisma.js')
const{sealNotificationConfig}=await import('../src/lib/notification-config.js')
await initializeFinancialDatabaseIntegrity()
const{sendNotification,sendHostManagedInstanceNotification,sendToChannel}=await import('../src/lib/notifier.js')
const{sendAdminAlert}=await import('../src/lib/admin-alerts.js')
const{updateSystemConfigs,initSystemConfig}=await import('../src/db/system-config.js')
await initSystemConfig()
const{sendTrafficThrottledNotification}=await import('../src/services/traffic-notifier.js')
const tag='tg-review-'+randomUUID().slice(0,10),users:number[]=[],channels:number[]=[],hosts:number[]=[],payloads:any[]=[],keys=['telegram_bot_enabled','telegram_bot_token']
const saved=await prisma.systemConfig.findMany({where:{key:{in:keys}}})
const fetchOriginal=globalThis.fetch;let rejectHTTP=false
globalThis.fetch=async(input,options)=>{assert.ok(String(input).startsWith('https://api.telegram.org/botfixture'));assert.equal(options?.redirect,'manual');assert.ok(options?.signal);payloads.push(JSON.parse(String(options?.body)));return Response.json({ok:true},{status:rejectHTTP?503:200})}
const channel=async(userId:number,name:string,extra={})=>{const c=await prisma.notificationChannel.create({data:{userId,name:tag+name,type:'telegram',enabled:true,config:sealNotificationConfig({botToken:'fixture-'+name,chatId:name}),...extra}});channels.push(c.id);return c}
try{
 const admin=await prisma.user.create({data:{username:tag+'admin',passwordHash:'fixture',role:'admin'}}),customer=await prisma.user.create({data:{username:tag+'customer',passwordHash:'fixture'}});users.push(admin.id,customer.id)
 const personal=await channel(customer.id,'customer'),adminAlert=await channel(admin.id,'alert',{alertCategory:'instance'}),misclassified=await channel(customer.id,'misclassified',{alertCategory:'instance'})
 await prisma.userTelegramBinding.create({data:{userId:customer.id,telegramUserId:'fixture-binding'}})
 await updateSystemConfigs([{key:'telegram_bot_enabled',value:'true'},{key:'telegram_bot_token',value:'fixture-site'}])
 const data={instanceName:'My customer machine',hostName:'private-host',oldHostName:'old-private-host',newHostName:'new-private-host',ociAccountName:'private-oci',ipv4:'10.18.2.3',ipv6:'fd42::5',error:'incus Error: private-host private-oci 10.18.2.3',newImage:'debian/13'}
 for(const event of ['instance_created','instance_create_failed','instance_rebuilt','instance_host_changed'] as const){const result=await sendNotification(customer.id,event,data);assert.equal(result.failed,0);assert.equal(result.sent,1)}
 const customerPayloads=payloads.filter(p=>p.chat_id==='customer'||p.chat_id==='fixture-binding')
 assert.ok(customerPayloads.length>=6)
 for(const p of customerPayloads){assert.ok(!/private.host|private.oci|10\.18\.2\.3|fd42|incus Error|节点:/.test(p.text),p.text);assert.ok(p.text.length<=4096);assert.equal(p.parse_mode,'MarkdownV2')}
 assert.ok(!payloads.some(p=>p.chat_id==='misclassified'||p.chat_id==='alert'),'personal lifecycle channels never use global/admin alert channels')
 const inbox=await prisma.inboxMessage.findMany({where:{userId:customer.id}});assert.ok(!/private-host|private-oci|10\.18\.2\.3|fd42/.test(JSON.stringify(inbox)))
 const adminResult=await sendAdminAlert('instance','Creation <failed>','用户：customer\n宿主：private-host\nOCI 账户：private-oci\n错误：具体错误\n时间：2026-11-15 09:00')
 assert.deepEqual(adminResult,{sent:1,failed:0});assert.ok(payloads.at(-1).text.includes('private-host'));assert.ok(payloads.at(-1).text.includes('private-oci'));assert.ok(payloads.at(-1).text.startsWith('<b>'));assert.equal(payloads.at(-1).parse_mode,'HTML')
 assert.ok(!payloads.some(p=>p.chat_id==='misclassified'),'invalid customer-owned admin alert channel cannot receive internal details')
 const host=await prisma.host.create({data:{name:'private-host',userId:customer.id,url:'https://127.0.0.1:18443',notifyPurchase:true,notifyRenew:true,notifyDestroy:true}});hosts.push(host.id)
 await sendHostManagedInstanceNotification(host.id,'purchase',{username:'buyer',instanceName:'customer-vps',amount:10})
 assert.ok(!payloads.at(-1).text.includes('private-host'))
 const pkg=await prisma.package.create({data:{userId:admin.id,name:tag,cpuMax:200,memoryMax:1024,diskMax:30720}})
 const instance=await prisma.instance.create({data:{userId:customer.id,hostId:host.id,packageId:pkg.id,name:'customer-vps',incusId:tag,status:'running',image:'fixture',cpu:100,memory:512,disk:1024}})
 await sendTrafficThrottledNotification(customer.id,instance.name,host.name);assert.ok(!payloads.at(-1).text.includes(host.name))
 await prisma.instance.delete({where:{id:instance.id}});await prisma.package.delete({where:{id:pkg.id}})
 assert.equal((await sendToChannel(personal.id,'Quota','IPv4: 10.18.2.3\n节点: private-host')).success,true);assert.ok(!/private-host|10\.18\.2\.3/.test(payloads.at(-1).text))
 rejectHTTP=true;assert.deepEqual(await sendAdminAlert('instance','Failure','test'),{sent:0,failed:1})
 assert.equal((await prisma.notificationLog.findFirstOrThrow({where:{channelId:adminAlert.id},orderBy:{id:'desc'}})).status,'failed')
 assert.equal(await prisma.notificationLog.count({where:{channelId:misclassified.id}}),0)
 console.log('PASS actual Telegram send pipelines: site/personal lifecycle, host income, traffic and global release customer payloads exclude host/OCI/private IP; admin HTML details retained; misclassified channels excluded and HTTP failure persisted')
}finally{
 globalThis.fetch=fetchOriginal;await prisma.notificationChannel.deleteMany({where:{id:{in:channels}}});await prisma.host.deleteMany({where:{id:{in:hosts}}});await prisma.user.deleteMany({where:{id:{in:users}}})
 for(const key of keys){const row=saved.find(r=>r.key===key);if(row)await prisma.systemConfig.update({where:{key},data:{value:row.value,type:row.type}});else await prisma.systemConfig.deleteMany({where:{key}})}
 await closePrismaDatabase()
 await rm(state,{recursive:true,force:true})
}process.exit(0)
