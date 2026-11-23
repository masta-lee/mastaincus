import assert from 'node:assert/strict'
import Fastify from 'fastify'
import ts from 'typescript'
import http from 'node:http'
import { closeApplicationHttp } from '../../src/lib/http-shutdown.js'
import { WorkerActivity } from '../../src/workers/worker-activity.js'

export async function verifyAppWorkerLifecycle(source: string) {
  const file = ts.createSourceFile('app.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const hooks: ts.CallExpression[] = []
  const listens: ts.CallExpression[] = []
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      if (node.expression.getText(file) === 'fastify.addHook') hooks.push(node)
      if (node.expression.getText(file) === 'fastify.listen') listens.push(node)
    }
    ts.forEachChild(node, visit)
  }
  visit(file)
  assert.ok(hooks.length && listens.length)
  for (const hook of hooks) {
    assert.ok(hook.getStart(file) < Math.min(...listens.map(call => call.getStart(file))), 'Register every hook before either protected or ordinary listen')
  }
  const workerHooks = hooks.filter(hook => /stopCheckoutWorker|stopRecoveryReviewWorker/.test(hook.getText(file)))
  assert.equal(workerHooks.length, 2)
  for (const protectedStartup of [false, true]) {
    const fastify = Fastify()
    let checkoutStopped = false, recoveryStopped = false
    const register = new Function('fastify', 'stopCheckoutWorker', 'stopRecoveryReviewWorker', workerHooks.map(hook => hook.getText(file)).join(';'))
    register(fastify, async () => { await new Promise(resolve => setTimeout(resolve, 10)); checkoutStopped = true }, () => { recoveryStopped = true })
    try {
      if (protectedStartup) await fastify.listen({ host: '127.0.0.1', port: 0 })
      if (!fastify.server.listening) await fastify.listen({ host: '127.0.0.1', port: 0 })
      assert.equal((await fastify.inject({ url: '/' })).statusCode, 404)
    } finally { await fastify.close() }
    assert.ok(checkoutStopped && recoveryStopped, 'Real Fastify close waits for the shipped worker shutdown callbacks')
  }
  const resourceHook=hooks.find(hook=>/stopInstanceTaskWorker.*stopRestoreWorker.*stopBackupUploadWorker/s.test(hook.getText(file)))
  assert.ok(resourceHook,'instance, restore and upload drains must be registered before listen')
  assert.ok(resourceHook.getText(file).includes("'preClose'"),'stop resource admission before waiting for existing HTTP/WebSocket connections')
  const connectionHook=hooks.find(hook=>hook.getText(file).includes('void beginBackgroundShutdown()'))
  assert.ok(connectionHook?.getText(file).includes("'preClose'"),'terminal connections and scheduler admissions close before HTTP server waits for connections')
  const fastify=Fastify()
  const released:Array<()=>void>=[]
  const stopped:string[]=[]
  const drain=(name:string)=>async()=>{stopped.push(name);await new Promise<void>(resolve=>released.push(resolve))}
  new Function('fastify','stopInstanceTaskWorker','stopRestoreWorker','stopBackupUploadWorker',resourceHook.getText(file))(fastify,drain('instance'),drain('restore'),drain('upload'))
  await fastify.listen({host:'127.0.0.1',port:0})
  let closed=false
  const close=fastify.close().then(()=>{closed=true})
  await new Promise(resolve=>setTimeout(resolve,10))
  assert.deepEqual(stopped,['instance','restore','upload'],'all admissions stop before waiting for any one drain')
  assert.equal(closed,false)
  for(const release of released)release()
  await close

  const activity=new WorkerActivity()
  let releaseClaim!:()=>void,releaseWork!:()=>void
  const claim=new Promise<void>(resolve=>{releaseClaim=resolve})
  const work=new Promise<void>(resolve=>{releaseWork=resolve})
  const pending=activity.run(async()=>{await claim;void activity.run(()=>work)})
  let drained=false
  const draining=activity.drain().then(()=>{drained=true})
  releaseClaim();await pending
  await new Promise(resolve=>setTimeout(resolve,10))
  assert.equal(drained,false,'work registered by a draining claim cannot be lost')
  releaseWork();await draining
  await assert.rejects(activity.run(async()=>{throw Error('synthetic failure')}))
  await activity.drain()
  const shutdown=file.statements.find(node=>ts.isFunctionDeclaration(node)&&node.name?.text==='gracefulShutdown')
  assert.ok(shutdown)
  const signals=source.indexOf("process.on('SIGTERM'")
  assert.ok(signals>0&&signals<source.indexOf('const start = async'),'exit signals cover protected startup before initialization')
  const javascript=ts.transpileModule(shutdown.getText(file),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText
  let releaseStartup!:()=>void
  const starting=new Promise<void>(resolve=>{releaseStartup=resolve})
  const steps:string[]=[]
  const shutdownProcess={exit:()=>{steps.push('exit')}}
  const shutdownFastify={close:async()=>{steps.push('fastify')},log:{error:()=>{}}}
  const createShutdown=new Function('fastify','closePrismaDatabase','process','console','starting','closeApplicationHttp','beginBackgroundShutdown','stopInstanceTaskWorker','stopRestoreWorker','stopBackupUploadWorker',`let startupPromise=starting,shutdownPromise=null,shuttingDown=false,businessStartupReady=true;${javascript};return {run:gracefulShutdown,state:()=>({shuttingDown,businessStartupReady})}`)
  const shutdownHarness=createShutdown(shutdownFastify,async()=>{steps.push('database')},shutdownProcess,{log:()=>{}},starting,async(server:{close:()=>Promise<void>},drain:()=>Promise<void>)=>{await drain();await server.close()},async()=>{},async()=>{},async()=>{},async()=>{})
  const first=shutdownHarness.run('SIGTERM'),second=shutdownHarness.run('SIGINT')
  assert.equal(first,second,'two signals cannot race database/worker close')
  assert.deepEqual(shutdownHarness.state(),{shuttingDown:true,businessStartupReady:false})
  assert.deepEqual(steps,[],'database and Fastify remain open while startup finishes')
  releaseStartup();await first
  assert.deepEqual(steps,['fastify','database','exit'])
  console.log('PASS protected startup shutdown: signals registered early, startup drain precedes database close, repeated signals share one close')
  const managed=await import('../../src/services/scheduler-lifecycle.js')
  assert.ok(source.includes("forceCloseConnections: 'idle'"),'idle keepalive sockets must not hold shutdown, active responses still finish')
  assert.ok(!source.includes('setInterval('),'startup cleanup timers must use managed admission and drain')
  const httpServer=Fastify({forceCloseConnections:'idle'})
  let releaseResponse!:()=>void,responseStarted!:()=>void
  const responseGate=new Promise<void>(resolve=>{releaseResponse=resolve}),responseEntered=new Promise<void>(resolve=>{responseStarted=resolve})
  httpServer.get('/active',async()=>{responseStarted();await responseGate;return {completed:true}})
  httpServer.get('/idle',async()=>({ok:true}))
  await httpServer.listen({host:'127.0.0.1',port:0})
  const address=httpServer.server.address();assert.ok(address&&typeof address==='object')
  const idleAgent=new http.Agent({keepAlive:true}),activeAgent=new http.Agent({keepAlive:true})
  const get=(path:string,agent:http.Agent)=>new Promise<string>((resolve,reject)=>{http.get({host:'127.0.0.1',port:address.port,path,agent},response=>{let body='';response.on('data',data=>body+=data);response.on('end',()=>resolve(body))}).on('error',reject)})
  await get('/idle',idleAgent)
  const activeResponse=get('/active',activeAgent);await responseEntered
  let httpClosed=false;const httpClose=closeApplicationHttp(httpServer).then(()=>{httpClosed=true})
  await new Promise(resolve=>setTimeout(resolve,10));assert.equal(httpClosed,false,'a real in-flight response is not destroyed')
  releaseResponse();assert.deepEqual(JSON.parse(await activeResponse),{completed:true});await httpClose
  idleAgent.destroy();activeAgent.destroy()
  const slowClose=Fastify({pluginTimeout:30,forceCloseConnections:'idle'})
  let releaseSlow!:()=>void
  const slowWork=new Promise<void>(resolve=>{releaseSlow=resolve})
  slowClose.addHook('preClose',async()=>{await slowWork})
  await slowClose.listen({host:'127.0.0.1',port:0})
  let slowClosed=false
  const closingSlow=closeApplicationHttp(slowClose,()=>slowWork).then(()=>{slowClosed=true})
  await new Promise(resolve=>setTimeout(resolve,80))
  assert.equal(slowClosed,false,'resource work longer than pluginTimeout remains alive outside timed preClose')
  assert.equal(slowClose.server.listening,false,'new HTTP connections stop before waiting for background work')
  releaseSlow();await closingSlow
  assert.equal(slowClosed,true)
  console.log('PASS resource shutdown exceeds plugin timeout without timing out preClose; new HTTP admission stopped')
  let releaseInterval!:()=>void,intervalStarted!:()=>void
  const intervalGate=new Promise<void>(resolve=>{releaseInterval=resolve}),intervalEntered=new Promise<void>(resolve=>{intervalStarted=resolve})
  let intervalCalls=0
  managed.scheduleInterval(async()=>{intervalCalls++;intervalStarted();await intervalGate},60000,true)
  await intervalEntered
  let releaseSchedule!:()=>void,releaseNested!:()=>void
  const gate=new Promise<void>(resolve=>{releaseSchedule=resolve})
  const nestedGate=new Promise<void>(resolve=>{releaseNested=resolve})
  let runs=0
  const task=managed.schedule('0 0 1 1 *',async()=>{runs++;await gate;void managed.trackScheduledWork(()=>nestedGate)},{name:'isolated-lifecycle'})
  await task.stop()
  const execution=task.execute()
  await new Promise(resolve=>setTimeout(resolve,10))
  assert.equal(runs,1)
  let schedulesStopped=false
  const stop=managed.stopManagedSchedules().then(()=>{schedulesStopped=true})
  assert.equal(schedulesStopped,false)
  releaseSchedule();await execution
  await new Promise(resolve=>setTimeout(resolve,10))
  assert.equal(schedulesStopped,false,'late nested scheduler work remains part of shutdown')
  releaseNested();await new Promise(resolve=>setTimeout(resolve,10))
  assert.equal(schedulesStopped,false,'current timer work is part of the same shutdown drain')
  releaseInterval();await stop
  managed.scheduleInterval(async()=>{intervalCalls++},1,true)
  await new Promise(resolve=>setTimeout(resolve,10));assert.equal(intervalCalls,1,'stopped timers cannot accept new callbacks')
  await task.execute()
  assert.equal(runs,1,'stopped schedule cannot begin new work even when manually executed')
  await task.destroy()
  const background=file.statements.find(node=>ts.isFunctionDeclaration(node)&&node.name?.text==='beginBackgroundShutdown')
  assert.ok(background)
  const backgroundJs=ts.transpileModule(background.getText(file),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText
  const stops=['stopManagedSchedules','stopBillingScheduler','stopMailExpiryScheduler','stopTicketAutoCloseScheduler','stopPlatformBackupScheduler','stopHostNotificationEmailWorker','stopProxySiteOperationWorker','stopCheckoutWorker','stopHostOnboardingWorker','stopHostRepairWorker','stopSecurityHardeningWorker','stopSystemImageCacheWorker','stopPoolResourceReconciliation','stopPoolDiskPreparation','stopUserCleanupWorker','stopHostPublicIpSync','stopHostPublicIpv6Sync','stopRecoveryReviewWorker','stopHostOfflineAlertWorker']
  const admitted:string[]=[]
  let releaseOther!:()=>void
  const other=new Promise<void>(resolve=>{releaseOther=resolve})
  const callbacks=stops.map((name,index)=>()=>{admitted.push(name);return index===0?Promise.reject(Error('controlled stop failure')):index===1?other:Promise.resolve()})
  const createBackground=new Function('stopSystemMonitor','stopSessionCleanup','closeAllSessions',...stops,`let backgroundShutdown=null;${backgroundJs};return beginBackgroundShutdown`)
  const backgroundRun=createBackground(()=>{},()=>{},()=>{},...callbacks)
  let returned=false
  const backgroundResult=backgroundRun().catch(()=>{returned=true})
  await new Promise(resolve=>setTimeout(resolve,10))
  assert.deepEqual(admitted,stops,'every scheduler admission stops immediately')
  assert.equal(returned,false,'one failed stop cannot release the backend while another scheduler is still running')
  releaseOther();await backgroundResult
  assert.equal(returned,true)
  console.log('PASS failed scheduler stop still drains other work before backend exit')
  console.log('PASS real cron lifecycle: current and nested work drains, stopped schedules refuse new executions')
  console.log('PASS resource worker lifecycle: real Fastify waits for all drains, nested claim execution and failed work cleanup')
  console.log('PASS app worker lifecycle: hooks registered before ordinary/protected listen; real Fastify close awaits checkout and recovery cleanup')
}
