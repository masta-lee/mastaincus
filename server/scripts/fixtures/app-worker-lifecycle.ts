import assert from 'node:assert/strict'
import Fastify from 'fastify'
import ts from 'typescript'
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
  const resourceHook=hooks.find(hook=>/stopInstanceTaskWorker.*stopRestoreWorker.*stopBackupUploadWorker/.test(hook.getText(file)))
  assert.ok(resourceHook,'instance, restore and upload drains must be registered before listen')
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
  console.log('PASS resource worker lifecycle: real Fastify waits for all drains, nested claim execution and failed work cleanup')
  console.log('PASS app worker lifecycle: hooks registered before ordinary/protected listen; real Fastify close awaits checkout and recovery cleanup')
}
