import assert from 'node:assert/strict'
import {drainOwnedBackend,knownLegacyCloseTimeout} from './drain-legacy-owner-backend.mjs'
const running={MainPID:'42',Result:'success',ActiveState:'active'}
const inactive={MainPID:'0',Result:'success',ActiveState:'inactive'}
let states=[running,running,inactive],signalled=0
await drainOwnedBackend(()=>states.shift(),()=>signalled++,async()=>{})
assert.equal(signalled,1)
for(const changed of [{...running,MainPID:'43'},{...inactive,Result:'exit-code'},{...inactive,ActiveState:'failed'}]){
  states=[running,changed]
  await assert.rejects(drainOwnedBackend(()=>states.shift(),()=>{},async()=>{}))
}
let clock=0
await assert.rejects(drainOwnedBackend(()=>running,()=>{},async()=>{clock+=35*60*1000},()=>clock),/DRAIN_PENDING/)
const version={gitCommit:'994fff285e9b'},message=JSON.stringify({level:50,err:{type:'FastifyError',message:"Plugin did not start in time: ''.",stack:'at Timeout._onTimeout (/opt/incudal/node_modules/.pnpm/avvio@9.1.0/node_modules/avvio/boot.js:487:21)'}}),journal=JSON.stringify({MESSAGE:message})
assert.equal(knownLegacyCloseTimeout(version,journal),true)
for(const bad of ['', 'invalid-json',journal+'\n'+journal,JSON.stringify({MESSAGE:message.replace('FastifyError','Error')}),JSON.stringify({MESSAGE:message.replace('Plugin did not start in time:','Other failure:')})])assert.equal(knownLegacyCloseTimeout(version,bad),false)
assert.equal(knownLegacyCloseTimeout({gitCommit:'another-source'},journal),false)
console.log('PASS legacy backend drain: original PID, successful normal exit, changed/failed state rejection and finite timeout')
