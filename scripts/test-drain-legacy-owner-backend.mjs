import assert from 'node:assert/strict'
import {drainOwnedBackend} from './drain-legacy-owner-backend.mjs'
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
console.log('PASS legacy backend drain: original PID, successful normal exit, changed/failed state rejection and finite timeout')
