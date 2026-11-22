import assert from 'node:assert/strict'
import Fastify from 'fastify'
import { request } from 'node:http'
import { ticketUploadBudget, beginTicketUploadProcessing, completeTicketUploadProcessing } from '../src/lib/request-budget.js'

const app=Fastify(),enterResolvers:Array<()=>void>=[]
let release!:()=>void,processing=0
const gate=new Promise<void>(resolve=>{release=resolve})
app.addHook('onRequest',async req=>{(req as any).user={id:1}})
app.post('/upload',{onRequest:ticketUploadBudget},async(req,reply)=>{
  beginTicketUploadProcessing(req);processing++;enterResolvers.forEach(resolve=>resolve())
  try{await gate;return reply.send({ok:true})}finally{processing--;completeTicketUploadProcessing(req)}
})
// Content is synthetic; the important part is the real socket cancellation
// while the handler continues owning memory/resources.
app.addContentTypeParser('multipart/form-data',async()=>({}))
const origin=await app.listen({host:'127.0.0.1',port:0})
try{
  const entered=new Promise<void>(resolve=>enterResolvers.push(resolve))
  const first=request(origin+'/upload',{method:'POST',headers:{'content-type':'multipart/form-data; boundary=fixture','content-length':'0'}})
  first.on('error',()=>{})
  first.end();await entered
  assert.equal(processing,1)
  const closed=new Promise<void>(resolve=>first.once('close',()=>resolve()))
  first.destroy();await closed
  const rejected=await app.inject({method:'POST',url:'/upload',headers:{'content-type':'multipart/form-data; boundary=fixture'}})
  assert.equal(rejected.statusCode,429,'aborted socket cannot release an active handler reservation')
  release()
  for(let n=0;processing&&n<100;n++)await new Promise(resolve=>setTimeout(resolve,5))
  const next=await app.inject({method:'POST',url:'/upload',headers:{'content-type':'multipart/form-data; boundary=fixture'}})
  assert.equal(next.statusCode,200,'handler finally must release the budget for a normal next request')
  console.log('PASS real cancelled upload keeps its global memory reservation until handler completion, then recovers')
}finally{release();await app.close()}
