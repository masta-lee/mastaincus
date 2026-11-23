// Disposable Linux service only: never stops or modifies the real backend.
import assert from 'node:assert/strict'
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import http from 'node:http'
const exec=promisify(execFile)
assert.equal(process.platform,'linux');assert.equal(process.getuid(),0)
assert.equal(process.env.INCUDAL_DRAIN_NATIVE_TEST,'disposable')
const app=resolve(process.env.INCUDAL_DRAIN_APP||fileURLToPath(new URL('..',import.meta.url)))
const source=await readFile(join(app,'deploy/incudal-backend.service.example'),'utf8')
const timeout=/^TimeoutStopSec=(.+)$/m.exec(source)?.[1];assert.equal(timeout,'35min')
const temporary=await mkdtemp(join(tmpdir(),'incudal-drain-')),unit='incudal-drain-test-'+process.pid
const require=createRequire(join(app,'server/package.json')),fastify=require.resolve('fastify')
const fixture=join(temporary,'fixture.mjs'),ready=join(temporary,'ready.json'),receipt=join(temporary,'closed.json')
const drainModule=join(app,'server/dist/lib/http-shutdown.js')
await writeFile(fixture,`import Fastify from ${JSON.stringify(fastify)};
import {closeApplicationHttp} from ${JSON.stringify(drainModule)};
import {writeFile} from 'node:fs/promises';
const f=Fastify({forceCloseConnections:'idle'});let stopped=false,workDone=false;let release;
const work=new Promise(r=>release=r);
f.get('/idle',async()=>({ok:true}));
f.get('/active',async()=>{setTimeout(()=>{workDone=true;release()},31000);await work;return{finished:true}});
await f.listen({host:'127.0.0.1',port:0});await writeFile(${JSON.stringify(ready)},JSON.stringify({port:f.server.address().port}));
process.on('SIGTERM',()=>{if(stopped)return;stopped=true;void(async()=>{await closeApplicationHttp(f);await work;await writeFile(${JSON.stringify(receipt)},JSON.stringify({workDone}));process.exit(0)})()});
`)
let active,idleAgent,activeAgent
try{
 await exec('systemd-run',['--unit='+unit,'--property=Type=exec','--property=User=root','--property=TimeoutStopSec='+timeout,process.execPath,fixture],{timeout:20000})
 let metadata;for(let n=0;n<100;n++){try{metadata=JSON.parse(await readFile(ready));break}catch{}await new Promise(r=>setTimeout(r,100))}
 assert.ok(metadata)
 const get=(path,agent)=>new Promise((resolve,reject)=>{http.get({host:'127.0.0.1',port:metadata.port,path,agent},r=>{let body='';r.on('data',b=>body+=b);r.on('end',()=>resolve(JSON.parse(body)))}).on('error',reject)})
 idleAgent=new http.Agent({keepAlive:true});activeAgent=new http.Agent({keepAlive:true})
 await get('/idle',idleAgent);active=get('/active',activeAgent)
 await new Promise(r=>setTimeout(r,200))
 const started=Date.now();await exec('systemctl',['stop',unit],{timeout:50000})
 assert.ok(Date.now()-started>30000,'in-flight work exceeding old stop budget must finish')
 assert.deepEqual(await active,{finished:true});assert.deepEqual(JSON.parse(await readFile(receipt)),{workDone:true})
 const{stdout}=await exec('journalctl',['-u',unit,'--no-pager'],{timeout:10000})
 assert.ok(!/timed out|signal SIGKILL|code=killed/.test(stdout))
 console.log('PASS real systemd: original 35min budget, 31sec active work completes, idle HTTP drains, no forced kill')
}finally{
 idleAgent?.destroy();activeAgent?.destroy()
 await exec('systemctl',['stop',unit],{timeout:10000}).catch(()=>{})
 await exec('systemctl',['reset-failed',unit],{timeout:10000}).catch(()=>{})
 await rm(temporary,{recursive:true,force:true})
}
