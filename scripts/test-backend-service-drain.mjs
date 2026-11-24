// Disposable Linux service only: never stops or modifies the real backend.
import assert from 'node:assert/strict'
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises'
import { execFile,execFileSync } from 'node:child_process'
import { promisify } from 'node:util'
import { join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import http from 'node:http'
import {drainOwnedBackend} from './drain-legacy-owner-backend.mjs'
const exec=promisify(execFile)
assert.equal(process.platform,'linux');assert.equal(process.getuid(),0)
assert.equal(process.env.INCUDAL_DRAIN_NATIVE_TEST,'disposable')
const app=resolve(process.env.INCUDAL_DRAIN_APP||fileURLToPath(new URL('..',import.meta.url)))
const source=await readFile(join(app,'deploy/incudal-backend.service.example'),'utf8')
const timeout=/^TimeoutStopSec=(.+)$/m.exec(source)?.[1];assert.equal(timeout,'35min')
assert.equal(/^TimeoutStartSec=(.+)$/m.exec(source)?.[1],'10min')
const temporary=await mkdtemp(join(tmpdir(),'incudal-drain-')),unit='incudal-drain-test-'+process.pid
const startupUnit=unit+'-startup'
const require=createRequire(join(app,'server/package.json')),fastify=require.resolve('fastify')
const fixture=join(temporary,'fixture.mjs'),ready=join(temporary,'ready.json'),receipt=join(temporary,'closed.json')
const drainModule=join(app,'server/dist/lib/http-shutdown.js')
await writeFile(fixture,`import Fastify from ${JSON.stringify(fastify)};
import {closeApplicationHttp} from ${JSON.stringify(drainModule)};
import {writeFile} from 'node:fs/promises';
const f=Fastify({forceCloseConnections:'idle'});let stopped=false,workDone=false;let release;
const work=new Promise(r=>release=r);
f.addHook('preClose',async()=>{await work});
f.get('/idle',async()=>({ok:true}));
f.get('/active',async()=>{setTimeout(()=>{workDone=true;release()},31000);await work;return{finished:true}});
await f.listen({host:'127.0.0.1',port:0});await writeFile(${JSON.stringify(ready)},JSON.stringify({port:f.server.address().port}));
process.on('SIGTERM',()=>{if(stopped)return;stopped=true;void(async()=>{await closeApplicationHttp(f,()=>work);await writeFile(${JSON.stringify(receipt)},JSON.stringify({workDone}));process.exit(0)})()});
`)
let active,idleAgent,activeAgent
try{
 await exec('systemd-run',['--unit='+unit,'--property=Type=exec','--property=User=root','--property=TimeoutStopSec=30s','--property=TimeoutStartSec=10min',process.execPath,fixture],{timeout:20000})
 let metadata;for(let n=0;n<100;n++){try{metadata=JSON.parse(await readFile(ready));break}catch{}await new Promise(r=>setTimeout(r,100))}
 assert.ok(metadata)
 const get=(path,agent)=>new Promise((resolve,reject)=>{http.get({host:'127.0.0.1',port:metadata.port,path,agent},r=>{let body='';r.on('data',b=>body+=b);r.on('end',()=>resolve(JSON.parse(body)))}).on('error',reject)})
 idleAgent=new http.Agent({keepAlive:true});activeAgent=new http.Agent({keepAlive:true})
 await get('/idle',idleAgent);active=get('/active',activeAgent)
 await new Promise(r=>setTimeout(r,200))
 const started=Date.now()
 const show=()=>Object.fromEntries(execFileSync('systemctl',['show',unit,'--property=MainPID,ActiveState,Result'],{encoding:'utf8'}).trim().split('\n').map(line=>line.split('=')))
 await drainOwnedBackend(show,()=>execFileSync('systemctl',['kill','--kill-whom=main','--signal=SIGTERM',unit],{stdio:'pipe'}))
 assert.ok(Date.now()-started>30000,'in-flight work exceeding old stop budget must finish')
 assert.deepEqual(await active,{finished:true});assert.deepEqual(JSON.parse(await readFile(receipt)),{workDone:true})
 const{stdout}=await exec('journalctl',['-u',unit,'--no-pager'],{timeout:10000})
 assert.ok(!/timed out|signal SIGKILL|code=killed/.test(stdout))
 console.log('PASS real systemd: legacy 30sec unit drains 31sec HTTP and preClose resource work with direct main-process signal, idle HTTP drains, no forced kill')
 const startupStarted=Date.now()
 await exec('systemd-run',['--unit='+startupUnit,'--wait','--property=Type=oneshot','--property=TimeoutStartSec=10min',
   '--property=ExecStartPre=/usr/bin/sleep 95','/usr/bin/true'],{timeout:125000})
 assert.ok(Date.now()-startupStarted>90000,'startup prerequisites exceeding the original systemd default must complete')
 const{stdout:startupLog}=await exec('journalctl',['-u',startupUnit,'--no-pager'],{timeout:10000})
 assert.ok(!/timed out|signal SIGKILL|code=killed/.test(startupLog))
 console.log('PASS real systemd: 95sec startup prerequisite completes with original 10min policy and no forced termination')
}finally{
 idleAgent?.destroy();activeAgent?.destroy()
 await exec('systemctl',['stop',unit],{timeout:10000}).catch(()=>{})
 await exec('systemctl',['reset-failed',unit],{timeout:10000}).catch(()=>{})
 await exec('systemctl',['stop',startupUnit],{timeout:10000}).catch(()=>{})
 await exec('systemctl',['reset-failed',startupUnit],{timeout:10000}).catch(()=>{})
 await rm(temporary,{recursive:true,force:true})
}
