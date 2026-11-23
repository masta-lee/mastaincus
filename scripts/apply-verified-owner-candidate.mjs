// Deploy an unpublished, publisher-signed candidate through the installed OTA
// worker. Only the candidate Release HTTP transport is supplied locally; all
// package verification, backup, migrations, readiness and rollback stay real.
import assert from 'node:assert/strict'
import {readFileSync,createReadStream,existsSync,realpathSync,lstatSync} from 'node:fs'
import {createHash,createPublicKey,verify} from 'node:crypto'
import {execFileSync} from 'node:child_process'
import {Readable} from 'node:stream'
import {resolve,basename,join} from 'node:path'

assert.equal(process.platform,'linux');assert.equal(process.getuid(),0)
assert.equal(process.env.INCUDAL_OWNER_CANDIDATE_DEPLOY,'authorized-test')
const archive=resolve(process.argv[2]||''),version=String(process.argv[3]||'')
assert.ok(process.argv.length===4||process.argv.length===5&&process.argv[4]==='--preflight')
const finalizeTool=join(import.meta.dirname,'finalize-verified-owner-candidate.mjs')
const finalizer=lstatSync(finalizeTool);assert.ok(finalizer.isFile()&&!finalizer.isSymbolicLink()&&finalizer.uid===0&&!(finalizer.mode&0o022))
assert.match(version,/^v1\.8\.14-test\.[a-f0-9]{7}$/)
const arch=process.arch==='arm64'?'arm64':'amd64',name=`incudal-${version}-linux-${arch}.tar.gz`
assert.equal(basename(archive),name)
const bytes=readFileSync(archive),sha256=createHash('sha256').update(bytes).digest('hex'),signature=readFileSync(archive+'.sig','utf8').trim()
const key=createPublicKey({format:'der',type:'spki',key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from('y6C9aLon6OtgHPp5KPVDpxoNha95YptW03o4Dp2djQA=','base64')])})
assert.ok(verify(null,Buffer.from('payincus/panel-package/v1\n'+version.slice(1)+'\nlinux-'+arch+'\n'+sha256),key,Buffer.from(signature,'base64')))
const app=realpathSync(existsSync('/opt/incudal/current')?'/opt/incudal/current':'/opt/incudal')
assert.ok(app==='/opt/incudal'||app.startsWith('/opt/incudal/releases/'))
assert.ok(!existsSync('/var/lib/incudal-backup/recovery-hold.json'))
// Match the root launcher's sealed current source checks before importing it.
const sourceManifest='/var/lib/incudal-ota/manifests/'+createHash('sha256').update(app).digest('hex')+'.sha256'
for(const file of[sourceManifest,sourceManifest+'.links']){const s=lstatSync(file);assert.ok(s.isFile()&&!s.isSymbolicLink()&&s.uid===0&&s.gid===0&&!(s.mode&0o022))}
execFileSync('sha256sum',['--check','--strict','--quiet',sourceManifest],{cwd:app,stdio:'pipe'})
const links=execFileSync('/bin/bash',['-c',String.raw`while IFS= read -r -d '' link; do printf '%q -> %q\n' "$link" "$(readlink -- "$link")"; done < <(find . -xdev -type l ! -path './server/certs/*' ! -path './.npm/*' ! -path './.cache/*' ! -path './.incudal-update-downloads/*' ! -path './update-logs/*' ! -path './agent-release/*' -print0 | sort -z)`],{cwd:app,encoding:'utf8'})
assert.equal(links,readFileSync(sourceManifest+'.links','utf8'))
assert.equal(execFileSync('git',['-C','/opt/incudal','remote','get-url','origin'],{encoding:'utf8'}).trim(),'https://github.com/mastalee928/payincus.git')
process.env.INCUDAL_APP_DIR=app;process.env.INSTALL_DIR='/opt/incudal';process.env.SYSTEM_UPDATE_APPLY_MODE='artifact';process.env.SERVICE_NAME='incudal-backend'
assert.notEqual(process.env.RUN_DB_CHECKS,'0')
await import(app+'/server/dist/config/env.js')
const {prisma,closePrismaDatabase}=await import(app+'/server/dist/db/prisma.js')
assert.equal(await prisma.systemUpdateTask.count({where:{status:{in:['pending','running']}}}),0)
assert.equal(await prisma.instanceTask.count({where:{status:{in:['PENDING','PROCESSING']}}}),0)
assert.equal(await prisma.restoreTask.count({where:{status:{in:['PENDING','PROCESSING']}}}),0)
assert.equal(await prisma.backupUploadTask.count({where:{status:{in:['PENDING','PROCESSING']}}}),0)
const admin=await prisma.user.findFirstOrThrow({where:{role:'admin',status:'active'},orderBy:{id:'asc'},select:{id:true}})
if(process.argv[4]==='--preflight'){await closePrismaDatabase();console.log('OWNER_SIGNED_CANDIDATE_PREFLIGHT_PASSED');process.exit(0)}
const task=await prisma.systemUpdateTask.create({data:{targetVersion:version,status:'pending',startedByUserId:admin.id}})
const url=`https://github.com/mastalee928/payincus/releases/download/${version}/${name}`,manifestUrl=`https://github.com/mastalee928/payincus/releases/download/${version}/ota-manifest.json`
const manifest={artifacts:[{name,platform:'linux',arch,url,sha256,size:bytes.length,version,signature}]}
const release={tag_name:version,draft:false,prerelease:true,assets:[{id:1,name:'ota-manifest.json',browser_download_url:manifestUrl},{id:2,name,browser_download_url:url,size:bytes.length,digest:'sha256:'+sha256}]}
const original=globalThis.fetch
globalThis.fetch=async(input,options)=>{
 const address=String(input)
 if(address===`https://api.github.com/repos/mastalee928/payincus/releases/tags/${version}`)return Response.json(release)
 if(address===manifestUrl||address==='https://api.github.com/repos/mastalee928/payincus/releases/assets/1')return Response.json(manifest)
 if(address===url||address==='https://api.github.com/repos/mastalee928/payincus/releases/assets/2')return new Response(Readable.toWeb(createReadStream(archive)),{headers:{'content-length':String(bytes.length)}})
 return original(input,options)
}
process.env.PATH='/usr/local/libexec/incudal/ota-path:'+process.env.PATH
process.argv=[process.execPath,join(app,'server/dist/scripts/run-system-update-task.js'),String(task.id),version]
console.log('OWNER_SIGNED_CANDIDATE_TASK:'+task.id)
await import(join(app,'server/dist/scripts/run-system-update-task.js'))
// The installed worker starts its asynchronous main without exporting it.
// Match the root wrapper's postflight on natural successful worker completion.
process.once('beforeExit',()=>{
 if(process.exitCode)return
 execFileSync(process.execPath,[finalizeTool,archive,version,String(task.id)],{stdio:'inherit',timeout:180000})
})
