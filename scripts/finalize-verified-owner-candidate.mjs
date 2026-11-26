// Original root launcher postflight for an independently signed owner candidate.
// Rebuild the seal only after every shipped file still equals that exact package
// and the real update task has completed successfully.
import assert from 'node:assert/strict'
import { readFileSync, lstatSync, realpathSync, existsSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { resolve, join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { createRequire } from 'node:module'
import { verifyPanelDigest } from './panel-package-signature.mjs'
export function assertRepositoryConfigurationMigration(before,after){
const original=before.toString('utf8');assert.ok(Buffer.from(original).equals(before),'REPOSITORY_CONFIG_ENCODING_INVALID')
const expected=original.replace(/^(SYSTEM_UPDATE_RELEASE_REPOSITORY|INCUDAL_AGENT_RELEASE_REPOSITORY|GITHUB_REPO|GITHUB_REPOSITORY)=([^\r\n]*)(\r?)$/gm,(line,key,raw)=>{
 let value=raw.split('#')[0].trim();if(value.length>=2&&['"',"'"].includes(value[0])&&value.at(-1)===value[0])value=value.slice(1,-1).trim()
 return value.toLowerCase()==='mastalee928/payincus'?key+'=masta-lee/mastaincus':line
})
assert.ok(Buffer.from(expected).equals(after),'REPOSITORY_MIGRATION_CHANGED_UNRELATED_CONFIGURATION')
}
export function migrateCandidateRepositoryConfiguration(archive,version){
assert.ok(process.platform==='linux'&&process.getuid()===0)
assert.ok(process.env.INCUDAL_OWNER_CANDIDATE_DEPLOY==='authorized-test'||process.env.GITHUB_ACTIONS==='true'&&process.env.RUNNER_ENVIRONMENT==='github-hosted')
const arch=process.arch==='arm64'?'arm64':'amd64',bytes=readFileSync(archive),sha=createHash('sha256').update(bytes).digest('hex')
assert.ok(verifyPanelDigest(version,arch,sha,readFileSync(archive+'.sig','utf8').trim()),'REPOSITORY_MIGRATION_CANDIDATE_SIGNATURE_INVALID')
const entries=execFileSync('/usr/bin/tar',['-tzf',archive],{encoding:'utf8',maxBuffer:64*1024*1024}).split('\n').filter(name=>name==='./scripts/install-panel.sh'||name==='scripts/install-panel.sh')
assert.equal(entries.length,1)
const installer=execFileSync('/usr/bin/tar',['-xOzf',archive,entries[0]],{maxBuffer:4*1024*1024})
assert.ok(installer.includes(Buffer.from('--migrate-release-repository)')),'CANDIDATE_REPOSITORY_MIGRATION_UNAVAILABLE')
const envPath='/opt/incudal/.env',before=readFileSync(envPath),metadata=lstatSync(envPath)
assert.ok(metadata.isFile()&&!metadata.isSymbolicLink()&&metadata.nlink===1&&metadata.uid===0)
const tools=mkdtempSync('/root/incudal-repository-source-'),script=join(tools,'install-panel.sh')
try{
 writeFileSync(script,installer,{mode:0o700,flag:'wx'})
 const childEnv=Object.fromEntries(Object.entries(process.env).filter(([key])=>!['BASH_ENV','ENV','SHELLOPTS','BASHOPTS','LD_PRELOAD','NODE_OPTIONS','NODE_PATH'].includes(key)))
 execFileSync('/usr/bin/bash',[script,'--migrate-release-repository'],{env:{...childEnv,PATH:'/usr/sbin:/usr/bin:/sbin:/bin'},stdio:'pipe',timeout:120000})
 assertRepositoryConfigurationMigration(before,readFileSync(envPath))
 const after=lstatSync(envPath);assert.ok(after.isFile()&&!after.isSymbolicLink()&&after.nlink===1&&after.uid===metadata.uid&&after.gid===metadata.gid&&after.mode===metadata.mode,'REPOSITORY_CONFIG_METADATA_CHANGED')
}finally{assert.ok(tools.startsWith('/root/incudal-repository-source-'));rmSync(tools,{recursive:true,force:true})}
console.log('REPOSITORY_SOURCES_MIGRATED_WITH_CREDENTIALS_PRESERVED')
}
export function verifyInstalledCandidate(archive,app,version,priorSeal='',generatedCache=''){
const script=String.raw`import pathlib,tarfile,hashlib,json,sys
archive,app,version,priorseal,generatedcache=sys.argv[1:];root=pathlib.Path(app);seen=set();count=0;previous={};digests={}
if priorseal:
 for line in pathlib.Path(priorseal).read_text().splitlines():
  assert len(line)>68 and line[64:68]=='  ./';previous[line[68:]]=line[:64]
with tarfile.open(archive,'r|gz')as t:
 for m in t:
  name=m.name.removeprefix('./');assert name not in seen;seen.add(name)
  if name=='.':assert m.isdir();continue
  assert not name.startswith('/')and not any(v in ['..','']for v in name.split('/'))
  if m.isfile()or m.islnk():
   p=root/name;s=p.lstat();assert p.is_file()and not p.is_symlink()and s.st_uid==0 and not(s.st_mode&0o022)
   current=p.read_bytes()
   if m.islnk():
    target=m.linkname.removeprefix('./');assert target in digests and hashlib.sha256(current).digest()==digests[target],name
    digests[name]=digests[target];count+=1;continue
   old=t.extractfile(m).read();digests[name]=hashlib.sha256(old).digest()
   if name=='version.json':
    a=json.loads(old);b=json.loads(current);assert a['version']==version and b['version']==version
    assert b.get('deployedAt')and a.get('deployedAt')is None;a.pop('deployedAt',None);b.pop('deployedAt',None);assert a==b
   else:assert hashlib.sha256(old).digest()==hashlib.sha256(current).digest(),name
   count+=1
  elif m.issym():
   p=root/name;s=p.lstat();assert p.is_symlink()and s.st_uid==0 and p.readlink().as_posix()==m.linkname
  else:assert m.isdir(),name
exclusions=['.git','.env','.gitconfig','server/certs','.npm','.cache','.incudal-update-downloads','update-logs','agent-release','.trusted-release-manifests']
for folder,dirs,files in __import__('os').walk(root,followlinks=False):
 for name in files+dirs:
  p=pathlib.Path(folder)/name;relative=p.relative_to(root).as_posix()
  if any(relative==x or relative.startswith(x+'/')for x in exclusions):continue
  if (p.is_file()or p.is_symlink())and relative not in seen:
   s=p.lstat();assert p.is_file()and not p.is_symlink()and s.st_uid==0 and not(s.st_mode&0o022)
   if relative=='server/node_modules/.cache/jiti/server-prisma.config.a586debf.mjs':assert generatedcache and hashlib.sha256(p.read_bytes()).hexdigest()==generatedcache,relative
   else:assert relative in previous and hashlib.sha256(p.read_bytes()).hexdigest()==previous[relative],relative
 dirs[:]=[name for name in dirs if not any((pathlib.Path(folder)/name).relative_to(root).as_posix()==x for x in exclusions)]
print('EXACT_SIGNED_CANDIDATE_POSTFLIGHT_FILES',count)`
console.log(execFileSync('python3',['-I','-B','-c',script,archive,app,version,priorSeal,generatedCache],{encoding:'utf8',stdio:'pipe'}).trim())
}
async function main(){
assert.equal(process.platform,'linux');assert.equal(process.getuid(),0)
assert.equal(process.env.INCUDAL_OWNER_CANDIDATE_DEPLOY,'authorized-test')
const archive=resolve(process.argv[2]||''),version=String(process.argv[3]||''),taskId=Number(process.argv[4])
assert.ok(process.argv.length===5||process.argv.length===6&&process.argv[5]==='--check');assert.match(version,/^v1\.8\.14-test\.[a-f0-9]{7}$/);assert.ok(Number.isSafeInteger(taskId)&&taskId>0)
const arch=process.arch==='arm64'?'arm64':'amd64',bytes=readFileSync(archive),sha=createHash('sha256').update(bytes).digest('hex')
assert.ok(verifyPanelDigest(version,arch,sha,readFileSync(archive+'.sig','utf8').trim()))
const app=realpathSync(existsSync('/opt/incudal/current')?'/opt/incudal/current':'/opt/incudal');assert.ok(app==='/opt/incudal'||app.startsWith('/opt/incudal/releases/'))
const seal='/var/lib/incudal-ota/manifests/'+createHash('sha256').update(app).digest('hex')+'.sha256',s=lstatSync(seal);assert.ok(s.uid===0&&!s.isSymbolicLink()&&!(s.mode&0o022))
const require=createRequire(join(app,'server/package.json')),prismaRequire=createRequire(require.resolve('prisma/config')),{createJiti}=prismaRequire('jiti')
const configPath=join(app,'server/prisma.config.ts'),jiti=createJiti(configPath,{fsCache:false})
const expected=jiti.transform({source:readFileSync(configPath,'utf8'),filename:configPath,ts:true,async:true}),cachePath=join(app,'server/node_modules/.cache/jiti/server-prisma.config.a586debf.mjs')
let generatedCache=''
if(existsSync(cachePath)){
 const content=readFileSync(cachePath,'utf8');assert.match(content,/ \/\* v9-[a-f0-9]{16} \*\/\n?$/)
 assert.equal(content.replace(/ \/\* v9-[a-f0-9]{16} \*\/\n?$/,''),expected)
 generatedCache=createHash('sha256').update(content).digest('hex')
}
verifyInstalledCandidate(archive,app,version,seal,generatedCache)
const helper='/usr/local/libexec/incudal/incudal-online-task',helperInfo=lstatSync(helper)
assert.ok(helperInfo.isFile()&&!helperInfo.isSymbolicLink()&&helperInfo.uid===0&&!(helperInfo.mode&0o022))
assert.deepEqual(readFileSync(helper),readFileSync(join(app,'deploy/incudal-online-task.sh.example')))
process.env.INCUDAL_APP_DIR=app;await import(join(app,'server/dist/config/env.js'))
const{prisma,closePrismaDatabase}=await import(join(app,'server/dist/db/prisma.js'))
try{const task=await prisma.systemUpdateTask.findUniqueOrThrow({where:{id:taskId}});assert.equal(task.status,'success');assert.equal(task.targetVersion,version);assert.ok(task.finishedAt)}finally{await closePrismaDatabase()}
const origins=execFileSync('git',['-C','/opt/incudal','config','--local','--get-all','remote.origin.url'],{encoding:'utf8'}).trim().split(/\r?\n/)
assert.ok(origins.length===1&&['https://github.com/masta-lee/mastaincus.git','https://github.com/mastalee928/payincus.git'].includes(origins[0]),'CANDIDATE_POSTFLIGHT_ORIGIN_UNTRUSTED')
assert.ok(execFileSync('git',['-C','/opt/incudal','remote','get-url','origin'],{encoding:'utf8'}).trim()===origins[0],'CANDIDATE_POSTFLIGHT_ORIGIN_REWRITTEN')
assert.ok(execFileSync('git',['-C','/opt/incudal','ls-remote','--get-url','https://github.com/masta-lee/mastaincus.git'],{encoding:'utf8'}).trim()==='https://github.com/masta-lee/mastaincus.git','CANDIDATE_POSTFLIGHT_SOURCE_REWRITTEN')
if(process.argv[5]==='--check'){console.log('SIGNED_CANDIDATE_POSTFLIGHT_CHECK_PASSED');return}
// This follows exact package and successful-task verification. The original
// worker's failed/rolled-back runtime and read-only check never change origin.
if(origins[0]==='https://github.com/mastalee928/payincus.git')execFileSync('git',['-C','/opt/incudal','remote','set-url','origin','https://github.com/masta-lee/mastaincus.git'],{stdio:'pipe'})
assert.ok(execFileSync('git',['-C','/opt/incudal','remote','get-url','origin'],{encoding:'utf8'}).trim()==='https://github.com/masta-lee/mastaincus.git','CANDIDATE_POSTFLIGHT_ORIGIN_MIGRATION_FAILED')
execFileSync('/usr/local/libexec/incudal/incudal-online-task',['seal'],{stdio:'pipe',timeout:120000})
execFileSync('sha256sum',['--check','--strict','--quiet',seal],{cwd:app,stdio:'pipe'})
console.log('ORIGINAL_LAUNCHER_SIGNED_CANDIDATE_POSTFLIGHT_COMPLETE')
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)await main()
