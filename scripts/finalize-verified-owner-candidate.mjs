// Original root launcher postflight for an independently signed owner candidate.
// Rebuild the seal only after every shipped file still equals that exact package
// and the real update task has completed successfully.
import assert from 'node:assert/strict'
import { readFileSync, lstatSync, realpathSync, existsSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { resolve, join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { createRequire } from 'node:module'
import { verifyPanelDigest } from './panel-package-signature.mjs'
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
if(process.argv[5]==='--check'){console.log('SIGNED_CANDIDATE_POSTFLIGHT_CHECK_PASSED');return}
execFileSync('/usr/local/libexec/incudal/incudal-online-task',['seal'],{stdio:'pipe',timeout:120000})
execFileSync('sha256sum',['--check','--strict','--quiet',seal],{cwd:app,stdio:'pipe'})
console.log('ORIGINAL_LAUNCHER_SIGNED_CANDIDATE_POSTFLIGHT_COMPLETE')
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)await main()
