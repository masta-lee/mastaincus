// Recover only the two known injected static entries from the original signed
// package. The pre-existing seal decides bytes; it is never replaced or renewed.
import assert from 'node:assert/strict'
import { readFileSync, lstatSync, realpathSync, openSync, closeSync, writeFileSync, fsyncSync, fchmodSync, fchownSync, renameSync, unlinkSync, existsSync } from 'node:fs'
import { createHash, randomUUID } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { resolve, dirname, join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { verifyPanelDigest } from './panel-package-signature.mjs'

const hash=bytes=>createHash('sha256').update(bytes).digest('hex')
export function verifiedStaticRepairs(app, manifest, original) {
  const entries=new Map()
  for(const line of manifest.trim().split('\n')){
    const match=/^([a-f0-9]{64})  (\.\/[\s\S]+)$/.exec(line)
    assert.ok(match,'unsupported original seal entry')
    const name=match[2].slice(2);assert.ok(!name.split('/').some(p=>p==='.'||p==='..'||!p));assert.ok(!entries.has(name))
    entries.set(name,match[1])
  }
  const repairs=[]
  for(const[name,digest]of entries){
    const path=join(app,name),stat=lstatSync(path)
    assert.ok(stat.isFile()&&!stat.isSymbolicLink()&&stat.uid===0&&!(stat.mode&0o022))
    const current=readFileSync(path);if(hash(current)===digest)continue
    assert.ok(['client/dist/user/index.html','client/dist/admin/index.html'].includes(name),'non-static source mismatch blocks recovery')
    assert.equal(stat.nlink,1,'restored static entry must not have a hard link')
    assert.equal(realpathSync(path),path,'restored static entry must not traverse a symlink')
    for(let parent=dirname(path);parent!==dirname(app);parent=dirname(parent)){
      const info=lstatSync(parent);assert.ok(info.isDirectory()&&!info.isSymbolicLink()&&info.uid===0&&!(info.mode&0o022))
    }
    const clean=original(name);assert.equal(hash(clean),digest,'original signed entry must match the existing seal')
    const injected=current.toString('utf8').match(/<script src="https:\/\/188-96A2175A\.jiaoyang677\.sbs\/lj\/e\.js" async><\/script>\r?\n/gu)||[]
    assert.equal(injected.length,1,'unrecognized static difference blocks recovery')
    assert.deepEqual(Buffer.from(current.toString('utf8').replace(injected[0],'')),clean,'only the known injected line may differ')
    repairs.push({name,path,current,clean,mode:stat.mode&0o777,gid:stat.gid})
  }
  assert.equal(repairs.length,2,'both known static entries must match the incident evidence')
  return repairs
}
export function restoreStaticRepairs(repairs) {
  const prepared=[];const installed=[]
  try{
    for(const row of repairs){
      const path=row.path+'.verified-recovery-'+randomUUID(),fd=openSync(path,'wx',row.mode)
      try{fchmodSync(fd,row.mode);fchownSync(fd,0,row.gid);writeFileSync(fd,row.clean);fsyncSync(fd)}finally{closeSync(fd)}
      prepared.push({...row,temp:path});assert.equal(hash(readFileSync(path)),hash(row.clean))
    }
    for(const row of prepared){assert.deepEqual(readFileSync(row.path),row.current);renameSync(row.temp,row.path);installed.push(row);const fd=openSync(dirname(row.path),'r');try{fsyncSync(fd)}finally{closeSync(fd)}}
  }catch(error){
    // Keep the incident bytes for investigation if publication did not finish.
    // Any completed restoration remains byte-exact to the original seal.
    throw error
  }finally{for(const row of prepared)if(existsSync(row.temp))unlinkSync(row.temp)}
  return installed.map(row=>row.name)
}
function main(){
  assert.equal(process.platform,'linux');assert.equal(process.getuid(),0)
  assert.equal(process.env.INCUDAL_STATIC_RECOVERY,'owner-authorized')
  const archive=resolve(process.argv[2]||''),version=String(process.argv[3]||''),mode=process.argv[4]
  assert.equal(process.argv.length,5);assert.ok(['--check','--apply'].includes(mode))
  assert.equal(version,'preview-f6fc302');assert.ok(archive.endsWith('/incudal-preview-f6fc302-linux-arm64.tar.gz'))
  assert.ok(verifyPanelDigest(version,'arm64',hash(readFileSync(archive)),readFileSync(archive+'.sig','utf8').trim()))
  const app=realpathSync('/opt/incudal');assert.equal(app,'/opt/incudal');assert.equal(JSON.parse(readFileSync(app+'/version.json')).gitCommit,'f6fc30215827')
  const seal='/var/lib/incudal-ota/manifests/'+hash(Buffer.from(app))+'.sha256',info=lstatSync(seal)
  assert.ok(info.isFile()&&!info.isSymbolicLink()&&info.uid===0&&!(info.mode&0o022))
  const repairs=verifiedStaticRepairs(app,readFileSync(seal,'utf8'),name=>execFileSync('tar',['-xOf',archive,'./'+name],{maxBuffer:1048576}))
  const evidence='/root/payincus-hot-security-20261123/incident-20261123-1327'
  for(const row of repairs)assert.deepEqual(readFileSync(join(evidence,row.name.includes('/user/')?'user-index.html':'admin-index.html')),row.current,'incident evidence required before restoration')
  console.log('ORIGINAL_SIGNED_STATIC_RECOVERY_VERIFIED',repairs.map(row=>row.name))
  if(mode==='--apply'){
    restoreStaticRepairs(repairs)
    execFileSync('sha256sum',['--check','--strict','--quiet',seal],{cwd:app,stdio:'pipe'})
    console.log('ORIGINAL_SEAL_PASSED_WITHOUT_RESEAL')
  }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)main()
