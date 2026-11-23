// Owner-authorized test deployment only. Atomically exchange signed release
// asset directories; never edit panel code, .env, host configuration or DB.
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, lstatSync, mkdtempSync, writeFileSync, renameSync, rmSync } from 'node:fs'
import { resolve, dirname, join } from 'node:path'
import { execFileSync } from 'node:child_process'
import { createHash, createPublicKey, verify } from 'node:crypto'
import { pathToFileURL } from 'node:url'

const publisher=createPublicKey({format:'der',type:'spki',key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from('y6C9aLon6OtgHPp5KPVDpxoNha95YptW03o4Dp2djQA=','base64')])})
export function verifyCandidateBundle(directory) {
  const expected=['incudal-agent-linux-amd64','incudal-agent-linux-arm64','manifest.json']
  assert.deepEqual(readdirSync(directory).sort(),expected)
  const metadata=lstatSync(join(directory,'manifest.json'))
  assert.ok(metadata.isFile()&&!metadata.isSymbolicLink()&&metadata.size<=1048576)
  const manifest=JSON.parse(readFileSync(join(directory,'manifest.json'),'utf8'))
  assert.match(manifest.version,/^v1\.0\.17-security\.[1-9][0-9]*$/)
  assert.match(manifest.sourceCommit,/^[a-f0-9]{40}$/)
  assert.deepEqual(Object.keys(manifest.files).sort(),['linux-amd64','linux-arm64'])
  for(const arch of ['amd64','arm64']) {
    const entry=manifest.files['linux-'+arch],name='incudal-agent-linux-'+arch,stat=lstatSync(join(directory,name))
    assert.equal(entry.name,name);assert.equal(entry.gzip,false)
    assert.ok(stat.isFile()&&!stat.isSymbolicLink()&&stat.size>20&&stat.size<=67108864)
    const bytes=readFileSync(join(directory,name)),digest=createHash('sha256').update(bytes).digest('hex')
    assert.equal(entry.size,bytes.length);assert.equal(entry.sha256,digest);assert.equal(entry.binarySha256,digest)
    assert.equal(bytes.subarray(0,4).toString('hex'),'7f454c46');assert.equal(bytes.readUInt16LE(18),arch==='amd64'?62:183)
    assert.match(entry.signature,/^[A-Za-z0-9+/]{86}==$/)
    assert.ok(verify(null,Buffer.from('payincus/agent-package/v1\n'+manifest.version.slice(1)+'\nlinux-'+arch+'\n'+digest),publisher,Buffer.from(entry.signature,'base64')))
  }
  return manifest
}

function protectedPath(path,leafDirectory=true) {
  for(let current=path;;current=dirname(current)) {
    const info=lstatSync(current)
    assert.ok(!info.isSymbolicLink()&&info.uid===0&&!(info.mode&0o022))
    if(current!==path||leafDirectory)assert.ok(info.isDirectory())
    if(current==='/')break
  }
}
export function exchangeCandidateDirectories(stage,destination) {
  execFileSync('/usr/bin/python3',['-I','-B','-c',"import ctypes,os,sys;lib=ctypes.CDLL(None,use_errno=True);fn=lib.renameat2;fn.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];r=fn(-100,os.fsencode(sys.argv[1]),-100,os.fsencode(sys.argv[2]),2);assert r==0,ctypes.get_errno();fd=os.open(os.path.dirname(sys.argv[1]),os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)",stage,destination])
}
function install(bundle) {
  assert.equal(process.platform,'linux');assert.equal(process.getuid(),0)
  const environment='/opt/incudal/.env';protectedPath(environment,false)
  const rows=readFileSync(environment,'utf8').split('\n').filter(line=>line.startsWith('INCUDAL_AGENT_RELEASE_DIR='))
  assert.equal(rows.length,1)
  const destination=rows[0].slice(rows[0].indexOf('=')+1).trim().replace(/^(['"])(.*)\1$/,'$2')
  assert.ok(/^\/var\/lib\/incudal-agent-release\/[A-Za-z0-9._-]+$/.test(destination))
  protectedPath(destination);protectedPath(bundle)
  const current=verifyCandidateBundle(destination),candidate=verifyCandidateBundle(bundle)
  assert.ok(BigInt(candidate.version.split('.').at(-1))>BigInt(current.version.split('.').at(-1)),'candidate must advance the installed test version')
  const info=lstatSync(destination),stage=mkdtempSync(join(dirname(destination),'.signed-candidate-'))
  let exchanged=false
  try {
    for(const name of readdirSync(bundle))writeFileSync(join(stage,name),readFileSync(join(bundle,name)),{mode:0o640})
    execFileSync('/usr/bin/chown',['-R','0:'+info.gid,stage])
    execFileSync('/usr/bin/chmod',['750',stage])
    assert.equal(verifyCandidateBundle(stage).version,candidate.version)
    exchangeCandidateDirectories(stage,destination)
    exchanged=true
    const retained=join(dirname(destination),'.before-'+candidate.version+'-'+Date.now())
    renameSync(stage,retained)
    assert.equal(verifyCandidateBundle(destination).version,candidate.version)
    console.log(JSON.stringify({installed:candidate.version,sourceCommit:candidate.sourceCommit,oldVersion:current.version,originalConfigurationUnchanged:true,atomicAssetExchange:true}))
  }finally{if(!exchanged)rmSync(stage,{recursive:true,force:true})}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  assert.equal(process.argv.length,3)
  install(resolve(process.argv[2]))
}
