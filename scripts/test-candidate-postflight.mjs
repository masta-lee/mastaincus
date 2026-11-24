import assert from'node:assert/strict'
import{mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync,symlinkSync,linkSync}from'node:fs'
import{join}from'node:path'
import{tmpdir}from'node:os'
import{execFileSync}from'node:child_process'
import{verifyInstalledCandidate}from'./finalize-verified-owner-candidate.mjs'
import{sealedRuntimeLinks}from'./sealed-runtime-links.mjs'
if(process.platform==='linux'&&process.getuid()===0){
 const root=mkdtempSync(join(tmpdir(),'incudal-postflight-'));try{
  const source=join(root,'source'),app=join(root,'app'),archive=join(root,'candidate.tar.gz'),version='v1.8.14-test.abcdef1'
  for(const dir of[source,app]){mkdirSync(dir);writeFileSync(join(dir,'runtime.js'),'exact original code\n');symlinkSync('runtime.js',join(dir,'runtime-link'))}
  const names=['space link','line\nlink','单引号\'','--option','@aws-sdk','agentkeepalive','ajv','Zpackage','apackage']
  for (const name of names) symlinkSync('target with\nline and space',join(app,name))
  symlinkSync('target\n\n',join(app,'trailing-newline'))
  const originalLinks=execFileSync('/bin/bash',['-c',String.raw`while IFS= read -r -d '' link; do printf '%q -> %q\n' "$link" "$(readlink -- "$link")"; done < <(find . -xdev -type l -print0 | sort -z)`],{cwd:app,encoding:'utf8'})
  assert.equal(sealedRuntimeLinks(app),originalLinks,'bulk read must retain original quoting, ordering and exact targets')
  const originalLocale=process.env.LC_ALL
  try{for(const locale of ['C',...execFileSync('locale',['-a'],{encoding:'utf8'}).split('\n').filter(value=>/^en_US\./i.test(value))]){
    process.env.LC_ALL=locale
    const expected=execFileSync('/bin/bash',['-c',String.raw`while IFS= read -r -d '' link; do printf '%q -> %q\n' "$link" "$(readlink -- "$link")"; done < <(find . -xdev -type l -print0 | sort -z)`],{cwd:app,encoding:'utf8'})
    assert.equal(sealedRuntimeLinks(app),expected,'original scoped package ordering and quoting must match '+locale)
  }}finally{if(originalLocale===undefined)delete process.env.LC_ALL;else process.env.LC_ALL=originalLocale}
  for (const name of names) rmSync(join(app,name))
  rmSync(join(app,'trailing-newline'))
  writeFileSync(join(source,'version.json'),JSON.stringify({version,deployedAt:null,gitCommit:'a'.repeat(12)}));writeFileSync(join(app,'version.json'),JSON.stringify({version,deployedAt:new Date().toISOString(),gitCommit:'a'.repeat(12)}))
  for(const dir of[source,app])linkSync(join(dir,'runtime.js'),join(dir,'runtime-hardlink.js'))
  execFileSync('tar',['-czf',archive,'-C',source,'.']);verifyInstalledCandidate(archive,app,version)
  writeFileSync(join(app,'runtime.js'),'injected');assert.throws(()=>verifyInstalledCandidate(archive,app,version));writeFileSync(join(app,'runtime.js'),readFileSync(join(source,'runtime.js')))
  writeFileSync(join(app,'extra-code.js'),'not shipped');assert.throws(()=>verifyInstalledCandidate(archive,app,version));rmSync(join(app,'extra-code.js'))
  const cache='server/node_modules/.cache/jiti/server-prisma.config.a586debf.mjs';mkdirSync(join(app,cache,'..'),{recursive:true});writeFileSync(join(app,cache),'generated-only');assert.throws(()=>verifyInstalledCandidate(archive,app,version));rmSync(join(app,cache))
  writeFileSync(join(app,'version.json'),JSON.stringify({version,deployedAt:'valid',gitCommit:'b'.repeat(12)}));assert.throws(()=>verifyInstalledCandidate(archive,app,version))
  console.log('PASS native exact candidate postflight rejects changed code/identity and allows only deployment timestamp')
 }finally{rmSync(root,{recursive:true,force:true})}
}else console.log('Candidate postflight native root checks run separately')
