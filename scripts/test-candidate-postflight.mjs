import assert from'node:assert/strict'
import{mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync,symlinkSync,linkSync,lstatSync}from'node:fs'
import{join}from'node:path'
import{createRequire}from'node:module'
import{tmpdir}from'node:os'
import{execFileSync}from'node:child_process'
import{verifyInstalledCandidate,assertRepositoryConfigurationMigration}from'./finalize-verified-owner-candidate.mjs'
import{sealedRuntimeLinks}from'./sealed-runtime-links.mjs'
const originalConfig=Buffer.from('SYSTEM_UPDATE_RELEASE_REPOSITORY="MASTALEE928/PAYINCUS" # retired\r\nINCUDAL_AGENT_RELEASE_REPOSITORY=mastalee928/payincus\r\nJWT_SECRET=fixture-unchanged\r\nGITHUB_REPOSITORY=custom/agent\r\n')
const migratedConfig=Buffer.from('SYSTEM_UPDATE_RELEASE_REPOSITORY="masta-lee/mastaincus" # retired\r\nINCUDAL_AGENT_RELEASE_REPOSITORY=masta-lee/mastaincus\r\nJWT_SECRET=fixture-unchanged\r\nGITHUB_REPOSITORY=custom/agent\r\n')
assertRepositoryConfigurationMigration(originalConfig,migratedConfig)
for(const changed of['JWT_SECRET=fixture-changed','GITHUB_REPOSITORY=wrong/agent'])assert.throws(()=>assertRepositoryConfigurationMigration(originalConfig,Buffer.from(migratedConfig.toString().replace(changed.startsWith('JWT')?'JWT_SECRET=fixture-unchanged':'GITHUB_REPOSITORY=custom/agent',changed))))
assert.throws(()=>assertRepositoryConfigurationMigration(originalConfig,Buffer.concat([migratedConfig,Buffer.from('NEW_AUTHORITY=wrong\n')])))
// Execute the actual base-system Bash parser/writer, with dotenv as an
// independent semantic oracle. All data and targets below are disposable.
const dotenv=createRequire(new URL('../server/package.json',import.meta.url))('dotenv')
const envRoot=mkdtempSync(join(tmpdir(),'incudal-source-env-'))
const slash=value=>value.replaceAll('\\','/')
const bash=process.platform==='win32'?'C:/Program Files/Git/bin/bash.exe':'/bin/bash'
const runner=String.raw`set -euo pipefail
source "$1"
ENV_FILE="$2"
GITHUB_REPO=masta-lee/mastaincus
log() { printf '%s\n' "$*"; }
case "$3" in
 read) get_env_value "$4" ;;
 migrate) for repository_key in SYSTEM_UPDATE_RELEASE_REPOSITORY INCUDAL_AGENT_RELEASE_REPOSITORY GITHUB_REPO GITHUB_REPOSITORY; do migrate_release_repository "$repository_key"; done ;;
 defaults)
   for read_key in KEEP SYSTEM_UPDATE_RELEASE_REPOSITORY INCUDAL_AGENT_RELEASE_REPOSITORY; do
     get_env_value "$read_key" > "$ENV_FILE.$read_key.before"
   done
   system_repository="$(get_release_repository_default GITHUB_REPO SYSTEM_UPDATE_RELEASE_REPOSITORY)" || exit 1
   agent_repository="$(get_release_repository_default GITHUB_REPOSITORY INCUDAL_AGENT_RELEASE_REPOSITORY)" || exit 1
   set_env_if_missing SYSTEM_UPDATE_RELEASE_REPOSITORY "$system_repository" fixture
   set_env_if_missing INCUDAL_AGENT_RELEASE_REPOSITORY "$agent_repository" fixture
   for repository_key in SYSTEM_UPDATE_RELEASE_REPOSITORY INCUDAL_AGENT_RELEASE_REPOSITORY GITHUB_REPO GITHUB_REPOSITORY; do migrate_release_repository "$repository_key"; done ;;
 missing) set_env_if_missing "$4" "$INCUDAL_ENV_FIXTURE_VALUE" fixture ;;
 set) set_env_value "$4" "$INCUDAL_ENV_FIXTURE_VALUE" fixture ;;
 exact-default) set_env_if_value "$4" "$5" "$INCUDAL_ENV_FIXTURE_VALUE" fixture ;;
 differential)
   get_env_value "$4" > "$ENV_FILE.source"
   get_env_value REVIEW_CREDENTIAL > "$ENV_FILE.credential"
   migrate_release_repository "$4" ;;
 concurrent)
   chmod() { printf 'KEEP=fixture-external-change\n' > "$ENV_FILE"; command chmod "$@"; }
   migrate_release_repository SYSTEM_UPDATE_RELEASE_REPOSITORY ;;
esac`
const cases=[
 {name:'export-and-key-whitespace-aliases',before:'export GITHUB_REPO = "custom/panel"\nGITHUB_REPOSITORY: custom/agent\nKEEP=fixture-retained',append:'SYSTEM_UPDATE_RELEASE_REPOSITORY=custom/panel\nINCUDAL_AGENT_RELEASE_REPOSITORY=custom/agent\n',panel:'custom/panel',agent:'custom/agent'},
 {name:'custom-primary-ignores-invalid-alias',before:'SYSTEM_UPDATE_RELEASE_REPOSITORY: custom/panel\nexport INCUDAL_AGENT_RELEASE_REPOSITORY = "custom/agent"\nGITHUB_REPO=invalid-alias\nGITHUB_REPOSITORY=mastalee928/payincus\nKEEP=fixture-retained',after:'SYSTEM_UPDATE_RELEASE_REPOSITORY: custom/panel\nexport INCUDAL_AGENT_RELEASE_REPOSITORY = "custom/agent"\nGITHUB_REPO=invalid-alias\nGITHUB_REPOSITORY=masta-lee/mastaincus\nKEEP=fixture-retained',panel:'custom/panel',agent:'custom/agent'},
 {name:'retired-export-colon-and-quote-format',before:' export  SYSTEM_UPDATE_RELEASE_REPOSITORY  =  "  MASTALEE928/PAYINCUS  " # retired\nINCUDAL_AGENT_RELEASE_REPOSITORY: `mastalee928/payincus` # retained comment\nKEEP=fixture-retained',after:' export  SYSTEM_UPDATE_RELEASE_REPOSITORY  =  "  masta-lee/mastaincus  " # retired\nINCUDAL_AGENT_RELEASE_REPOSITORY: `masta-lee/mastaincus` # retained comment\nKEEP=fixture-retained',panel:'masta-lee/mastaincus',agent:'masta-lee/mastaincus'},
 {name:'last-duplicate-primary-wins',before:'SYSTEM_UPDATE_RELEASE_REPOSITORY=mastalee928/payincus\nexport SYSTEM_UPDATE_RELEASE_REPOSITORY = "custom/last"\nINCUDAL_AGENT_RELEASE_REPOSITORY=custom/agent-first\n INCUDAL_AGENT_RELEASE_REPOSITORY = custom/agent-last\nKEEP=fixture-retained',after:'SYSTEM_UPDATE_RELEASE_REPOSITORY=masta-lee/mastaincus\nexport SYSTEM_UPDATE_RELEASE_REPOSITORY = "custom/last"\nINCUDAL_AGENT_RELEASE_REPOSITORY=custom/agent-first\n INCUDAL_AGENT_RELEASE_REPOSITORY = custom/agent-last\nKEEP=fixture-retained',panel:'custom/last',agent:'custom/agent-last'},
 {name:'empty-last-primary-inherits-alias',before:'SYSTEM_UPDATE_RELEASE_REPOSITORY=custom/first\nexport SYSTEM_UPDATE_RELEASE_REPOSITORY = "" # last empty\nINCUDAL_AGENT_RELEASE_REPOSITORY=" "\nGITHUB_REPO=custom/alias\nGITHUB_REPOSITORY=custom/agent\nKEEP=fixture-retained',after:'SYSTEM_UPDATE_RELEASE_REPOSITORY=custom/first\nexport SYSTEM_UPDATE_RELEASE_REPOSITORY = "custom/alias" # last empty\nINCUDAL_AGENT_RELEASE_REPOSITORY="custom/agent"\nGITHUB_REPO=custom/alias\nGITHUB_REPOSITORY=custom/agent\nKEEP=fixture-retained',panel:'custom/alias',agent:'custom/agent'},
 {name:'quoted-value-after-equals-newline',before:'GITHUB_REPO=\n"  custom/panel  "\nGITHUB_REPOSITORY=\n\'custom/agent\'\nKEEP=fixture-retained',append:'SYSTEM_UPDATE_RELEASE_REPOSITORY=custom/panel\nINCUDAL_AGENT_RELEASE_REPOSITORY=custom/agent\n',panel:'custom/panel',agent:'custom/agent'},
 ...["'",'"','`'].map(quote=>({name:'multiline-credential-'+quote,before:'KEEP='+quote+'fixture-first\nGITHUB_REPO=mastalee928/payincus\nSYSTEM_UPDATE_RELEASE_REPOSITORY=mastalee928/payincus\nfixture-last'+quote+'\nexport SYSTEM_UPDATE_RELEASE_REPOSITORY = custom/panel\nINCUDAL_AGENT_RELEASE_REPOSITORY=custom/agent',after:null,panel:'custom/panel',agent:'custom/agent'}))
]
// These review regressions construct one real retired source after the
// credential, so its last token is the exact expected replacement position.
// Getter semantics are checked independently with the installed dotenv parser.
const sourceKeys=['SYSTEM_UPDATE_RELEASE_REPOSITORY','INCUDAL_AGENT_RELEASE_REPOSITORY','GITHUB_REPO','GITHUB_REPOSITORY']
const retiredRepository='mastalee928/payincus',replacementRepository='masta-lee/mastaincus'
const differentialCases=[]
const addDataCase=(name,before,key=sourceKeys[0])=>differentialCases.push({name,before,key})
const sourceData=(credential,key=sourceKeys[0],eol='\n',finalLf=true)=>credential+eol+key+'='+retiredRepository+(finalLf?eol:'')
for(const key of sourceKeys)addDataCase('canonical-'+key,sourceData('REVIEW_CREDENTIAL=opaque-fixture',key),key)
addDataCase('export-key-space',sourceData('REVIEW_CREDENTIAL=opaque-fixture').replace(sourceKeys[0]+'=','export  '+sourceKeys[0]+'  =  '))
addDataCase('duplicate-custom-last',sourceData('REVIEW_CREDENTIAL=opaque-fixture')+sourceKeys[0]+'=custom/source\n')
addDataCase('duplicate-retired-last','REVIEW_CREDENTIAL=opaque-fixture\n'+sourceKeys[0]+'=custom/source\n'+sourceKeys[0]+'='+retiredRepository+'\n')
for(const eol of['\r\n','\r'])addDataCase('physical-eol-'+JSON.stringify(eol),sourceData('REVIEW_CREDENTIAL="opaque-fixture"',sourceKeys[0],eol))
addDataCase('no-final-lf',sourceData('REVIEW_CREDENTIAL="opaque-fixture"',sourceKeys[0],'\n',false))
for(const quote of["'",'"','`']){
 addDataCase('multiline-'+quote,sourceData('REVIEW_CREDENTIAL='+quote+'opaque-first\n'+sourceKeys[0]+'='+retiredRepository+'\nopaque-last'+quote))
 for(const count of[1,2])addDataCase('multiline-tail-slash-'+quote+'-'+count,sourceData('REVIEW_CREDENTIAL='+quote+'opaque-first\nopaque-last'+'\\'.repeat(count)+quote))
 addDataCase('unclosed-fallback-'+quote,sourceData('REVIEW_CREDENTIAL='+quote+'opaque-without-closing'))
}
addDataCase('escaped-quote-multiline',sourceData('REVIEW_CREDENTIAL="opaque\\"quoted\n'+sourceKeys[0]+'='+retiredRepository+'\nopaque-last"'))
addDataCase('escaped-tail-single-line',sourceData('REVIEW_CREDENTIAL="opaque-tail\\"'))
addDataCase('unclosed-double-escapes',sourceData('REVIEW_CREDENTIAL="opaque\\nopaque\\rwithout-closing'))
addDataCase('quoted-fallback-extra',sourceData('REVIEW_CREDENTIAL="opaque" extra\\n'))
addDataCase('bom-key-value-space',sourceData('REVIEW_CREDENTIAL=opaque-fixture').replace(sourceKeys[0]+'=','\ufeffexport\u00a0'+sourceKeys[0]+'\u2003=\u3000').replace(retiredRepository,'"\ufeff'+retiredRepository+'\u00a0"'))
addDataCase('unicode-space-set',sourceData('REVIEW_CREDENTIAL=opaque-fixture').replace(sourceKeys[0]+'=','\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000'+sourceKeys[0]+'='))
for(const separator of['\u2028','\u2029'])addDataCase('unicode-record-'+separator,'REVIEW_CREDENTIAL="opaque-fixture"'+separator+sourceKeys[0]+'="'+retiredRepository+'"\n')
addDataCase('colon-separator',sourceData('REVIEW_CREDENTIAL=opaque-fixture').replace(sourceKeys[0]+'=',sourceKeys[0]+': '))
for(const eol of['\n','\r\n','\r']){
 addDataCase('colon-bare-next-line-'+JSON.stringify(eol),'REVIEW_CREDENTIAL:'+eol+sourceKeys[0]+'='+retiredRepository+eol+'GITHUB_REPO='+retiredRepository+eol,'GITHUB_REPO')
 addDataCase('colon-quoted-next-line-'+JSON.stringify(eol),sourceData('REVIEW_CREDENTIAL:'+eol+'"opaque-fixture"',sourceKeys[0],eol))
}
for(const separator of['\u2028','\u2029'])addDataCase('colon-bare-unicode-record-'+separator,'REVIEW_CREDENTIAL:'+separator+sourceKeys[0]+'='+retiredRepository+'\nGITHUB_REPO='+retiredRepository+'\n','GITHUB_REPO')
addDataCase('comments','# '+sourceKeys[0]+'='+retiredRepository+'\n'+sourceData('REVIEW_CREDENTIAL="opaque-fixture"').replace(retiredRepository,'"'+retiredRepository+'" # retained comment'))
addDataCase('blank-value-next-quoted',sourceData('REVIEW_CREDENTIAL=\n"opaque-fixture"'))
assert.equal(differentialCases.length,41)
let envChecks=0
try{
 for(const filename of['install-panel.sh','init-env.sh']){
  const source=readFileSync(new URL('./'+filename,import.meta.url),'utf8')
  const names=['env_dotenv_data','get_env_value','env_file_identity','write_env_atomically','set_env_if_missing','get_release_repository_default','migrate_release_repository',...(filename==='install-panel.sh'?['set_env_value','set_env_if_value']:[])]
  const functions=names.map(name=>{const body=source.match(new RegExp('^'+name+'\\(\\) \\{[\\s\\S]*?^\\}','m'))?.[0];assert.ok(body,name);return body}).join('\n')
  const functionsPath=join(envRoot,filename+'.functions'),file=join(envRoot,filename+'.env')
  writeFileSync(functionsPath,functions,{mode:0o600})
  const childEnv=Object.fromEntries(Object.entries(process.env).filter(([key])=>!['BASH_ENV','ENV','SHELLOPTS','BASHOPTS','LD_PRELOAD','NODE_OPTIONS','NODE_PATH'].includes(key)))
  const run=(operation,key='',value='',expected='')=>execFileSync(bash,['--noprofile','--norc','-s','--',slash(functionsPath),slash(file),operation,key,expected],{input:runner,env:{...childEnv,INCUDAL_ENV_FIXTURE_VALUE:value},encoding:'utf8',maxBuffer:1024*1024,timeout:60000})
  for(const eol of['\n','\r\n'])for(const finalLf of[false,true])for(const test of cases){
   const before=test.before.replaceAll('\n',eol)+(finalLf?eol:'')
   writeFileSync(file,before,{mode:0o640})
   const parsed=dotenv.parse(before)
   const metadata=lstatSync(file),output=run('defaults'),after=readFileSync(file)
   for(const key of['KEEP','SYSTEM_UPDATE_RELEASE_REPOSITORY','INCUDAL_AGENT_RELEASE_REPOSITORY'])assert.deepEqual(readFileSync(file+'.'+key+'.before'),Buffer.from((parsed[key]??'')+'\n'),filename+'/'+test.name+' read '+key)
   const expected=test.append?before+(finalLf?'':eol)+test.append.replaceAll('\n',eol):(test.after??test.before).replaceAll('\n',eol)+(finalLf?eol:'')
   assert.deepEqual(after,Buffer.from(expected),filename+'/'+test.name+'/'+JSON.stringify(eol)+'/'+finalLf)
   const selected=dotenv.parse(after)
   assert.equal(selected.SYSTEM_UPDATE_RELEASE_REPOSITORY.trim(),test.panel)
   assert.equal(selected.INCUDAL_AGENT_RELEASE_REPOSITORY.trim(),test.agent)
   assert.equal(selected.KEEP,parsed.KEEP,'multiline credential value is preserved')
   const afterMetadata=lstatSync(file)
   assert.equal(afterMetadata.uid,metadata.uid);assert.equal(afterMetadata.gid,metadata.gid);assert.equal(afterMetadata.mode,metadata.mode)
   if(before===expected){assert.equal(afterMetadata.ino,metadata.ino);assert.ok(!output.includes('迁移'))}
   const stable=afterMetadata.ino
   run('migrate');assert.deepEqual(readFileSync(file),after);assert.equal(lstatSync(file).ino,stable)
   envChecks++
  }
  for(const eol of['\n','\r\n'])for(const finalLf of[false,true]){
   const before='KEEP=fixture-unmatched'+(finalLf?eol:'')
   writeFileSync(file,before,{mode:0o640});const inode=lstatSync(file).ino
   assert.ok(!run('migrate').includes('迁移'));assert.deepEqual(readFileSync(file),Buffer.from(before));assert.equal(lstatSync(file).ino,inode)
   const duplicate=('KEEP=fixture-first\nexport KEEP = "" # effective empty\nNEXT=fixture-retained').replaceAll('\n',eol)+(finalLf?eol:'')
   writeFileSync(file,duplicate,{mode:0o640});run('missing','KEEP','fixture-replacement')
   assert.deepEqual(readFileSync(file),Buffer.from(duplicate.replace('KEEP = ""','KEEP = "fixture-replacement"')))
   assert.equal(dotenv.parse(readFileSync(file)).KEEP,'fixture-replacement')
   if(filename==='install-panel.sh'){
    const custom=duplicate.replace('KEEP = ""','KEEP = "fixture-last"')
    writeFileSync(file,custom,{mode:0o640});run('set','KEEP','fixture-explicit')
    assert.deepEqual(readFileSync(file),Buffer.from(custom.replace('KEEP = "fixture-last"','KEEP = "fixture-explicit"')))
   }
   envChecks++
  }
  for(const test of differentialCases){
   const before=Buffer.from(test.before),parsed=dotenv.parse(before),position=test.before.lastIndexOf(retiredRepository)
   assert.ok(position>=0,test.name)
   const expected=Buffer.from(test.before.slice(0,position)+replacementRepository+test.before.slice(position+retiredRepository.length))
   writeFileSync(file,before,{mode:0o640});const metadata=lstatSync(file)
   run('differential',test.key)
   assert.deepEqual(readFileSync(file+'.source'),Buffer.from((parsed[test.key]??'')+'\n'),filename+'/'+test.name+' source getter')
   assert.deepEqual(readFileSync(file+'.credential'),Buffer.from((parsed.REVIEW_CREDENTIAL??'')+'\n'),filename+'/'+test.name+' credential getter')
   const after=readFileSync(file),updated=lstatSync(file)
   assert.deepEqual(after,expected,filename+'/'+test.name+' exact migration')
   assert.doesNotThrow(()=>assertRepositoryConfigurationMigration(before,after),filename+'/'+test.name+' migration postflight')
   assert.equal(dotenv.parse(after).REVIEW_CREDENTIAL,parsed.REVIEW_CREDENTIAL)
   assert.equal(updated.uid,metadata.uid);assert.equal(updated.gid,metadata.gid);assert.equal(updated.mode,metadata.mode)
   envChecks++
  }
  for(const [index,key]of['JWT_SECRET','COOKIE_SECRET','ENCRYPTION_KEY','ADMIN_PASSWORD','INCUDAL_AGENT_RELEASE_TOKEN'].entries()){
   const quote=["'",'"','`'][index%3],before=key+'='+quote+'\n'+quote+'\nNEXT=fixture-retained'
   writeFileSync(file,before,{mode:0o640});const inode=lstatSync(file).ino
   run('missing',key,'fixture-must-not-replace')
   assert.deepEqual(readFileSync(file),Buffer.from(before),filename+'/'+key+' newline-only credential')
   assert.equal(lstatSync(file).ino,inode);assert.equal(run('read',key),'\n\n')
   envChecks++
  }
  if(filename==='install-panel.sh'){
   for(const quote of["'",'"','`'])for(const count of[1,2]){
    const before=sourceData('REVIEW_CREDENTIAL='+quote+'initial-fixture'+quote),value='replacement-first\nreplacement-last'+'\\'.repeat(count)
    writeFileSync(file,before,{mode:0o640});run('set','REVIEW_CREDENTIAL',value)
    const after=readFileSync(file)
    assert.deepEqual(after,Buffer.from(before.replace('initial-fixture',value)))
    assert.equal(dotenv.parse(after).REVIEW_CREDENTIAL,value)
    assert.equal(run('read','REVIEW_CREDENTIAL'),value+'\n','setter output must be readable by its own parser')
    envChecks++
   }
   for(const trailingLf of[0,1,2]){
    const before='PORT="3000'+'\n'.repeat(trailingLf)+'"\nNEXT=fixture-retained'
    writeFileSync(file,before,{mode:0o640});run('exact-default','PORT','3001','3000')
    assert.deepEqual(readFileSync(file),Buffer.from(trailingLf?before:before.replace('3000','3001')),'exact default comparison preserves real trailing LF')
    envChecks++
   }
  }
  for(const before of['KEEP=fixture-retained\nexport GITHUB_REPO = invalid-alias','KEEP=fixture-retained\nSYSTEM_UPDATE_RELEASE_REPOSITORY=invalid-primary\nGITHUB_REPO=custom/alias',...['\n','\r\n','\r'].map(eol=>'GITHUB_REPO:'+eol+'SYSTEM_UPDATE_RELEASE_REPOSITORY='+retiredRepository+eol+'KEEP=fixture-retained')]){
   writeFileSync(file,before,{mode:0o640});const inode=lstatSync(file).ino
   assert.throws(()=>run('defaults'),error=>error.status===1&&!error.signal&&String(error.stderr).includes('Environment data parsing failed; original configuration retained.'));assert.deepEqual(readFileSync(file),Buffer.from(before));assert.equal(lstatSync(file).ino,inode)
   envChecks++
  }
  writeFileSync(file,'SYSTEM_UPDATE_RELEASE_REPOSITORY=mastalee928/payincus\nKEEP=fixture-retained',{mode:0o640})
  assert.throws(()=>run('concurrent'),error=>error.status===1&&!error.signal&&String(error.stderr).includes('Environment update failed; original configuration retained.'));assert.equal(readFileSync(file,'utf8'),'KEEP=fixture-external-change\n','concurrent configuration change must survive the stale candidate')
  envChecks++
  console.log('PASS repository env fixtures for',filename,'cumulative cases',envChecks)
 }
}finally{assert.ok(envRoot.startsWith(join(tmpdir(),'incudal-source-env-')));rmSync(envRoot,{recursive:true,force:true})}
console.log('PASS actual Bash/dotenv repository data cases',envChecks,'(CRLF, no final LF, multiline/fallback credentials, Unicode records, duplicate priority, exact defaults and concurrent edits)')
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
