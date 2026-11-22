import{readFile,writeFile,mkdir}from'node:fs/promises'
import{createHash}from'node:crypto'
import{execFileSync}from'node:child_process'
import{gzipSync}from'node:zlib'
import{resolve}from'node:path'
const input=process.argv[2]||'incus-compat-input',destination='agent/internal/provisioning/compat'
const runId=process.env.INCUS_COMPAT_BUILD_RUN||''
if(!/^[1-9]\d+$/.test(runId))throw Error('INCUS_COMPAT_BUILD_RUN_INVALID')
await mkdir(destination,{recursive:true})
for(const arch of['amd64','arm64']){
 const dir=resolve(input,arch);await mkdir(dir,{recursive:true})
 execFileSync('gh',['run','download',runId,'--name','incudal-incusd-sysinfo-'+arch,'--dir',dir],{stdio:'pipe'})
 const m=JSON.parse(await readFile(resolve(dir,'incusd-manifest.json'),'utf8')),b=await readFile(resolve(dir,'incusd'))
 if(m.purpose!=='alpine-incus-sysinfo-compat'||m.incusVersion!=='7.6.0'||m.sourceSha256!=='f57dcf2b781f6664b04b264e680d6b05a86303bbee717161110282e2a8891486'||m.patchedSourceSha256!=='501bf2ce32a2078bc8b99913f5e17f25ad621f1ff79c3d22a98a44bd2bc4b1d6'||m.lifecycleSourceSha256!=='819e0462aa64e4147520a8686b55f52f2ca6761b69fdb6058e8caa946741f637'||m.memorySourceSha256!=='56b95831a97677406958326f0a2d42a1aebc4589ebab8c616d9e735df2194f63'||m.memoryNamespaceSourceSha256!=='917e33a02226b436dd6724c59fdc04735cc7958a1ffa33bd80f5084b39fa2ed1'||m.memoryRaftSourceSha256!=='08af4c3ed863c1b7ce25d95aed06ab6ac9eb4d8e95f1c5884b7f699ab6151dce'||m.securityModulesScriptSha256!=='025e7a6456f97e4b28fad8d2d2b437cc177452001e65248345158f914f07c4a3'||m.memoryBuildDefault!=='disablethp=1'||m.memoryBudgetRevision!=='daemon-memory-v3'||m.size!==b.length||createHash('sha256').update(b).digest('hex')!==m.sha256||b.readUInt16LE(18)!==(arch==='amd64'?62:183))throw Error('INCUS_COMPAT_FIXED_ARTIFACT_MISMATCH')
 await writeFile(destination+'/manifest-'+arch+'.json',JSON.stringify(m));await writeFile(destination+'/incusd-'+arch+'.gz',gzipSync(b,{level:9}))
 await writeFile('agent/internal/provisioning/compat_payload_'+arch+'.go',`//go:build linux && ${arch}\npackage provisioning\nimport "embed"\n//go:embed compat/incusd-${arch}.gz compat/manifest-${arch}.json\nvar compatibilityPayload${arch} embed.FS\nfunc init(){compatibilityFiles=compatibilityPayload${arch}}\n`)
}
console.log('Prepared pinned, native-validated Incus compatibility payloads')
