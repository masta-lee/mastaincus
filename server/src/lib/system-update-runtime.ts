import { realpath, access } from 'node:fs/promises'
import { retainedMigrationIdentity } from './database-migration-identity.js'
import { resolve } from 'node:path'
import { runSystemUpdateCommand } from './system-update-command.js'

// Resolve in a fresh process: a worker has already imported its old Prisma/PG
// modules and Node's resolution cache must not satisfy a newly applied release.
const verifyRuntime = String.raw`
const fs=require('node:fs'),path=require('node:path'),{createRequire}=require('node:module');
try {
 const root=fs.realpathSync(process.argv[1]),metadata=JSON.parse(fs.readFileSync(path.join(root,'server/package.json'),'utf8'));
 const deps=Object.keys(metadata.dependencies||{}).filter(n=>!n.startsWith('@types/'));
 if(!deps.length)throw Error('OTA artifact has no declared server runtime dependencies');
 const resolver=createRequire(path.join(root,'server/package.json')),resolved=new Map();
 for(const name of deps){let file;try{
  if(name==='prisma'){const metadataFile=resolver.resolve('prisma/package.json'),pkg=JSON.parse(fs.readFileSync(metadataFile,'utf8'));const bin=typeof pkg.bin==='string'?pkg.bin:pkg.bin?.prisma;if(typeof bin!=='string')throw Error('missing Prisma CLI');file=fs.realpathSync(path.resolve(path.dirname(metadataFile),bin))}
  else file=fs.realpathSync(resolver.resolve(name))
 }catch{throw Error('OTA artifact is missing bundled runtime dependency: '+name)}
  if(!file.startsWith(root+path.sep))throw Error('OTA dependency resolves outside its release: '+name);resolved.set(name,file)}
 if(resolved.has('@prisma/client')){let generated;try{generated=fs.realpathSync(createRequire(resolved.get('@prisma/client')).resolve('.prisma/client/default'))}catch{throw Error('OTA artifact is missing its generated Prisma client')}
  if(!generated.startsWith(root+path.sep))throw Error('OTA generated Prisma client resolves outside its release')}
}catch(error){console.error(error.message);process.exitCode=1}
`
export async function assertBundledSystemUpdateRuntime(directory: string) {
 const root=await realpath(resolve(directory))
 await runSystemUpdateCommand(process.execPath,['-e',verifyRuntime,root],{
  cwd:root,env:{PATH:process.env.PATH,SystemRoot:process.env.SystemRoot},capture:true,timeoutMs:30000,label:'校验发行包内的完整运行依赖'
 })
}

// Run the trusted release's CLI directly. Corepack/pnpm may otherwise spend
// the migration window downloading a package-manager runtime from its cache.
const resolvePrismaCli = String.raw`
const fs=require('node:fs'),path=require('node:path'),{createRequire}=require('node:module');
const root=fs.realpathSync(process.argv[1]),resolver=createRequire(path.join(root,'server/package.json'));
const metadataFile=resolver.resolve('prisma/package.json'),pkg=JSON.parse(fs.readFileSync(metadataFile,'utf8'));
const bin=typeof pkg.bin==='string'?pkg.bin:pkg.bin?.prisma;
if(typeof bin!=='string')throw Error('OTA artifact is missing its Prisma CLI');
const cli=fs.realpathSync(path.resolve(path.dirname(metadataFile),bin));
if(!cli.startsWith(root+path.sep))throw Error('OTA Prisma CLI resolves outside its release');
process.stdout.write(cli);
`
export async function runBundledSystemUpdateMigrations(directory: string, options: {
 env: NodeJS.ProcessEnv; stdout: (data: Buffer) => void; stderr: (data: Buffer) => void
}) {
 const root=await realpath(resolve(directory))
 const cli=await runSystemUpdateCommand(process.execPath,['-e',resolvePrismaCli,root],{
  cwd:root,env:{PATH:process.env.PATH,SystemRoot:process.env.SystemRoot},capture:true,timeoutMs:30000,
  label:'校验发行包内的 Prisma 迁移入口'
 })
 // Prisma runs its command only as the main module, not when require() loads it.
 const environment = { ...options.env }
 // Root migration code must never inherit a business-process import shim or
 // library-injection environment when it executes the privileged CLI.
 for(const name of ['NODE_OPTIONS','NODE_PATH','LD_PRELOAD','LD_LIBRARY_PATH','BASH_ENV','ENV','PYTHONPATH','PYTHONHOME'])delete environment[name]
 if(process.platform==='linux'&&process.getuid?.()===0){
  const path='/var/lib/incudal-database/migration.url'
  const present=await access(path).then(()=>true,error=>{if(error.code==='ENOENT')return false;throw error})
  if(present)environment.DATABASE_URL=(await retainedMigrationIdentity(new URL(environment.DATABASE_URL||''))).href
 }
 await runSystemUpdateCommand(process.execPath,[cli,'migrate','deploy'],{
  cwd:resolve(root,'server'),...options,env:environment,timeoutMs:300000,label:'执行发行包内的 Prisma 数据库迁移'
 })
}
