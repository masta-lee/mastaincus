// Root-owned compatibility shim for sealed pre-role-separation releases.
// Suppress only two redundant DDL statements after proving defaults already
// match. Business credentials never receive object-owner authority.
import { createRequire } from 'node:module'
import { resolve } from 'node:path'
import * as nodeModule from 'node:module'
import { readFileSync, lstatSync, realpathSync, readlinkSync } from 'node:fs'
import { pathToFileURL, fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { existsSync } from 'node:fs'
const runtime = new URL(process.env.DATABASE_URL || 'postgresql://invalid@localhost/invalid')
if (runtime.username === 'incudal' && ['localhost','127.0.0.1','[::1]'].includes(runtime.hostname)) {
  const main=resolve(process.argv[1]||''), app=main.slice(0,main.indexOf('/server/dist/'))
  const legacy=app&&main.includes('/server/dist/')&&!readFileSync(app+'/server/dist/db/prisma.js','utf8').includes('protectAuthenticationClient')
  if(legacy){
    const version=JSON.parse(readFileSync(app+'/server/package.json','utf8')).version
    if(!['1.8.13','1.8.14'].includes(version))throw Error('DATABASE_LEGACY_VERSION_UNSUPPORTED')
    const root='/usr/local/libexec/incudal/database-compat-runtime'
    const baseline='/var/lib/incudal-finance/baseline.json'
    const marker=existsSync(baseline)?JSON.parse(readFileSync(baseline,'utf8')):{}
    if(marker.authenticationSignature||existsSync('/var/lib/incudal-database/migration.url')){
      const protectedFile=path=>{
        if(!path.startsWith(root+'/')||realpathSync(path)!==path)throw Error('DATABASE_COMPAT_RUNTIME_UNTRUSTED')
        for(let parent=path;parent!==root.slice(0,root.lastIndexOf('/'));parent=parent.slice(0,parent.lastIndexOf('/'))){const stat=lstatSync(parent);if(stat.uid!==0||stat.mode&0o022||stat.isSymbolicLink())throw Error('DATABASE_COMPAT_RUNTIME_UNTRUSTED')}
      }
      protectedFile(root+'/manifest.json')
      const manifest=JSON.parse(readFileSync(root+'/manifest.json','utf8'))
      if(manifest.version!==1||!manifest.files||typeof manifest.files!=='object')throw Error('DATABASE_COMPAT_RUNTIME_UNTRUSTED')
      for(const [relative,target]of Object.entries(manifest.links||{})){
        if(relative.startsWith('/')||relative.split('/').some(value=>value==='..'||value==='.')||typeof target!=='string')throw Error('DATABASE_COMPAT_RUNTIME_UNTRUSTED')
        const path=root+'/'+relative,stat=lstatSync(path)
        if(!stat.isSymbolicLink()||stat.uid!==0||readlinkSync(path)!==target||!realpathSync(path).startsWith(root+'/'))throw Error('DATABASE_COMPAT_RUNTIME_UNTRUSTED')
      }
      for(const [relative,hash]of Object.entries(manifest.files)){
        if(relative.startsWith('/')||relative.split('/').some(value=>value==='..'||value==='.')||typeof hash!=='string'||!/^[a-f0-9]{64}$/.test(hash))throw Error('DATABASE_COMPAT_RUNTIME_UNTRUSTED')
        const path=root+'/'+relative;protectedFile(path)
        if(createHash('sha256').update(readFileSync(path)).digest('hex')!==hash)throw Error('DATABASE_COMPAT_RUNTIME_UNTRUSTED')
      }
      const replacements=marker.authenticationSignature
        ? {'db/prisma.js':'db/legacy-security-bridge.js','lib/security.js':'lib/security.js','lib/oauth-provider.js':'lib/oauth-provider.js','db/notifications.js':'db/notifications.js','db/system-config.js':'db/system-config.js','db/lottery.js':'db/lottery.js','services/host-gateway-dns.js':'services/host-gateway-dns.js','db/oauth.js':'db/oauth.js','lib/system-update-runtime.js':'lib/system-update-runtime.js','lib/log-sanitizer.js':'lib/log-sanitizer.js'}
        : {'lib/system-update-runtime.js':'lib/system-update-runtime.js'}
      for(const relative of ['server/dist/db/prisma.js','server/dist/db/legacy-security-bridge.js','server/dist/lib/authentication-integrity.js','server/dist/lib/financial-integrity.js'])if(!manifest.files[relative])throw Error('DATABASE_COMPAT_RUNTIME_UNTRUSTED')
      if(typeof nodeModule.registerHooks!=='function')throw Error('DATABASE_LEGACY_SECURITY_REQUIRES_NODE_PATCH')
      nodeModule.registerHooks({resolve(specifier,context,next){
        const result=next(specifier,context)
        if(result.url.startsWith('file:')){
          const path=fileURLToPath(result.url),relative=path.startsWith(app+'/server/dist/')?path.slice((app+'/server/dist/').length):''
          if(replacements[relative])return {...result,url:pathToFileURL(root+'/server/dist/'+replacements[relative]).href}
        }
        return result
      }})
      if(marker.authenticationSignature){
        const current=await import(pathToFileURL(root+'/server/dist/db/prisma.js').href)
        await current.initializeFinancialDatabaseIntegrity()
      }
    }
  }
  const require=createRequire(resolve(process.argv[1]||'')),{Pool}=require('pg'),query=Pool.prototype.query
  const statements=new Map([
    ['ALTER TABLE "packages" ALTER COLUMN "network_mode" SET DEFAULT \'nat\'','packages'],
    ['ALTER TABLE "instances" ALTER COLUMN "network_mode" SET DEFAULT \'nat\'','instances']
  ])
  Pool.prototype.query=function(...args){
    const table=typeof args[0]==='string'?statements.get(args[0].trim()):undefined
    if(!table)return query.apply(this,args)
    return query.call(this,`SELECT pg_get_expr(d.adbin,d.adrelid) AS value FROM pg_attrdef d JOIN pg_attribute a ON a.attrelid=d.adrelid AND a.attnum=d.adnum JOIN pg_class c ON c.oid=d.adrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=$1 AND a.attname='network_mode'`,[table]).then(result=>{
      if(result.rows.length!==1||!/^'nat'::(?:"NetworkMode"|public\."NetworkMode")$/.test(result.rows[0].value))throw Error('DATABASE_LEGACY_DEFAULT_NOT_PREPARED')
      return {command:'ALTER',rowCount:0,rows:[],fields:[]}
    })
  }
}
