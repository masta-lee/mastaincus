// Explicit owner-authorized incident containment. Credentials stay in a private
// local file and stdin. Never changes controller/WireGuard/customer identities.
import assert from 'node:assert/strict'
import { readFile, writeFile, rename, lstat } from 'node:fs/promises'
import { randomBytes, createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import { resolve, join } from 'node:path'
import { pathToFileURL } from 'node:url'
export async function rotateRootPassword({previous,password,connect,save}){
 const c=await connect(previous)
 try{
  await new Promise((done,reject)=>c.exec('chpasswd',(error,stream)=>{if(error)return reject(Error('ROOT_PASSWORD_CHANNEL_FAILED'));stream.on('data',()=>{});stream.stderr.on('data',()=>{});stream.on('close',code=>code===0?done():reject(Error('ROOT_PASSWORD_CHANGE_FAILED')));stream.end('root:'+password+'\n')}))
  const proof=await connect(password);proof.end()
  let oldRejected=false;try{const old=await connect(previous);old.end()}catch(e){oldRejected=e.level==='client-authentication'}
  assert.ok(oldRejected,'previous password must fail authentication')
  await save()
 }finally{c.end()}
}
async function main(){
const require=createRequire(resolve('server/package.json')),{Client}=require('ssh2')
assert.equal(process.env.INCUDAL_ROOT_PASSWORD_ROTATION,'owner-authorized')
const file=resolve(process.argv[2]||'');assert.equal(process.argv.length,3)
assert.ok(file.startsWith(join(process.env.USERPROFILE,'.codex','private','payincus')+require('node:path').sep))
const config=JSON.parse(await readFile(file,'utf8'));assert.equal(config.username,'root')
const fileInfo=await lstat(file);assert.ok(fileInfo.isFile()&&!fileInfo.isSymbolicLink()&&fileInfo.nlink===1)
const known=[]
for(const line of(await readFile(join(process.env.USERPROFILE,'.ssh','known_hosts'),'utf8')).split(/\r?\n/)){
 const fields=line.split(/\s+/);if(fields[2]&&fields[0]?.split(',').some(host=>host===config.hostname||host===`[${config.hostname}]:${config.port||22}`))known.push(createHash('sha256').update(Buffer.from(fields[2],'base64')).digest('base64'))
}
for(const m of(await readFile('logs/oss-fetch-production-inputs.cjs','utf8')).matchAll(/if\(connection\.hostname==='([^']+)'\)known\.push\('([^']+)'\)/g))if(m[1]===config.hostname)known.push(m[2])
assert.ok(known.length)
const password=randomBytes(36).toString('base64url'),pending=file+'.pending-rotation.json';await writeFile(pending,JSON.stringify({...config,password}),{flag:'wx',mode:0o600})
await writeFile(file+'.pre-rotation.private.json',JSON.stringify(config),{flag:'wx',mode:0o600})
const connect=password=>new Promise((resolve,reject)=>{const c=new Client();c.once('ready',()=>resolve(c));c.once('error',e=>{c.destroy();reject(e)});c.connect({host:config.hostname,port:config.port||22,username:'root',password,readyTimeout:15000,hostVerifier:key=>known.includes(createHash('sha256').update(key).digest('base64'))})})
try{await rotateRootPassword({previous:config.password,password,connect,save:async()=>rename(pending,file)})}catch{throw Error('ROOT_PASSWORD_ROTATION_NOT_CONFIRMED_PRIVATE_PENDING_RETAINED')}
 console.log('ROOT_PASSWORD_ROTATED_NEW_LOGIN_VERIFIED_OLD_PASSWORD_REJECTED')
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)await main()
