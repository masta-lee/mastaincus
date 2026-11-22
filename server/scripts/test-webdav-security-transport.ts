import assert from 'node:assert/strict'
import {Readable} from 'node:stream'
import {createRequire,syncBuiltinESMExports}from'node:module'
process.env.DATABASE_URL='postgresql://fixture:fixture@127.0.0.1:1/compile_only'
const req=createRequire(import.meta.url),{MockAgent}=req('../node_modules/undici')
const agent=new MockAgent();agent.disableNetConnect()
const origin='https://storage-security-flow.example',pool=agent.get(origin)
const dav='<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/root/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>'
let received=0
const {mock}=await import('node:test'),dns=req('node:dns/promises')
const lookup=mock.method(dns,'lookup',async()=>[{address:'1.1.1.1',family:4}]);syncBuiltinESMExports()
const originalFetch=globalThis.fetch
globalThis.fetch=(url,init)=>originalFetch(url,{...init,dispatcher:agent}as any)
try{
 const {WebDavProvider}=await import('../src/storage/providers/WebDavProvider.ts')
 const provider=new WebDavProvider({type:'WEBDAV',host:origin,username:'fixture',password:'fixture',basePath:'/root'})
 pool.intercept({path:'/',method:'PROPFIND'}).reply(207,dav)
 await provider.testConnection()
 pool.intercept({path:'/root',method:'PROPFIND'}).reply(404,'')
 pool.intercept({path:'/root',method:'MKCOL'}).reply(201,'')
 pool.intercept({path:'/root/archive.tar',method:'PUT'}).reply(201,()=>{received++;return ''}).delay(100)
 await provider.uploadStream(Readable.from(['archive-fixture']),'archive.tar');assert.equal(received,1)
 pool.intercept({path:'/root/archive.tar',method:'GET'}).reply(200,'archive-fixture')
 const downloaded=await provider.downloadStream('archive.tar');let data='';for await(const chunk of downloaded)data+=chunk;assert.equal(data,'archive-fixture')
 pool.intercept({path:'/',method:'PROPFIND'}).reply(307,'',{headers:{location:'http://127.0.0.1/private'}})
 await assert.rejects(provider.testConnection(),/REDIRECT_REFUSED/)
 pool.intercept({path:'/',method:'PROPFIND'}).reply(207,'X'.repeat(2*1024**2+1))
 await assert.rejects(provider.testConnection(),/TOO_LARGE/)
 pool.intercept({path:'/root/archive.tar',method:'DELETE'}).reply(204,'')
 await provider.deleteFile('archive.tar')
 console.log(JSON.stringify({localMockTransport:true,normalXml:true,uploadWaitsRemoteSuccess:true,downloadStreams:true,redirectDenied:true,oversizedXmlDenied:true,deleteSuccess:true}))
}finally{globalThis.fetch=originalFetch;lookup.mock.restore();syncBuiltinESMExports();await agent.close()}
process.exit(0)
