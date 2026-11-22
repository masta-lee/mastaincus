import assert from 'node:assert/strict'
import dns from 'node:dns'
import promises from 'node:dns/promises'
import http from 'node:http'
import {syncBuiltinESMExports}from'node:module'
import{mock}from'node:test'
process.env.DATABASE_URL='postgresql://fixture:fixture@127.0.0.1:1/security_only'
let received=0, credentialReceived=false
const server=http.createServer((request,response)=>{
  received++;credentialReceived=typeof request.headers.authorization==='string'
  request.resume();response.writeHead(207,{'Content-Type':'application/xml'})
  response.end('<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>')
})
await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve))
const port=(server.address()as any).port,hostname='storage-dns-audit.example'
let preflights=0,connectLookups=0
const promiseMock=mock.method(promises,'lookup',async(host:string,...args:any[])=>{
  if(host!==hostname)throw Error('unexpected lookup');preflights++;return [{address:'1.1.1.1',family:4}]
})
const callbackMock=mock.method(dns,'lookup',((host:string,options:any,callback:any)=>{
  if(typeof options==='function'){callback=options;options={}}
  if(host!==hostname){callback(Error('unexpected lookup'));return}
  connectLookups++;queueMicrotask(()=>options?.all?callback(null,[{address:'127.0.0.1',family:4}]):callback(null,'127.0.0.1',4))
})as any)
syncBuiltinESMExports()
try{
  const {WebDavProvider}=await import('../src/storage/providers/WebDavProvider.ts')
  const provider=new WebDavProvider({type:'WEBDAV',host:`http://${hostname}:${port}`,username:'fixture-user',password:'fixture-password',basePath:'/'})
  await assert.rejects(provider.testConnection())
  assert.equal(received,0);assert.equal(credentialReceived,false)
  const {safeFetch,safeOutboundDispatcher}=await import('../src/lib/outbound-security.ts')
  const count=received
  await assert.rejects(safeFetch(`http://${hostname}:${port}/`))
  assert.equal(received,count,'connection-time verifier refuses rebinding')
  await safeOutboundDispatcher.close()
  console.log(JSON.stringify({isolatedLocalOnly:true,publicPreflights:preflights,loopbackConnects:connectLookups,webdavReachedPrivateTarget:false,credentialSentToPrivateTarget:credentialReceived,safeFetchControlRefused:true}))
}finally{
  promiseMock.mock.restore();callbackMock.mock.restore();syncBuiltinESMExports();server.closeAllConnections();await new Promise<void>(resolve=>server.close(()=>resolve()))
}
process.exit(0)
