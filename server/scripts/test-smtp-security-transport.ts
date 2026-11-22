import assert from 'node:assert/strict'
import { createServer as createTlsServer } from 'node:tls'
import { createServer as createTcpServer, type Socket } from 'node:net'
import { execFileSync, spawn } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

process.env.DATABASE_URL ||= 'postgresql://fixture:fixture@127.0.0.1:1/smtp_fixture'
if (process.env.SMTP_FIXTURE_CHILD) {
  const {createSmtpTransport}=await import('../src/lib/mailer.js')
  const mode=process.env.SMTP_FIXTURE_CHILD
  const transport=createSmtpTransport({host:'127.0.0.1',port:Number(process.env.SMTP_FIXTURE_PORT),secure:mode!=='plaintext',username:'synthetic-user',password:'synthetic-password'})
  try {
    if(mode==='trusted') {
      const sent=await transport.sendMail({from:'sender@example.invalid',to:'receiver@example.invalid',subject:'SMTP security fixture',text:'actual message'})
      assert.equal(sent.accepted.length,1)
      await assert.rejects(transport.sendMail({from:'sender@example.invalid',to:'receiver@example.invalid',attachments:[{path:process.env.SMTP_FIXTURE_FILE!}]}),/File access rejected/)
      await assert.rejects(transport.sendMail({from:'sender@example.invalid',to:'receiver@example.invalid',attachments:[{path:'http://127.0.0.1:1/secret'}]}),/Url access rejected/)
    } else await assert.rejects(transport.verify(),mode==='plaintext'?/STARTTLS|502|Error upgrading/ : /self.signed|certificate/i)
  } finally {transport.close(); const {closePrismaDatabase}=await import('../src/db/prisma.js');await closePrismaDatabase()}
} else {
  const folder=await mkdtemp(join(tmpdir(),'smtp-security-'))
  const key=join(folder,'key.pem'),cert=join(folder,'cert.pem'),file=join(folder,'secret')
  const messages:string[]=[],auth:string[]=[],plainAuth:string[]=[]
  const protocol=(socket:Socket,plain=false)=>{
    socket.on('error',()=>{});socket.setEncoding('utf8');socket.write('220 synthetic SMTP\r\n')
    let pending='',data=false,message=''
    socket.on('data',(value:string)=>{
      pending+=value
      let end:number
      while((end=pending.indexOf('\r\n'))>=0){const line=pending.slice(0,end);pending=pending.slice(end+2)
        if(data){if(line==='.') {data=false;messages.push(message);message='';socket.write('250 accepted\r\n')}else message+=line+'\n';continue}
        if(line.startsWith('EHLO')||line.startsWith('HELO'))socket.write('250-local fixture\r\n250 AUTH PLAIN\r\n')
        else if(line.startsWith('STARTTLS'))socket.write('502 TLS required but unavailable\r\n')
        else if(line.startsWith('AUTH')){(plain?plainAuth:auth).push(line);socket.write('235 authenticated\r\n')}
        else if(line==='DATA'){data=true;socket.write('354 data\r\n')}
        else if(line==='QUIT'){socket.end('221 goodbye\r\n')}
        else socket.write('250 OK\r\n')
      }
    })
  }
  let tlsServer:ReturnType<typeof createTlsServer>|undefined,plainServer:ReturnType<typeof createTcpServer>|undefined
  try {
    const openssl=process.env.OPENSSL_PATH||(process.platform==='win32'?'C:/Program Files/Git/usr/bin/openssl.exe':'openssl')
    execFileSync(openssl,['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore'})
    await writeFile(file,'must not be read')
    tlsServer=createTlsServer({key:await readFile(key),cert:await readFile(cert)},socket=>protocol(socket));tlsServer.on('tlsClientError',()=>{})
    plainServer=createTcpServer(socket=>protocol(socket,true))
    await Promise.all([new Promise<void>(done=>tlsServer!.listen(0,'127.0.0.1',done)),new Promise<void>(done=>plainServer!.listen(0,'127.0.0.1',done))])
    for(const mode of ['trusted','untrusted','plaintext']){
      const server=mode==='plaintext'?plainServer:tlsServer,port=(server.address() as {port:number}).port
      const env={...process.env,SMTP_FIXTURE_CHILD:mode,SMTP_FIXTURE_PORT:String(port),SMTP_FIXTURE_FILE:file,NODE_EXTRA_CA_CERTS:mode==='trusted'?cert:''}
      await new Promise<void>((done,reject)=>{const child=spawn(process.execPath,[...process.execArgv,process.argv[1]],{env,stdio:'inherit'});child.on('error',reject);child.on('close',code=>code===0?done():reject(new Error('SMTP fixture child failed')) )})
    }
    assert.equal(messages.filter(message=>message.includes('actual message')).length,1)
    assert.ok(auth.length>0);assert.equal(plainAuth.length,0,'plaintext server receives no SMTP credentials')
    console.log('PASS actual SMTP transport: trusted TLS delivery, bad certificate rejection, no plaintext authentication, local file and URL attachment denial')
  } finally {
    await Promise.all([tlsServer,plainServer].filter(Boolean).map(server=>new Promise<void>(done=>server!.close(()=>done()))))
    await rm(folder,{recursive:true,force:true})
  }
}
process.exit(0)
