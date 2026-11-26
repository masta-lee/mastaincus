import assert from'node:assert/strict'
import{generateKeyPairSync}from'node:crypto'
import{createRequire}from'node:module'
import{resolve}from'node:path'
import{rotateRootPassword}from'./rotate-controller-root-password.mjs'
const require=createRequire(resolve('server/package.json')),{Server,Client}=require('ssh2')
const key=generateKeyPairSync('rsa',{modulusLength:2048}).privateKey.export({type:'pkcs1',format:'pem'}),previous='synthetic-old-only',password='synthetic-new-only'
for(const scenario of['normal','write-failed','old-still-valid']){
 let current=previous,saved=false,commands=[]
 const server=new Server({hostKeys:[key]},client=>{
  client.on('authentication',ctx=>ctx.method==='password'&&ctx.username==='root'&&(ctx.password===current||scenario==='old-still-valid'&&ctx.password===previous)?ctx.accept():ctx.reject())
  client.on('ready',()=>client.on('session',accept=>{const session=accept();session.on('exec',(accept,_reject,info)=>{commands.push(info.command);const stream=accept();let input='';stream.on('data',b=>input+=b);stream.on('end',()=>{assert.equal(input,'root:'+password+'\n');if(scenario==='write-failed'){stream.exit(1)}else{current=password;stream.exit(0)}stream.end()})})}))
 })
 await new Promise(r=>server.listen(0,'127.0.0.1',r))
 const connect=secret=>new Promise((r,j)=>{const c=new Client();c.once('ready',()=>r(c));c.once('error',e=>{c.destroy();j(e)});c.connect({host:'127.0.0.1',port:server.address().port,username:'root',password:secret,readyTimeout:3000})})
 try{const work=rotateRootPassword({previous,password,connect,save:async()=>{saved=true}});if(scenario==='normal'){await work;assert.ok(saved)}else{await assert.rejects(work);assert.ok(!saved)}assert.deepEqual(commands,['chpasswd'])}
 finally{await new Promise(r=>server.close(r))}
}
console.log('PASS actual SSH rotation: stdin only, new/old authentication checks, failed writes and incomplete revocation reject')
