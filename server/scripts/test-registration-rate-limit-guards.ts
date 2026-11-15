import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import Fastify from 'fastify'
import rateLimit from '@fastify/rate-limit'
import {applyConfiguredRouteRateLimits,findRateLimitRule,globalRateLimit} from '../src/config/rate-limit.js'
const source=readFileSync(new URL('../src/app.ts',import.meta.url),'utf8')
assert.ok(source.indexOf('applyConfiguredRouteRateLimits(fastify)') < source.indexOf('await fastify.register(rateLimit,'),'route policies must precede the plugin hook that consumes them')
const app=Fastify()
applyConfiguredRouteRateLimits(app)
await app.register(rateLimit,{...globalRateLimit,keyGenerator:req=>`${req.ip}:${findRateLimitRule(req.url,req.method)?.path||'global'}`})
app.post('/api/auth/register',async()=>({accepted:true}))
app.post('/api/auth/send-verification-code',async()=>({accepted:true}))
try {
 for(let n=0;n<5;n++){
  const result=await app.inject({method:'POST',url:'/api/auth/register?rotate='+n,remoteAddress:'203.0.113.20',headers:{'x-forwarded-for':`192.0.2.${n+1}`}})
  assert.equal(result.statusCode,n<3?200:429,'exactly three requests, query/header rotation cannot bypass')
 }
 assert.equal((await app.inject({method:'POST',url:'/api/auth/register',remoteAddress:'203.0.113.21'})).statusCode,200)
 for(let n=0;n<6;n++)assert.equal((await app.inject({method:'POST',url:'/api/auth/send-verification-code',remoteAddress:'203.0.113.20'})).statusCode,n<5?200:429)
 console.log('PASS real Fastify rate-limit plugin: installed route policy enforces 3/min registrations and 5/hour verification requests; spoofed headers and query rotation rejected')
} finally {await app.close()}
