import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { Readable } from 'node:stream'
import { createRequire, syncBuiltinESMExports } from 'node:module'
import { mock } from 'node:test'
import { storageHttpAgent } from '../src/storage/transport.js'

process.env.DATABASE_URL ||= 'postgresql://fixture:fixture@127.0.0.1:1/compile_only'
const require = createRequire(import.meta.url)
const dns = require('node:dns/promises')
const lookup = mock.method(dns, 'lookup', async () => [{ address: '1.1.1.1', family: 4 }])
syncBuiltinESMExports()
let requests = 0, expects = 0, uploaded = '', oversized = false
const server = createServer(async (request, response) => {
  requests++; if (request.headers.expect) expects++
  assert.match(request.headers.authorization || '', /^AWS4-HMAC-SHA256 /)
  if (request.method === 'PUT') {
    for await (const chunk of request) uploaded += chunk
    response.setHeader('ETag', '"fixture"'); response.end()
  } else if (request.method === 'DELETE') { response.statusCode = 204; response.end() }
  else if (request.url?.includes('list-type=2')) {
    response.setHeader('content-type', 'application/xml')
    response.end(oversized ? 'X'.repeat(2 * 1024 ** 2 + 1) : '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>fixture</Name><Contents><Key>root/archive.tar</Key></Contents></ListBucketResult>')
  } else { response.setHeader('content-type', 'application/octet-stream'); response.end('s3-fixture-data') }
})
await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
const port = (server.address() as { port: number }).port
const connection = mock.method(storageHttpAgent, 'createConnection', function (this: any, options: any, callback: any) {
  assert.equal(options.host, 'storage-security-transport.example')
  // Only the exact verified socket boundary is redirected to this local server.
  const method = Object.getPrototypeOf(Object.getPrototypeOf(storageHttpAgent)).createConnection
  return method.call(this, { ...options, host: '127.0.0.1', port }, callback)
})
try {
  const { S3Provider } = await import('../src/storage/providers/S3Provider.js')
  const provider = new S3Provider({ type: 'S3', host: `http://storage-security-transport.example:${port}`, username: 'fixture', password: 'fixture', basePath: '/root', extra: { bucket: 'fixture', region: 'test', forcePathStyle: true } })
  await provider.testConnection()
  await provider.uploadStream(Readable.from(['s3-fixture-data']), 'archive.tar')
  assert.ok(uploaded.includes('s3-fixture-data'))
  const stream = await provider.downloadStream('archive.tar'); let result = ''
  for await (const chunk of stream) result += chunk
  assert.equal(result, 's3-fixture-data')
  await provider.deleteFile('archive.tar')
  assert.equal(expects, 0, 'Expect must not create a second unverified SDK Agent')
  oversized = true
  await assert.rejects(provider.testConnection(), /TOO_LARGE/)
  assert.ok(requests >= 5)
  console.log('PASS actual S3 HTTP signing, streaming CRUD, verified Agent and pre-parser XML limits')
} finally {
  connection.mock.restore(); lookup.mock.restore(); syncBuiltinESMExports()
  storageHttpAgent.destroy(); server.closeAllConnections()
  await new Promise<void>(resolve => server.close(() => resolve()))
}
