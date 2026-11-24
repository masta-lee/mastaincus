import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { createConnection, createServer } from 'node:net'
import { join } from 'node:path'

if (process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted' ||
    execFileSync('id', ['-u'], { encoding: 'utf8' }).trim() !== '0') {
  throw new Error('DISPOSABLE_GITHUB_ROOT_DATABASE_ADMISSION_REQUIRED')
}
const modulePath = '/opt/incudal/server/dist/lib/database-startup.js'
const serverRoot = '/opt/incudal/server'
const evidence = await mkdtemp('/tmp/incudal-database-admission-')
const require = createRequire(join(serverRoot, 'package.json'))
const { Pool } = require('pg')
const sockets = new Set()
let server, pool, badPasswordPool, databaseUnit
let phase = 'read-installed-module'
const result = { success: false, readOnly: true, actualPostgreSQL: true }

function pids() {
  assert.match(databaseUnit, /^postgresql@(?:16|17|18)-main$/)
  return ['incudal-backend', databaseUnit].map(unit =>
    execFileSync('systemctl', ['show', unit, '--property=MainPID', '--value'], { encoding: 'utf8', timeout: 20_000 }).trim())
}
async function protectedFiles() {
  const files = ['/opt/incudal/.env', '/var/lib/incudal-finance/baseline.json',
    ...['identity.json', 'enrollment.json', 'signing.pem'].map(name => '/var/lib/incudal-gateway-controller/' + name)]
  return Object.fromEntries(await Promise.all(files.map(async path =>
    [path, createHash('sha256').update(await readFile(path)).digest('hex')])))
}
try {
  const { waitForStartupDatabase } = await import(modulePath)
  phase = 'read-database-configuration'
  const matches = (await readFile('/opt/incudal/.env', 'utf8')).match(/^DATABASE_URL=(.+)$/gm)
  assert.equal(matches?.length, 1)
  const database = new URL(matches[0].slice('DATABASE_URL='.length).trim().replace(/^(['"])(.*)\1$/, '$2'))
  assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(database.hostname))
  assert.equal(database.pathname, '/incudal')
  // The installer retains an existing supported PostgreSQL. Newer GitHub
  // images may already run 17/18; never fingerprint an unrelated 16 unit.
  phase = 'identify-original-database-service'
  const version = execFileSync('runuser', ['-u', 'postgres', '--', 'psql', '-X', '-At',
    '-p', String(database.port || 5432), '-d', 'incudal', '-c', 'SHOW server_version_num'],
    { encoding: 'utf8', timeout: 20_000 }).trim()
  assert.match(version, /^[0-9]{6}$/)
  const major = Math.floor(Number(version) / 10_000)
  assert.ok([16, 17, 18].includes(major))
  databaseUnit = 'postgresql@' + major + '-main'
  result.postgresqlMajor = major
  phase = 'fingerprint-original-runtime'
  const originalPids = pids(), originalFiles = await protectedFiles()
  assert.ok(originalPids.every(pid => Number(pid) > 1))
  let connections = 0
  server = createServer(socket => {
    sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket))
    if (++connections <= 2) return // Real TCP handshakes; PostgreSQL admission remains pending until the original pool times out.
    const upstream = createConnection({ host: database.hostname === '[::1]' ? '::1' : database.hostname, port: Number(database.port || 5432) })
    sockets.add(upstream); upstream.on('error', () => socket.destroy()); upstream.once('close', () => { sockets.delete(upstream); socket.destroy() })
    socket.once('close', () => upstream.destroy()); socket.pipe(upstream); upstream.pipe(socket)
  })
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve) })
  const address = server.address(); assert.ok(address && typeof address !== 'string')
  const forwarded = new URL(database); forwarded.hostname = '127.0.0.1'; forwarded.port = String(address.port)
  pool = new Pool({ connectionString: forwarded.href, max: 1, connectionTimeoutMillis: 5_000, statement_timeout: 15_000, query_timeout: 15_000 })
  pool.on('error', () => {})
  let reads = 0
  phase = 'read-through-two-real-connection-timeouts'
  assert.equal(await waitForStartupDatabase(async () => { reads++; return pool.query('SELECT 1') }, () => false), true)
  assert.equal(reads, 3); assert.equal(connections, 3)
  assert.equal((await pool.query('SELECT 1')).rows[0]['?column?'], 1)
  assert.equal(pool.waitingCount, 0)
  const invalid = new URL(database); invalid.password = 'deliberately-invalid-disposable-test-password'
  badPasswordPool = new Pool({ connectionString: invalid.href, max: 1, connectionTimeoutMillis: 15_000, statement_timeout: 15_000, query_timeout: 15_000 })
  badPasswordPool.on('error', () => {})
  let invalidAttempts = 0
  phase = 'reject-invalid-database-password'
  await assert.rejects(waitForStartupDatabase(async () => { invalidAttempts++; return badPasswordPool.query('SELECT 1') }, () => false),
    error => error?.code === '28P01')
  assert.equal(invalidAttempts, 1)
  phase = 'verify-original-runtime-preserved'
  assert.deepEqual(pids(), originalPids); assert.deepEqual(await protectedFiles(), originalFiles)
  result.success = true; result.transientConnectionRetries = 2; result.authenticationFailureAttempts = 1
  result.originalBackendAndDatabasePreserved = true; result.configurationIdentityFinancePreserved = true
} catch (error) {
  await writeFile(join(evidence, 'error.private.log'), String(error?.stack || 'DATABASE_ADMISSION_FAILED'), { mode: 0o600 })
  result.failedPhase = phase
  result.errorCode = typeof error?.code === 'string' && /^[A-Z0-9_]{1,64}$/.test(error.code) ? error.code : 'DATABASE_ADMISSION_FAILED'
  console.error('NATIVE_DATABASE_ADMISSION_FAILED; ' + JSON.stringify({ phase, code: result.errorCode, postgresqlMajor: result.postgresqlMajor }) + '; private evidence: ' + evidence)
  process.exitCode = 1
} finally {
  await badPasswordPool?.end(); await pool?.end()
  for (const socket of sockets) socket.destroy()
  if (server) await new Promise(resolve => server.close(resolve))
  await writeFile(join(evidence, 'summary.json'), JSON.stringify(result), { mode: 0o600 })
}
if (result.success) console.log('PASS real PostgreSQL startup admission: ' + JSON.stringify(result))
