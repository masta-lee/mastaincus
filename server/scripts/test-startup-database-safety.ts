import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { waitForStartupDatabase } from '../src/lib/database-startup.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
const repoRoot = resolve(__dirname, '../..')

function readRepoFile(path: string): string {
  return readFileSync(resolve(repoRoot, path), 'utf8')
}

const initSource = readRepoFile('server/src/db/init-prisma.ts')
const appSource = readRepoFile('server/src/app.ts')
const poolSource = readRepoFile('server/src/db/prisma.ts')
const envExample = readRepoFile('.env.example')
const installPanel = readRepoFile('scripts/install-panel.sh')
const serverPackage = readRepoFile('server/package.json')
const resetAdminPasswordSource = readRepoFile('server/scripts/reset-admin-password.ts')

const guardIndex = initSource.indexOf('function assertDatabaseResetAllowed(')
const resetIndex = initSource.indexOf('await resetDatabaseFast()')
const guardCallIndex = initSource.indexOf('assertDatabaseResetAllowed(shouldReset)')

assert.notEqual(guardIndex, -1, 'database initialization must define a production reset safety guard')
assert.notEqual(guardCallIndex, -1, 'database initialization must call the reset safety guard')
assert.notEqual(resetIndex, -1, 'database initialization must keep resetDatabaseFast explicit')
assert.ok(
  guardIndex < guardCallIndex && guardCallIndex < resetIndex,
  'production reset guard must run before resetDatabaseFast()'
)
assert.ok(
  initSource.includes("process.env.NODE_ENV !== 'production'") &&
    initSource.includes('ALLOW_PRODUCTION_DATABASE_RESET') &&
    initSource.includes("const productionResetConfirmation = 'RESET_PRODUCTION_DATABASE'") &&
    initSource.includes('RESET_DATABASE is disabled in production'),
  'production database reset must require an explicit second confirmation phrase'
)
assert.ok(
  appSource.includes("resetDatabase: process.env.RESET_DATABASE === 'true' || process.env.RESET_DATABASE === '1'"),
  'app startup must pass RESET_DATABASE intent through initPrismaDatabase for guarded handling'
)
const admissionIndex = appSource.indexOf('await waitForInitialDatabaseConnection(() => shuttingDown)')
assert.ok(admissionIndex > 0 && admissionIndex < appSource.indexOf('await assertRuntimeDatabaseRole(prisma)') &&
  admissionIndex < appSource.indexOf('await initializeFinancialDatabaseIntegrity()'),
  'read-only database admission must finish before role checks, financial initialization or business workers')
assert.ok(poolSource.includes("waitForStartupDatabase(() => pool.query('SELECT 1'), isStopping)"), 'startup readiness uses the original bounded pool and only SELECT 1')
for (const failure of [new Error('timeout exceeded when trying to connect'), new Error('Connection terminated due to connection timeout'), Object.assign(new Error('starting'), { code: '57P03' })]) {
  let attempts = 0, clock = 0
  assert.equal(await waitForStartupDatabase(async () => { if (++attempts < 3) throw failure }, () => false,
    { now: () => clock, sleep: async ms => { clock += ms } }), true)
  assert.equal(attempts, 3)
}
for (const failure of [Object.assign(new Error('timeout exceeded when trying to connect'), { code: '28P01' }),
  Object.assign(new Error('permission denied'), { code: '42501' }), new Error('FINANCIAL_INTEGRITY_FAILED'), new Error('unknown error')]) {
  let attempts = 0
  await assert.rejects(waitForStartupDatabase(async () => { attempts++; throw failure }, () => false), error => error === failure)
  assert.equal(attempts, 1, 'credential, authority and unknown failures never repeat')
}
{
  let clock = 0, attempts = 0
  const failure = Object.assign(new Error('offline'), { code: 'ECONNREFUSED' })
  await assert.rejects(waitForStartupDatabase(async () => { attempts++; throw failure }, () => false,
    { timeoutMs: 400, now: () => clock, sleep: async ms => { clock += ms } }), error => error === failure)
  assert.equal(clock, 400)
  assert.equal(attempts, 2, 'the initial connection retry never admits another read after its deadline')
}
{
  let stopping = false, attempts = 0, settle: (() => void) | undefined
  const pending = new Promise<void>(resolve => { settle = resolve })
  const admission = waitForStartupDatabase(async () => { attempts++; await pending }, () => stopping)
  stopping = true
  let finished = false; void admission.then(() => { finished = true })
  await Promise.resolve(); assert.equal(finished, false, 'shutdown retains ownership of the in-flight read')
  settle!(); assert.equal(await admission, false); assert.equal(attempts, 1)
  attempts = 0
  assert.equal(await waitForStartupDatabase(async () => { attempts++ }, () => true), false)
  assert.equal(attempts, 0)
}
{
  let stopping = false, attempts = 0
  assert.equal(await waitForStartupDatabase(async () => { attempts++; throw new Error('timeout exceeded when trying to connect') }, () => stopping,
    { now: () => 0, sleep: async () => { stopping = true } }), false)
  assert.equal(attempts, 1, 'shutdown during backoff starts no further connection')
}
assert.ok(
  !envExample.match(/^ALLOW_PRODUCTION_DATABASE_RESET=/m) &&
    !installPanel.match(/^ALLOW_PRODUCTION_DATABASE_RESET=/m),
  'production database reset confirmation must not be enabled by default in env templates or installer output'
)

assert.ok(
  initSource.includes('const minimumProductionAdminPasswordLength = 12') &&
    initSource.includes('const unsafeInitialAdminPasswordPatterns = [') &&
    initSource.includes('/change[_-]?me/i') &&
    initSource.includes('/replace/i') &&
    initSource.includes('/generate/i') &&
    initSource.includes('/placeholder/i') &&
    initSource.includes('function getUnsafeInitialAdminPasswordReason(password: string | undefined): string | null') &&
    initSource.includes('ADMIN_PASSWORD must be configured to a strong non-placeholder value in production'),
  'production initial admin password must reject missing, weak, default, and placeholder values'
)
assert.ok(
  envExample.includes('ADMIN_PASSWORD=change_me_admin_password') &&
    initSource.includes('change[_-]?me'),
  '.env.example admin password placeholder must be rejected by production initialization'
)
assert.ok(
  envExample.includes('ADMIN_EMAIL=admin@payincus.local') &&
    initSource.includes("process.env.ADMIN_EMAIL || process.env.ADMIN_INITIAL_EMAIL || 'admin@payincus.local'") &&
    !initSource.includes("email: 'admin@isvoro.com'"),
  'initial admin email must be configurable through ADMIN_EMAIL instead of being hardcoded'
)

assert.ok(
  serverPackage.includes('"reset:admin-password": "node --import tsx scripts/reset-admin-password.ts"') &&
    resetAdminPasswordSource.includes('RESET_ADMIN_PASSWORD') &&
    resetAdminPasswordSource.includes('ADMIN_PASSWORD') &&
    resetAdminPasswordSource.includes("const unsafeProductionConfirmation = 'I_UNDERSTAND'") &&
    resetAdminPasswordSource.includes('ALLOW_UNSAFE_ADMIN_PASSWORD') &&
    resetAdminPasswordSource.includes('RESET_ADMIN_DISABLE_2FA') &&
    resetAdminPasswordSource.includes('twoFactorEnabled: false') &&
    resetAdminPasswordSource.includes('revokeAllUserRefreshTokens(userId)') &&
    resetAdminPasswordSource.includes('invalidateUserAccessTokens(userId)') &&
    !resetAdminPasswordSource.includes('console.log(password)'),
  'admin password reset script must be available, production guarded, and must not print plaintext passwords'
)

console.log('startup database safety checks passed')
