import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { Readable } from 'node:stream'
import { spawnSync } from 'node:child_process'
process.env.DATABASE_URL ||= 'postgresql://fixture:fixture@127.0.0.1:1/compile_only'
import { readBoundedResponse, limitReadable } from '../src/lib/bounded-response.js'
import { runStorageTest } from '../src/lib/request-budget.js'
import { normalizeStorageFilename, normalizeStorageBasePath } from '../src/storage/path.js'
import { readTelegramResponse } from '../src/lib/notification-response.js'
const { encodeRecoveryCodes, readRecoveryCodeHashes } = await import('../src/lib/security.js')
const { sealNotificationConfig, openNotificationConfig } = await import('../src/lib/notification-config.js')

process.env.ENCRYPTION_KEY='isolated-security-repair-test-key'
const envelope=sealNotificationConfig({botToken:'123:SyntheticOnly',chatId:'test'})
assert.ok(!JSON.stringify(envelope).includes('SyntheticOnly'))
assert.deepEqual(openNotificationConfig(envelope),{botToken:'123:SyntheticOnly',chatId:'test'})
assert.throws(()=>openNotificationConfig({...envelope,sealed:String(envelope.sealed).slice(0,-2)+'00'}))
assert.throws(()=>openNotificationConfig({botToken:'123:SyntheticOnly'}))
const codes=encodeRecoveryCodes(['ABCD-EFGH'])
assert.equal(readRecoveryCodeHashes(codes)?.length,1)
assert.equal(readRecoveryCodeHashes(JSON.stringify(['ABCD-EFGH'])),null)
assert.equal(await readBoundedResponse(Readable.from([Buffer.from('test')]),4),'test')
await assert.rejects(readBoundedResponse(Readable.from([Buffer.alloc(5)]),4),/TOO_LARGE/)
await assert.rejects(readBoundedResponse(limitReadable(Readable.from([Buffer.alloc(5)]),4),8),/TOO_LARGE/)
assert.deepEqual(await readTelegramResponse(Response.json({ok:false,description:'Bearer synthetic-only'})),{ok:false,description:'[REDACTED_JWT]'})
await assert.rejects(readTelegramResponse(Response.json({ok:'true'})),/INVALID/)
let responseCancelled = false
await assert.rejects(readTelegramResponse(new Response(new ReadableStream({
  start(controller) { controller.enqueue(new Uint8Array(65537)) },
  cancel() { responseCancelled = true }
}))),/TOO_LARGE/)
assert.ok(responseCancelled, 'oversized notification bodies must release the actual response stream')
for (const text of ['line\r\nDELE file','bad\u007f']) { assert.throws(()=>normalizeStorageFilename(text)); assert.throws(()=>normalizeStorageBasePath(text)) }
let release!:()=>void
const gate=new Promise<void>(resolve=>{release=resolve})
const tests=Array.from({length:4},()=>runStorageTest(()=>gate))
await assert.rejects(runStorageTest(()=>Promise.resolve()),error=>(error as {statusCode?:number}).statusCode===429)
release();await Promise.all(tests);await runStorageTest(()=>Promise.resolve())
const auth=await readFile(new URL('../src/lib/authentication-integrity.ts',import.meta.url),'utf8')
for(const model of ['refreshToken','userOAuthBinding','publicApiToken','oAuthGrant','twoFactorRecoveryCodes','notificationChannel','storageConfig'])assert.ok(auth.includes(model))
assert.ok(auth.includes('marker.authenticationSignature')&&auth.includes('verifyAuthenticationDatabaseSeals'))
assert.ok(auth.includes('const nativeTransaction=raw.$transaction.bind(raw)')&&auth.includes('overrides.set(property,value)'),'callback transaction overrides must not mutate the underlying financial wrapper and recurse')
const transport=await readFile(new URL('../src/storage/transport.ts',import.meta.url),'utf8')
assert.ok(transport.includes('revalidatingLookup')&&transport.includes('createConnection')&&transport.includes('isIpPrivateOrReserved'))
const terminal=await readFile(new URL('../src/lib/terminal-proxy.ts',import.meta.url),'utf8')
assert.ok(terminal.includes('TERMINAL_SERVER_IDENTITY_REQUIRED')&&!terminal.includes('rejectUnauthorized: false'))
const incus = await readFile(new URL('../src/lib/incus/incus-client.ts',import.meta.url),'utf8')
assert.ok(incus.includes('INCUS_SERVER_IDENTITY_REQUIRED'), 'production Incus API cannot fall back to an unverified server')
const oauth=await readFile(new URL('../src/lib/oauth-provider.ts',import.meta.url),'utf8')
assert.ok(oauth.includes('WHERE code_hash=${codeHash} FOR UPDATE')&&oauth.includes('WHERE token_hash=${refreshTokenHash} FOR UPDATE'))
const retained=await readFile(new URL('../../scripts/install-platform-backup.sh',import.meta.url),'utf8')
const ownership=await readFile(new URL('../../deploy/incudal-online-task.sh.example',import.meta.url),'utf8')
assert.ok(ownership.includes('if [[ "$app_dir" == "$INSTALL_DIR" ]]; then'),'an existing releases folder cannot skip active flat runtime hardening')
assert.ok(retained.includes('"$root/server/templates"')&&retained.includes('server/dist server/templates'),'rollback security modules need their matching runtime templates')
assert.ok(retained.includes('/usr/bin/chown -R root:root "$stage"')&&!/^\s*chown -R root:root "\$stage"/m.test(retained),'new root runtime preparation must not hit the old worker PATH chown wrapper')
const databasePreparation=await readFile(new URL('../../scripts/harden-database.py',import.meta.url),'utf8')
assert.ok(databasePreparation.match(/node_check=subprocess\.run\([^\n]+env=\{'PATH':'\/usr\/bin:\/bin'\}/),'Node patch preflight must not inherit the backend compatibility import or injection environment')
const migrationHelper=await readFile(new URL('../../scripts/migrate-database.sh',import.meta.url),'utf8')
assert.ok(migrationHelper.includes('umask 077')&&migrationHelper.includes('export JITI_FS_CACHE=false'),'root migrations must not generate reusable writable code caches inside node_modules')
assert.ok(migrationHelper.includes('[[ ! -L /opt/incudal/current ]]')&&!migrationHelper.includes('[[ -e "$root" ]] || root=/opt/incudal'),'only an actual atomic symlink selects the current runtime')
const python = spawnSync(process.env.PYTHON || 'python', ['../scripts/test-incus-security-modules.py'], { encoding: 'utf8', windowsHide: true })
assert.equal(python.status,0,python.stdout+python.stderr)
const shim=await readFile(new URL('../../scripts/legacy-database-startup.mjs',import.meta.url),'utf8')
assert.ok(shim.includes("marker.authenticationSignature||existsSync('/var/lib/incudal-database/migration.url')")&&shim.includes(": {'lib/system-update-runtime.js':'lib/system-update-runtime.js'}"),'pre-baseline role separation needs the root-only migration bridge on an old-worker retry')
const migrationRepair=await readFile(new URL('../src/services/host-management-repair.ts',import.meta.url),'utf8')
assert.ok(migrationRepair.includes('missingServerIdentity')&&migrationRepair.includes("host.managementSshUser!=='root'")&&migrationRepair.includes('previousFingerprint')&&migrationRepair.includes('HOST_TLS_IDENTITY_CHANGED'))
assert.ok(migrationRepair.indexOf('deps.verify(verifiedHost, signal)')<migrationRepair.indexOf('...identity, ...(missingCertificate'),'original SSH certificate migration must verify TLS before publishing the new pin')
console.log('PASS security repairs: strict credentials, recovery hashes, bounded response, session/permission seals, connection-time checks and TLS pins')
process.exit(0)
