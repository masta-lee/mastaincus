// Real database/systemd recovery on disposable GitHub VMs. Only OSS transport
// is replaced with local files; no cloud credentials or customer hosts are used.
import assert from 'node:assert/strict'
import childProcess, { execFile } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { chown, copyFile, mkdtemp, readFile, rename, rm, stat, writeFile } from 'node:fs/promises'
import { createRequire, syncBuiltinESMExports } from 'node:module'
import { basename, join } from 'node:path'
import { promisify } from 'node:util'

assert.equal(process.env.GITHUB_ACTIONS, 'true', 'Disposable GitHub runner required')
assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted')
assert.equal(process.platform, 'linux')
assert.equal(process.getuid(), 0)
// Preserve real child execution, but report only fixed operation labels and
// exit metadata when the worker sanitizes an OS error. Never log argv or stderr:
// gateway commands and database utilities can carry identity/credential data.
const originalExec = childProcess.execFile
const originalPromisifiedExec = originalExec[promisify.custom]
const diagnosticExec = (...args) => originalExec(...args)
diagnosticExec[promisify.custom] = (...args) => {
  const pending = originalPromisifiedExec(...args)
  const result = pending.catch(error => {
    const operation = ['is-active', 'restart', 'start', 'stop', 'show', 'strip', 'syncconf', '-u', '-g'].includes(args[1]?.[0]) ? args[1][0] : 'other'
    console.error('Backup drill child failure', JSON.stringify({ program: basename(args[0]), operation,
      exitCode: Number.isInteger(error.code) ? error.code : null,
      signal: ['SIGTERM', 'SIGKILL'].includes(error.signal) ? error.signal : null,
      deviceMissing: /(?:Cannot find device|does not exist|No such device)/i.test(error.stderr || ''),
      deviceExists: /(?:already exists|File exists)/i.test(error.stderr || ''),
      serviceFailed: /Job for .* failed/i.test(error.stderr || '') }))
    throw error
  })
  result.child = pending.child
  return result
}
childProcess.execFile = diagnosticExec
syncBuiltinESMExports()
const exec = promisify(execFile)
const require = createRequire('/opt/incudal/server/package.json')
const initialEnv = require('dotenv').parse(await readFile('/opt/incudal/.env'))
Object.assign(process.env, initialEnv, { NODE_ENV: 'production', INCUDAL_APP_DIR: '/opt/incudal' })
const uid = Number((await exec('/usr/bin/id', ['-u', 'incudal'])).stdout.trim())
const gid = Number((await exec('/usr/bin/id', ['-g', 'incudal'])).stdout.trim())
process.setgid(gid) // Match the installed root:incudal oneshot's file ownership.
const core = await import('/opt/incudal/server/dist/services/platform-backup-core.js')
const { AliyunOssClient } = await import('/opt/incudal/server/dist/services/aliyun-oss-client.js')
const { runPlatformBackupTask } = await import('/opt/incudal/server/dist/services/platform-backup-worker.js')
const { pgQuery, localDatabaseAdmin, quoteIdentifier } = await import('/opt/incudal/server/dist/services/platform-backup-database.js')
const { controlRecoveryBackend, waitForProtectedBackendHealth } = await import('/opt/incudal/server/dist/services/platform-backup-health.js')
const { ensureBackupLocales } = await import('/opt/incudal/server/dist/services/platform-backup-locale.js')
const secured=await import('/opt/incudal/server/dist/db/prisma.js')
await secured.initializeFinancialDatabaseIntegrity()
const controllerRoot = '/var/lib/incudal-gateway-controller'
const controllerKeyBefore = createHash('sha256').update(await readFile(`${controllerRoot}/signing.pem`)).digest('hex')
const controllerIdentityBefore = await readFile(`${controllerRoot}/identity.json`, 'utf8')
const storage = await mkdtemp('/var/tmp/incudal-backup-drill-')
const records = new Map()
const preservedSource = `incudal_drill_${randomUUID().replaceAll('-', '')}`
let sourcePreserved = false
let config = core.normalizeConfig({ enabled: false, region: 'oss-cn-hangzhou', bucket: 'local-drill-only', prefix: 'drill/',
  accessKeyId: 'LocalDrillOnly', accessKeySecret: randomUUID(), backupPassword: randomUUID(), intervalHours: 24, retention: 3 })
const password = core.openSecret(config.backupPassword)
const saveConfig = async () => { await core.writeBackupConfig(config); await chown(core.statePath('inbox', 'config.json'), uid, gid) }
await saveConfig()
// Local object storage stubs are in this CI process only, never in production code.
AliyunOssClient.prototype.assertBackupBucket = async () => {}
AliyunOssClient.prototype.retain = async () => {}
AliyunOssClient.prototype.upload = async function (settings, source, metadata, verification, _checkpoint, readablePath) {
  const prefix = `${settings.prefix}${settings.installationId}/${metadata.id}/`
  const path = join(storage, metadata.id)
  await copyFile(source, path); await copyFile(path, verification)
  assert.equal(createHash('sha256').update(await readFile(verification)).digest('hex'), metadata.sha256)
  assert.ok(metadata.readableZip && readablePath)
  const zipCopy = join(storage, metadata.readableZip.name)
  await copyFile(readablePath, zipCopy)
  assert.equal(createHash('sha256').update(await readFile(zipCopy)).digest('hex'), metadata.readableZip.sha256)
  records.set(prefix, { ...metadata, prefix, path }); return prefix
}
AliyunOssClient.prototype.index = async prefix => { assert.ok(records.has(prefix)); return records.get(prefix) }
AliyunOssClient.prototype.download = async (record, destination) => { await copyFile(record.path, destination) }
// One bounded observation of the original worker in these empty CI fixtures.
// The installed worker has its own production limit and service budgets.
const recoveryObservationTimeout=15*60*1000
async function recoveryTaskDiagnostics(kind,id,startedAt,error=null) {
  const statuses=['pending','running','success','failed','warning']
  const stages=['accepted','preflight','verifying','checking_database','checking_compatibility','stopping','restoring_database',
    'protected_start','awaiting_review','rolled_back','waiting_agent_heartbeats','resumed','complete']
  const journalStages=['prepared','switching','database_switched','files_switched','protected_start','awaiting_review',
    'rolling_back','rollback_prepared','rolled_back_review']
  let result=null,hold=null,journal=null,readError=false
  try {
    result=await core.readJson(core.statePath('results',`${id}.json`))
    hold=await core.readJson(join(core.backupRoot(),'recovery-hold.json'))
    if(hold?.taskId)journal=await core.readJson(join(core.statePath('private',core.validateId(hold.taskId)),'journal.json'))
  } catch { readError=true }
  console.error('Backup drill recovery state',JSON.stringify({kind,held:hold?true:readError?'unknown':false,readError,
    status:statuses.includes(result?.status)?result.status:'unknown',
    stage:stages.includes(result?.stage)?result.stage:'unknown',
    journalStage:journalStages.includes(journal?.stage)?journal.stage:'unknown',
    code:/^OSS_[A-Z0-9_]{1,96}$/.test(result?.error||'')?result.error:null,
    elapsedMs:Math.max(0,Date.now()-startedAt),exitCode:Number.isInteger(error?.code)?error.code:null,
    signal:['SIGTERM','SIGKILL'].includes(error?.signal)?error.signal:null}))
}
async function task(kind, extras = {}) {
  const startedAt=Date.now()
  config = await core.readBackupConfig()
  const id = randomUUID()
  const held=core.recoveryHeld()
  const recovery=held?await (await import('/opt/incudal/server/dist/services/platform-recovery-operator.js')).recoveryOperator():null
  const [admin]=held?[]:await pgQuery("SELECT id FROM users WHERE username='admin' AND role='admin' AND status='active'")
  if (!held) await (await import('/opt/incudal/server/dist/lib/authentication-integrity.js')).verifyRecoveryAuthenticationActor(admin?.id)
  const request = { id, kind, createdBy: recovery?.actorId ?? admin.id, createdAt: new Date().toISOString(), config, ...extras }
  if (['restore', 'rollback', 'resume'].includes(kind)) {
    // Run the shipped oneshot with its actual PID/task argv and operation flock.
    // Startup recovery must recognize the live owner, not mistake this smoke
    // process for an interrupted restore and roll its activation back.
    await core.writeJson(core.statePath('inbox', `${id}.json`), request)
    try {
      await exec('/usr/local/libexec/incudal/incudal-online-task', ['platform-backup', id], { timeout: recoveryObservationTimeout })
    } catch(error) {
      await recoveryTaskDiagnostics(kind,id,startedAt,error)
      throw Error('BACKUP_DRILL_WORKER_FAILED')
    }
    Object.assign(process.env, require('dotenv').parse(await readFile('/opt/incudal/.env')))
  } else {
    await runPlatformBackupTask(request)
  }
  const result = await core.readJson(core.statePath('results', `${id}.json`))
  if (result?.status !== 'success')await recoveryTaskDiagnostics(kind,id,startedAt)
  assert.equal(result?.status, 'success', `${kind}: BACKUP_DRILL_RESULT_FAILED`)
  console.log(`Platform backup drill: ${kind} passed`)
  return result
}
async function health(held) {
  const response = await fetch('http://127.0.0.1:3001/api/health')
  assert.equal(response.status, 200)
  assert.equal((await response.json()).recoveryHeld, held)
}
async function gatewayState() {
  const links = JSON.parse((await exec('/usr/sbin/ip', ['-j', 'address', 'show', 'dev', 'incudal-mgmt'])).stdout)
  assert.equal(links.length, 1)
  return {
    mtu: links[0].mtu,
    addresses: links[0].addr_info.map(item => `${item.family}:${item.local}/${item.prefixlen}`).sort(),
    publicKey: (await exec('/usr/bin/wg', ['show', 'incudal-mgmt', 'public-key'])).stdout.trim(),
    listenPort: (await exec('/usr/bin/wg', ['show', 'incudal-mgmt', 'listen-port'])).stdout.trim(),
    peers: (await exec('/usr/bin/wg', ['show', 'incudal-mgmt', 'allowed-ips'])).stdout.trim()
  }
}
async function verifyBackupLocaleDrill() {
  const before = (await exec('/usr/bin/systemctl', ['show', 'incudal-backend', 'postgresql@16-main', '-p', 'MainPID', '-p', 'NRestarts'])).stdout
  const installed = (await exec('/usr/bin/locale', ['-a'])).stdout.toLowerCase().replaceAll('utf-8', 'utf8').split(/\r?\n/)
  const name = ['fr_FR.UTF-8','de_DE.UTF-8','it_IT.UTF-8','ja_JP.UTF-8','ko_KR.UTF-8'].find(value => !installed.includes(value.toLowerCase().replace('utf-8','utf8')))
  assert.ok(name, 'disposable VM must have one unused UTF-8 locale for the running-postmaster regression')
  const umask = process.umask()
  // Reproduce the archive-only form on this disposable runner. The product
  // must also fix names that locale -a already lists, without restarting PG.
  await exec('/usr/bin/localedef', ['-i',name.split('.')[0],'-f','UTF-8',name], { timeout:120000 })
  const archiveHash = createHash('sha256').update(await readFile('/usr/lib/locale/locale-archive')).digest('hex')
  const database = `incudal_verify_${randomUUID().replaceAll('-','')}`, quoted = quoteIdentifier(database)
  const create = `CREATE DATABASE ${quoted} OWNER incudal_migrate TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE '${name}' LC_CTYPE '${name}';`
  let exists = false, archiveRejected = false
  try {
    try { await localDatabaseAdmin(create); exists=true }
    catch (error) { assert.ok(['OSS_DATABASE_ADMIN_FAILED','OSS_DATABASE_LOCALE_UNAVAILABLE'].includes(error.code)); archiveRejected=true }
    if (exists) { await localDatabaseAdmin(`DROP DATABASE ${quoted};`); exists=false }
    await ensureBackupLocales([name])
    await localDatabaseAdmin(create); exists=true
    const [actual] = await pgQuery('SELECT datcollate,datctype FROM pg_database WHERE datname=$1',[database])
    assert.equal(actual.datcollate,name);assert.equal(actual.datctype,name)
    const category = `/usr/lib/locale/${name.replace('UTF-8','utf8')}/LC_COLLATE`
    const created = await stat(category)
    await ensureBackupLocales([name])
    assert.equal((await stat(category)).mtimeMs,created.mtimeMs,'repeated locale validation must not regenerate valid data')
    assert.equal(process.umask(),umask,'the worker private-file umask stays intact')
    assert.equal(createHash('sha256').update(await readFile('/usr/lib/locale/locale-archive')).digest('hex'),archiveHash)
    assert.equal((await exec('/usr/bin/systemctl', ['show', 'incudal-backend', 'postgresql@16-main', '-p', 'MainPID', '-p', 'NRestarts'])).stdout,before)
    console.log('Backup locale running-postmaster regression passed',JSON.stringify({archiveRejected,standalone:true,exactCollation:true,noRestart:true,idempotent:true}))
  } finally { if(exists)await localDatabaseAdmin(`DROP DATABASE ${quoted};`) }
}
async function largeObjectState(database, fixture) {
  assert.ok(database==='incudal'||database===preservedSource,'LO evidence is confined to this drill source/destination')
  const ids=[fixture.large,fixture.empty];assert.ok(ids.every(value=>/^[0-9]+$/.test(value)))
  const output=await localDatabaseAdmin(`\\connect ${quoteIdentifier(database)}
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT json_build_object('metadata',(SELECT coalesce(json_agg(json_build_array(oid::text,pg_get_userbyid(lomowner),lomacl::text) ORDER BY oid),'[]') FROM pg_largeobject_metadata WHERE oid IN (${ids.join(',')})),
  'pages',(SELECT coalesce(json_agg(json_build_array(loid::text,pageno,encode(sha256(data),'hex')) ORDER BY loid,pageno),'[]') FROM pg_largeobject WHERE loid IN (${ids.join(',')})));
COMMIT;`)
  const records=output.split(/\r?\n/).filter(line=>line.startsWith('{'))
  assert.equal(records.length,1);return JSON.parse(records[0])
}
const largeObjectRoles=()=>pgQuery(`SELECT rolname,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,
  (SELECT count(*)::int FROM pg_auth_members WHERE member=r.oid OR roleid=r.oid) memberships FROM pg_roles r
  WHERE rolname IN ('incudal','incudal_migrate') ORDER BY rolname`)
async function createLargeObjectFixture() {
  assert.equal((await pgQuery('SELECT count(*)::int AS count FROM pg_largeobject_metadata'))[0].count,0,'empty fixture database required before creating LO data')
  const data=Buffer.from(Array.from({length:8193},(_,index)=>index%256))
  const [{id:large}]=await pgQuery('SELECT lo_from_bytea(0,$1::bytea)::text AS id',[data])
  const [{id:empty}]=await pgQuery('SELECT lo_create(0)::text AS id')
  const fixture={large,empty,data,roles:await largeObjectRoles()}
  fixture.source=await largeObjectState('incudal',fixture)
  assert.ok(fixture.source.pages.filter(row=>row[0]===large).length>1,'real multi-page large object required')
  assert.equal(fixture.source.pages.filter(row=>row[0]===empty).length,0,'zero-page object retains a separate metadata OID')
  assert.deepEqual(fixture.source.metadata.map(row=>row[0]),[large,empty].sort((a,b)=>Number(a)-Number(b)))
  return fixture
}
async function verifyRestoredLargeObjects(fixture, verifyHardening=false) {
  const before=await largeObjectState('incudal',fixture)
  assert.deepEqual(before.pages,fixture.source.pages,'all original LO page numbers and content hashes survive restore')
  assert.deepEqual(before.metadata.map(row=>row[0]),fixture.source.metadata.map(row=>row[0]),'original multi/zero-page LO OIDs survive restore')
  assert.ok(before.metadata.every(row=>row[1]==='incudal'),'only the runtime owns restored LO application data')
  if(verifyHardening){
    assert.equal(core.recoveryHeld(),false,'repeat hardening is tested after real recovery protection is cleared')
    for(let repeat=0;repeat<2;repeat++)await exec('/usr/bin/python3',['-I','-B','/opt/incudal/scripts/harden-database.py'],
      {timeout:180000,env:{...process.env,NODE_OPTIONS:'',NODE_PATH:''}})
    assert.deepEqual(await largeObjectState('incudal',fixture),before,'repeated role hardening keeps LO data, OIDs and runtime ownership')
  }
  const roles=await largeObjectRoles();assert.deepEqual(roles,fixture.roles,'LO mapping cannot alter role flags or memberships')
  assert.equal(roles.length,2)
  for(const role of roles)assert.ok(!role.rolsuper&&!role.rolcreatedb&&!role.rolcreaterole&&!role.rolreplication&&!role.rolbypassrls&&role.memberships===0)
  const [{actor}]=await pgQuery('SELECT current_user::text AS actor');assert.equal(actor,'incudal')
  const [{outside}]=await pgQuery(`SELECT count(*)::int AS outside FROM pg_largeobject_metadata m
    CROSS JOIN LATERAL aclexplode(m.lomacl) a WHERE m.oid=ANY($1::oid[]) AND (a.grantee<>m.lomowner OR a.grantor<>m.lomowner)`,[[fixture.large,fixture.empty]])
  assert.equal(outside,0,'restored LOs grant nothing to PUBLIC or other roles')
  assert.deepEqual((await pgQuery('SELECT lo_get($1::oid) AS data',[fixture.large]))[0].data,fixture.data,'authenticated low-privilege runtime reads restored binary data')
  assert.deepEqual((await pgQuery('SELECT lo_get($1::oid) AS data',[fixture.empty]))[0].data,Buffer.alloc(0))
  const probe=quoteIdentifier('lo_ddl_'+randomUUID().replaceAll('-',''))
  for(const sql of [`CREATE TABLE public.${probe}(id integer)`,`CREATE SCHEMA ${probe}`,'SET ROLE incudal_migrate'])
    await assert.rejects(pgQuery(sql),error=>error.code==='42501','LO data ownership must not restore DDL or migration-role access')
  if(core.recoveryHeld()){
    assert.deepEqual(await largeObjectState(preservedSource,fixture),fixture.source,'protected restore leaves the preserved source database unchanged')
    console.log('PASS protected restored LO: original multi/zero-page OIDs, pages and readable data, no outside ACL/DDL/role access; mutations wait for actual resume')
    return
  }
  const patch=Buffer.from([0xa1,0xb2,0xc3,0xd4])
  await pgQuery('SELECT lo_put($1::oid,0,$2::bytea)',[fixture.large,patch])
  assert.deepEqual((await pgQuery('SELECT lo_get($1::oid,0,4) AS data',[fixture.large]))[0].data,patch,'runtime native write is retained')
  for(const id of [fixture.empty,fixture.large])assert.equal((await pgQuery('SELECT lo_unlink($1::oid) AS removed',[id]))[0].removed,1,'runtime native unlink is retained')
  assert.equal((await largeObjectState('incudal',fixture)).metadata.length,0)
  assert.deepEqual(await largeObjectState(preservedSource,fixture),fixture.source,'runtime reads/writes/unlinks on the destination cannot change the preserved source database')
  console.log('PASS restored LO: original multi/zero-page OIDs and pages, authenticated runtime native read/write/unlink, no DDL/role elevation, preserved source database unchanged')
}
try {
  for (const entry of ['user', 'admin']) {
    assert.equal(await readFile(`/opt/incudal/client/dist/${entry}/recovery/payincus-recovery.py`, 'utf8'), await readFile('/opt/incudal/scripts/platform-backup-recovery.py', 'utf8'))
    assert.equal(await readFile(`/opt/incudal/client/dist/${entry}/recovery/恢复说明.md`, 'utf8'), await readFile('/opt/incudal/scripts/platform-backup-recovery-guide.md', 'utf8'))
  }
  await exec('python3', ['/opt/incudal/scripts/platform-backup-recovery.py', 'status'], { timeout: 15000 })
  for (const path of ['/etc/systemd/system/incudal-platform-backup@.service', '/etc/systemd/system/incudal-backend.service.d/platform-backup.conf']) assert.ok((await stat(path)).isFile())
  await exec('/usr/bin/sudo', ['-u', 'incudal', 'test', '-w', '/var/lib/incudal-backup/inbox'])
  await assert.rejects(exec('/usr/bin/sudo', ['-u', 'incudal', 'test', '-r', '/var/lib/incudal-backup/private']))
  await verifyBackupLocaleDrill()
  const [{hosts:loHosts,instances:loInstances}]=await pgQuery('SELECT (SELECT count(*)::int FROM hosts) hosts,(SELECT count(*)::int FROM instances) instances')
  assert.equal(loHosts,0);assert.equal(loInstances,0,'LO recovery regression uses only the empty disposable installation')
  const largeObjects=await createLargeObjectFixture()
  const key = `backup_drill_${randomUUID()}`
  await secured.prisma.systemConfig.create({data:{key,value:'snapshot',type:'string'}})
  const backup = await task('backup')
  // B must really have independently initialized authentication/money seals.
  // Changing A's key in place creates invalid signatures, not a fresh B.
  const [{ hosts, instances }] = await pgQuery('SELECT (SELECT count(*)::int FROM hosts) hosts,(SELECT count(*)::int FROM instances) instances')
  assert.equal(hosts, 0); assert.equal(instances, 0, 'the disposable fresh-install drill has no customers')
  assert.equal(new URL(initialEnv.DATABASE_URL).pathname, '/incudal')
  await controlRecoveryBackend('stop')
  await secured.closePrismaDatabase()
  await localDatabaseAdmin(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='incudal'; ALTER DATABASE incudal RENAME TO ${quoteIdentifier(preservedSource)}; CREATE DATABASE incudal OWNER incudal_migrate TEMPLATE template0; REVOKE ALL ON DATABASE incudal FROM PUBLIC; GRANT CONNECT ON DATABASE incudal TO incudal;`)
  sourcePreserved = true
  await rename('/var/lib/incudal-finance/baseline.json', join(storage, 'source-baseline.json'))
  const targetKey = randomUUID() + randomUUID()
  const sourceSecret = core.openSecret(config.accessKeySecret)
  const originalEndpoint = initialEnv.ONBOARDING_WG_ENDPOINT
  assert.ok(originalEndpoint && /:51820$/.test(originalEndpoint), 'fresh-install management endpoint expected')
  const targetEnv = { ...initialEnv, ENCRYPTION_KEY: targetKey, ONBOARDING_WG_ENDPOINT: originalEndpoint.replace(/:51820$/, ':51999') }
  await writeFile('/opt/incudal/.env', Object.entries(targetEnv).map(([name, value]) => `${name}='${value}'`).join('\n') + '\n')
  process.env.ENCRYPTION_KEY = targetKey
  await exec('/usr/bin/python3', ['-I', '-B', '/opt/incudal/scripts/harden-database.py'], { timeout: 180000, env: { ...process.env, NODE_OPTIONS: '', NODE_PATH: '' } })
  await exec('/usr/bin/bash', ['/opt/incudal/scripts/migrate-database.sh'], { timeout: 180000, env: { ...process.env, NODE_OPTIONS: '', NODE_PATH: '' } })
  await controlRecoveryBackend('start')
  await waitForProtectedBackendHealth(false)
  // Use a new protected client with B's environment and actual signed writer.
  await exec('/usr/bin/node', ['--input-type=module', '-e',
    `const db=await import('/opt/incudal/server/dist/db/prisma.js');try{await db.initializeFinancialDatabaseIntegrity();await db.prisma.systemConfig.create({data:{key:${JSON.stringify(key)},value:'before-restore',type:'string'}})}finally{await db.closePrismaDatabase()}`],
    { timeout: 180000, env: { ...process.env, NODE_OPTIONS: '', NODE_PATH: '' } })
  await assert.rejects((await import('/opt/incudal/server/dist/lib/financial-integrity.js')).verifyFinancialDatabaseSeals('incudal', initialEnv.ENCRYPTION_KEY, false, true), /FINANCIAL_INTEGRITY_INVALID/)
  console.log('PASS independent destination: new database, shipped migrations, administrator and money/authentication seals; source key rejected')
  config.accessKeySecret = core.sealSecret(sourceSecret); config.backupPassword = core.sealSecret(password)
  await saveConfig()
  const preview = await task('preview', { sourcePrefix: backup.objectPrefix, password: core.sealSecret(password) })
  const gatewayEndpoints = (await exec('/usr/bin/wg', ['show', 'incudal-mgmt', 'endpoints'])).stdout
  const gatewayIfindex = (await readFile('/sys/class/net/incudal-mgmt/ifindex', 'utf8')).trim()
  const gatewayBefore = await gatewayState()
  await task('restore', { previewId: preview.id, confirmation: `RESTORE ${preview.id}` })
  for (const name of ['recovery-hold.json', 'recovery-operator.json']) {
    assert.equal((await stat(join(core.backupRoot(), name))).mode & 0o777, 0o640, 'restored public state retains exact service-read mode under umask077')
    await exec('/usr/bin/sudo', ['-u', 'incudal', 'test', '-r', join(core.backupRoot(), name)])
  }
  const legacyHold = await core.readJson(join(core.backupRoot(), 'recovery-hold.json'))
  await core.writeJson(join(core.backupRoot(), 'recovery-hold.json'), { ...legacyHold, autoResume: false }, 0o640)
  assert.equal((await readFile('/sys/class/net/incudal-mgmt/ifindex', 'utf8')).trim(), gatewayIfindex, 'same-controller recovery must not recreate the management interface')
  assert.equal((await exec('/usr/bin/wg', ['show', 'incudal-mgmt', 'endpoints'])).stdout, gatewayEndpoints, 'same-controller recovery must preserve learned peer endpoints')
  await health(true)
  await verifyRestoredLargeObjects(largeObjects)
  assert.equal((await pgQuery('SELECT value FROM system_configs WHERE key=$1', [key]))[0].value, 'snapshot')
  assert.equal(core.openSecret((await core.readBackupConfig()).backupPassword), password)
  assert.ok(process.env.ENCRYPTION_KEY === initialEnv.ENCRYPTION_KEY, 'restoration retains the authenticated source encryption key')
  const restoredEnv = require('dotenv').parse(await readFile('/opt/incudal/.env'))
  assert.equal(restoredEnv.ONBOARDING_WG_ENDPOINT, originalEndpoint, 'restored UDP listen port must replace fresh-machine environment default')
  assert.equal(restoredEnv.ONBOARDING_GATEWAY_FINGERPRINT, initialEnv.ONBOARDING_GATEWAY_FINGERPRINT, 'destination SSH host identity must remain pinned')
  assert.equal(createHash('sha256').update(await readFile(`${controllerRoot}/signing.pem`)).digest('hex'), controllerKeyBefore)
  assert.equal(await readFile(`${controllerRoot}/identity.json`, 'utf8'), controllerIdentityBefore)
  await exec('/usr/bin/python3', ['-I', '-B', '/opt/incudal/scripts/enroll-gateway-controller.py', '--verify'])
  for (const path of ['/api/host-onboarding/inventory', '/api/instances', '/api/oauth/github/callback']) assert.equal((await fetch(`http://127.0.0.1:3001${path}`)).status, 503)
  assert.equal((await fetch('http://127.0.0.1:3001/api/system-config/public')).status, 200)
  const login = await fetch('http://127.0.0.1:3001/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: initialEnv.ADMIN_PASSWORD }) })
  assert.equal(login.status, 200, 'administrator can log in while recovery is held')
  console.log('PASS installed recovery state: service-readable 0640 files and administrator login while held')
  await exec('/usr/bin/sudo', ['-u', 'incudal', 'test', '-r', '/opt/incudal/server/certs/onboarding-gateway.key'])
  // Model an interrupted worker whose files already match but whose live
  // network still differs. Rollback must reconcile the kernel, not the ifindex.
  await exec('/usr/sbin/ip', ['link', 'set', 'dev', 'incudal-mgmt', 'mtu', gatewayBefore.mtu === 1280 ? '1380' : '1280'])
  await exec('/usr/bin/wg', ['set', 'incudal-mgmt', 'listen-port', gatewayBefore.listenPort === '51998' ? '51997' : '51998'])
  assert.notDeepEqual(await gatewayState(), gatewayBefore, 'drill must actually change live gateway state')
  await task('rollback', { confirmation: 'ROLLBACK RESTORE' })
  assert.deepEqual(await gatewayState(), gatewayBefore, 'rollback must restore live addresses, MTU, identity, listen port and peers')
  await health(true)
  assert.equal((await pgQuery('SELECT value FROM system_configs WHERE key=$1', [key]))[0].value, 'before-restore')
  assert.ok(process.env.ENCRYPTION_KEY === targetKey, 'rollback retains the independent destination encryption key')
  assert.equal(require('dotenv').parse(await readFile('/opt/incudal/.env')).ONBOARDING_WG_ENDPOINT, targetEnv.ONBOARDING_WG_ENDPOINT, 'rollback preserves destination environment bytes')
  assert.equal(createHash('sha256').update(await readFile(`${controllerRoot}/signing.pem`)).digest('hex'), controllerKeyBefore)
  assert.equal(core.openSecret((await core.readBackupConfig()).backupPassword), password)
  // The legacy rollback drill must supply the current batch and real review
  // receipts, just like the protected route. It is not the one-click contract.
  Object.assign(process.env, require('dotenv').parse(await readFile('/opt/incudal/.env')))
  const recoveryState = await import('/opt/incudal/server/dist/services/platform-recovery-state.js')
  const rollbackBatch = await recoveryState.activeRecoveryBatch()
  assert.equal(rollbackBatch.mode, 'rollback')
  assert.equal((await pgQuery('SELECT count(*)::int count FROM hosts'))[0].count, 0, 'fresh fixture must have no customer hosts')
  await exec('/usr/bin/node', ['--input-type=module', '-e', `
    const {createHash}=await import('node:crypto');
    const db=await import('/opt/incudal/server/dist/db/prisma.js');
    try {
      await db.initializeFinancialDatabaseIntegrity();
      const state=await import('/opt/incudal/server/dist/services/platform-recovery-state.js');
      const {recordRecoveryEvidence}=await import('/opt/incudal/server/dist/services/platform-recovery-evidence.js');
      const {verifyRecoveryGateway}=await import('/opt/incudal/server/dist/services/platform-recovery-gateway.js');
      const batch=await state.activeRecoveryBatch();
      for(const category of ['finance','access','tasks'])await recordRecoveryEvidence(category,
        {reference:'fresh-rollback-'+category,observedAt:new Date().toISOString(),sourceHash:await state.recoveryDatasetHash(category),
          evidenceHash:createHash('sha256').update('empty-fixture-'+category).digest('hex')},batch.operator_id,{password:process.env.ADMIN_PASSWORD});
      await verifyRecoveryGateway(batch,batch.operator_id);
    } finally {await db.closePrismaDatabase()}`],
    { timeout: 180000, env: { ...process.env, NODE_OPTIONS: '', NODE_PATH: '' } })
  await task('resume', { confirmation: 'RESUME AFTER RECONCILIATION', recoveryBatchId: rollbackBatch.id })
  await health(false)
  assert.equal((await exec('/usr/bin/systemctl', ['show', 'incudal-backend', '-p', 'NRestarts', '--value'])).stdout.trim(), '0')
  console.log('Linux backup/preview/restore/rollback/resume and key consistency passed; OSS transport was simulated.')

  // Exercise the current snapshot policy independently. The installed protected
  // backend must verify the real local gateway and dispatch its own root resume;
  // no finance/access receipt or second operator confirmation is provided.
  const automaticPreview = await task('preview', { sourcePrefix: backup.objectPrefix, password: core.sealSecret(password) })
  const automaticRestore = await task('restore', { previewId: automaticPreview.id,
    confirmation: `RESTORE ${automaticPreview.id}`, restorePolicy: 'snapshot-v1' })
  const until = Date.now() + recoveryObservationTimeout
  let complete = false
  while (Date.now() < until) {
    const [batch] = await pgQuery('SELECT completed_at FROM platform_recovery_batches WHERE id=$1', [automaticRestore.id])
    if (batch?.completed_at && !await core.readJson(join(core.backupRoot(), 'recovery-hold.json')) &&
        !await core.readJson(join(core.backupRoot(), 'recovery-activation.json'))) { complete = true; break }
    await new Promise(resolve => setTimeout(resolve, 1000))
  }
  if (!complete) {
    const checks = await pgQuery("SELECT category,payload FROM platform_recovery_evidence WHERE batch_id=$1 AND category IN ('gateway-check','auto-resume') ORDER BY created_at DESC LIMIT 4", [automaticRestore.id])
    console.error('Snapshot continuation checks', JSON.stringify(checks.map(({category,payload}) => ({category,
      status: ['retry','blocked','dispatched','success','running'].includes(payload?.status) ? payload.status : 'unknown',
      code: /^[A-Z0-9_]{1,100}$/.test(payload?.code || '') ? payload.code : null,
      attempt: Number.isSafeInteger(payload?.attempt) ? payload.attempt : null}))))
    for (const {category,payload} of checks) {
      if (category !== 'auto-resume' || !/^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(payload?.taskId || '')) continue
      const unit = `incudal-platform-backup@${payload.taskId}.service`
      const unitLog = await exec('/usr/bin/journalctl', ['-u',unit,'--no-pager','-n','12']).catch(() => ({stdout:''}))
      const result = await core.readJson(core.statePath('results',`${payload.taskId}.json`))
      // Only fixed classifications leave the VM; journal text may hold secrets.
      console.error('Snapshot worker diagnostics', JSON.stringify({attempt:payload.attempt,
        lockBusy:/platform maintenance (?:task is running|lock did not become available)/.test(unitLog.stdout),
        trustRejected:/release (?:file set|integrity)|worker missing/.test(unitLog.stdout),
        receiptPresent:Boolean(result),code:/^[A-Z0-9_]{1,100}$/.test(result?.error || '')?result.error:null}))
    }
  }
  assert.ok(complete, 'snapshot recovery must finish through installed automatic review and root resume')
  await health(false)
  await verifyRestoredLargeObjects(largeObjects,true)
  assert.equal((await pgQuery('SELECT value FROM system_configs WHERE key=$1', [key]))[0].value, 'snapshot')
  assert.equal(createHash('sha256').update(await readFile(`${controllerRoot}/signing.pem`)).digest('hex'), controllerKeyBefore)
  assert.equal(await readFile(`${controllerRoot}/identity.json`, 'utf8'), controllerIdentityBefore)
  const [{ count: manualReceipts }] = await pgQuery("SELECT count(*)::int count FROM platform_recovery_evidence WHERE batch_id=$1 AND category IN ('finance','access','tasks')", [automaticRestore.id])
  assert.equal(manualReceipts, 0, 'snapshot policy must not require manual review evidence')
  console.log('PASS installed snapshot policy: real database and gateway identity restored; automatic root resume; zero manual financial/access/task receipts; OSS transport simulated; no customer hosts.')
} finally {
  if (sourcePreserved) await localDatabaseAdmin(`DROP DATABASE ${quoteIdentifier(preservedSource)} WITH (FORCE);`)
  await rm(storage, { recursive: true, force: true })
}
process.exit(0)
