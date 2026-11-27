// Disposable GitHub VM only. Runs the original published worker with real PG,
// filesystem, systemd, migration, helper installation and health checks.
// Only the not-yet-published candidate Release HTTP response is local.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { readFile, writeFile, realpath, lstat } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { Readable } from 'node:stream'
import { execFile, execFileSync } from 'node:child_process'
import { promisify } from 'node:util'
import { resolve } from 'node:path'
import { verifyPanelDigest } from './panel-package-signature.mjs'
import { migrateCandidateRepositoryConfiguration } from './finalize-verified-owner-candidate.mjs'

assert.equal(process.env.GITHUB_ACTIONS, 'true')
assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted')
assert.equal(process.platform, 'linux'); assert.equal(process.getuid(), 0)
const [mode, archiveArg] = process.argv.slice(2)
assert.ok(['migrate', 'before', 'worker', 'rolled-back', 'after', 'root-rollback-prepare', 'root-rollback-wait', 'root-duplicate-after'].includes(mode))
const archive = resolve(archiveArg), stateFile = '/root/incudal-legacy-upgrade.json'
const atomic = await lstat('/opt/incudal/current').then(info => info.isSymbolicLink()).catch(() => false)
let app = await realpath(atomic ? '/opt/incudal/current' : '/opt/incudal')
const require = createRequire(app + '/server/package.json')
const env = require('dotenv').parse(await readFile('/opt/incudal/.env'))
const exec = promisify(execFile)
const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const identities = ['/var/lib/incudal-gateway-controller/signing.pem', '/var/lib/incudal-gateway-controller/identity.json',
  '/etc/wireguard/incudal-mgmt.conf', '/root/.ssh/incudal-host-management', '/opt/incudal/.env']
const { Client } = require('pg')
const baseline = process.env.UPGRADE_DRILL_BASELINE_VERSION
assert.match(baseline || '', /^v\d+\.\d+\.\d+$/)

async function verifyRootLauncherGitGate() {
  const sourcePath=app+'/deploy/incudal-online-task.sh.example',helperPath='/usr/local/libexec/incudal/incudal-online-task'
  const [source,helper]=await Promise.all([readFile(sourcePath),readFile(helperPath)])
  for(const path of [sourcePath,helperPath]) {
    const info=await lstat(path)
    assert.ok(info.isFile()&&!info.isSymbolicLink()&&info.uid===0&&info.gid===0&&info.nlink===1&&!(info.mode&0o022),'root launcher must retain protected original metadata')
  }
  const archiveSource=['before','rolled-back','root-rollback-wait','root-duplicate-after'].includes(mode)?process.env.UPGRADE_DRILL_BASELINE_ARCHIVE:archive
  assert.ok(archiveSource,'original baseline archive must remain available for independent helper comparison')
  const expectedSource=execFileSync('tar',['-xOf',archiveSource,'./deploy/incudal-online-task.sh.example'],{maxBuffer:1024*1024})
  assert.ok(source.equals(expectedSource),'startup must never change the sealed deployment template')
  const old='https://github.com/mastalee928/payincus.git',current='https://github.com/masta-lee/mastaincus.git'
  const raw=execFileSync('/usr/bin/git',['-C','/opt/incudal','config','--local','--get-all','remote.origin.url'],{encoding:'utf8'}).trim()
  assert.ok([old,current].includes(raw),'root launcher requires one exact maintained or retired origin')
  const expected=raw===current&&source.includes(Buffer.from(old))&&!source.includes(Buffer.from(current))
    ?Buffer.from(source.toString('utf8').replaceAll(old,current)):source
  let retainedSecure=false
  if(!helper.equals(expected)) {
    const securePath='/usr/local/libexec/incudal/database-secure-task'
    const secureInfo=await lstat(securePath)
    const secure=await readFile(securePath)
    const currentTemplate=execFileSync('tar',['-xOf',archive,'./deploy/incudal-online-task.sh.example'],{maxBuffer:1024*1024})
    retainedSecure=hash(source)==='15fd9cac0a7af20a2a8499b10637c7d3696c99ef1abe81eacce728134011219a'&&helper.equals(currentTemplate)&&secure.equals(helper)&&
      secureInfo.isFile()&&!secureInfo.isSymbolicLink()&&secureInfo.uid===0&&secureInfo.gid===0&&secureInfo.nlink===1&&(secureInfo.mode&0o777)===0o755
  }
  assert.ok(helper.equals(expected)||retainedSecure,'installed helper must follow the actual origin or retain its verified current security launcher after rollback')
  const declaration=helper.toString('utf8').match(/^verify_git_control\(\) \{[\s\S]*?^\}/m)?.[0]
  assert.ok(declaration,'execute the exact shipped launcher gate, not a fixture replacement')
  execFileSync('/usr/bin/env',['-i','PATH=/usr/sbin:/usr/bin:/sbin:/bin','HOME=/var/cache/incudal-ota','LC_ALL=C','/usr/bin/bash','-s'],{
    input:'set -euo pipefail\nINSTALL_DIR=/opt/incudal\nfail() { printf "%s\\n" "ROOT_LAUNCHER_GIT_GATE_REFUSED" >&2; exit 1; }\n'+declaration+'\nverify_git_control\n',
    stdio:['pipe','pipe','pipe'],timeout:30000
  })
  const startup='/usr/local/libexec/incudal/incudal-repository-source-startup'
  const initialLegacyBefore=mode==='before'&&process.env.UPGRADE_DRILL_INSTALLER_SOURCE!=='current'&&process.env.UPGRADE_DRILL_RETRY!=='true'
  let startupInfo
  try { startupInfo=await lstat(startup) } catch(error) { if(error?.code!=='ENOENT')throw error }
  assert.ok(startupInfo||initialLegacyBefore,'the current installer and every post-candidate phase must retain the repository startup guard')
  if(startupInfo) {
    assert.ok(startupInfo.isFile()&&!startupInfo.isSymbolicLink()&&startupInfo.uid===0&&startupInfo.gid===0&&startupInfo.nlink===1&&(startupInfo.mode&0o777)===0o755,
      'the actual repository startup guard must remain a protected regular file')
    const candidateInstaller=execFileSync('tar',['-xOf',archive,'./scripts/install-panel.sh'],{maxBuffer:1024*1024}).toString('utf8')
    const marker="<<'INCUDAL_REPOSITORY_SOURCE_SCRIPT'\n",end='\nINCUDAL_REPOSITORY_SOURCE_SCRIPT'
    assert.equal(candidateInstaller.split(marker).length,2)
    assert.equal(candidateInstaller.split(end).length,2)
    const candidateStartup=Buffer.from(candidateInstaller.split(marker)[1].split(end)[0]+'\n')
    assert.ok((await readFile(startup)).equals(candidateStartup),'the active startup guard must match its independently signed candidate installer in complete bytes')
    const post=execFileSync('/usr/bin/systemctl',['show','incudal-backend.service','--property=ExecStartPost','--value'],{encoding:'utf8'})
    const entry=[...post.matchAll(/\{[^}]*\}/g)].map(match=>match[0]).find(text=>text.includes(startup))
    assert.ok(entry?.includes('argv[]=/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /usr/bin/bash '+startup+' ;')&&/code=exited\s*;\s*status=0/.test(entry),'actual root startup correction must complete through the loaded backend unit')
    for(const unit of ['incudal-online-update@1.service','incudal-online-rollback@1.service']) {
      const after=execFileSync('/usr/bin/systemctl',['show',unit,'--property=After','--value'],{encoding:'utf8'})
      assert.ok(after.trim().split(/\s+/).includes('incudal-backend.service'),'actual loaded root task unit must wait for backend startup: '+unit)
    }
  }
  console.log('PASS exact shipped root launcher Git gate and unchanged sealed template after actual service startup')
}

if (mode === 'root-rollback-prepare') {
  const state=JSON.parse(await readFile(stateFile))
  assert.ok(atomic && state.atomic && process.env.UPGRADE_DRILL_SCENARIO==='rollback' && process.env.UPGRADE_DRILL_INSTALLER_SOURCE==='current')
  await verifyRootLauncherGitGate()
  assert.equal(JSON.parse(await readFile(app+'/version.json')).version,state.candidateVersion)
  const client=new Client({connectionString:env.DATABASE_URL});await client.connect()
  try {
    const task=(await client.query('SELECT status,backup_path FROM system_update_tasks WHERE id=$1',[state.taskId])).rows[0]
    assert.equal(task.status,'success');assert.equal(task.backup_path,state.oldApp)
  }finally{await client.end()}
  assert.equal(execFileSync('/usr/bin/git',['-C','/opt/incudal','config','--local','--get-all','remote.origin.url'],{encoding:'utf8'}).trim(),'https://github.com/masta-lee/mastaincus.git')
  // Only this disposable fixture's exact legacy origin changes. The original
  // old archive, rollback release, runtime and identities stay unchanged.
  execFileSync('/usr/bin/git',['-C','/opt/incudal','remote','set-url','origin','https://github.com/mastalee928/payincus.git'])
  execFileSync('/usr/local/libexec/incudal/incudal-online-task',['seal'],{stdio:'pipe',timeout:180000})
  state.rootRollbackUnit='incudal-online-rollback@'+state.taskId+'.service'
  await writeFile(stateFile,JSON.stringify(state),{mode:0o600})
  console.log('PASS exact legacy-origin fixture for actual root rollback; original candidate and rollback archive unchanged')
} else if (mode === 'root-rollback-wait' || mode === 'root-duplicate-after') {
  const state=JSON.parse(await readFile(stateFile))
  // systemctl start in the shell waits for the actual oneshot's natural exit.
  // Successful inactive units may be garbage-collected, so do not rely on a
  // transient InvocationID/timestamp surviving after that completed job.
  const unit=mode==='root-rollback-wait'?state.rootRollbackUnit:'incudal-online-update@'+state.taskId+'.service'
  const output=execFileSync('/usr/bin/systemctl',['show',unit,'--property=Result,ExecMainStatus,Job,ExecStart'],{encoding:'utf8'})
  assert.match(output,/^Result=success$/m);assert.match(output,/^ExecMainStatus=0$/m)
  // systemctl renders an absent completed job as either empty or numeric zero.
  // The synchronous start has returned; any active/nonzero job still fails.
  assert.match(output,/^Job=(?:0)?$/m)
  const operation=mode==='root-rollback-wait'?'rollback':'update'
  let launcher='/usr/local/libexec/incudal/incudal-online-task'
  if(output.includes('argv[]=/usr/local/libexec/incudal/database-secure-task ')) {
    launcher='/usr/local/libexec/incudal/database-secure-task'
    const info=await lstat(launcher),bytes=await readFile(launcher)
    const candidateTemplate=execFileSync('tar',['-xOf',archive,'./deploy/incudal-online-task.sh.example'],{maxBuffer:1024*1024})
    assert.ok(info.isFile()&&!info.isSymbolicLink()&&info.uid===0&&info.gid===0&&info.nlink===1&&(info.mode&0o777)===0o755&&bytes.equals(candidateTemplate),
      'the retained root security unit must execute the exact protected candidate launcher')
  }
  assert.ok(output.includes('argv[]='+launcher+' '+operation+' '+state.taskId+' ;'),'actual root unit must retain an authenticated shipped launcher and exact task argument')
  if(mode==='root-rollback-wait')assert.ok((await readFile('/opt/incudal/update-logs/system-update-'+state.taskId+'-rollback.log','utf8')).includes('Rollback completed successfully'))
  else assert.ok((await readFile('/opt/incudal/update-logs/system-update-'+state.taskId+'.log','utf8')).trimEnd().endsWith('System update task '+state.taskId+' is already claimed or finished; skipping duplicate worker'),'actual next root unit must enter the original completed-task guard')
  app=await realpath('/opt/incudal/current')
  assert.equal(app,state.oldApp)
  assert.equal(execFileSync('/usr/bin/git',['-C','/opt/incudal','config','--local','--get-all','remote.origin.url'],{encoding:'utf8'}).trim(),'https://github.com/masta-lee/mastaincus.git')
  await verifyRootLauncherGitGate()
  const client=new Client({connectionString:env.DATABASE_URL});await client.connect()
  try{
    const task=(await client.query('SELECT status FROM system_update_tasks WHERE id=$1',[state.taskId])).rows[0]
    assert.equal(task.status,'rolled_back','root duplicate task must preserve the completed rollback')
    for(const file of identities)assert.equal(hash(await readFile(file)),state.original[file],'actual root rollback must preserve controller/network/environment identity: '+file)
  }finally{await client.end()}
  assert.equal(JSON.parse(await readFile(app+'/version.json')).version,state.baseline)
  execFileSync('/usr/bin/systemctl',['is-active','--quiet','incudal-backend'])
  console.log(mode==='root-rollback-wait'?'PASS actual root rollback, internal backend restart and immediate migrated-helper gate without another restart':'PASS next actual root update unit reached the original duplicate-worker guard without another restart')
} else if (mode === 'migrate') {
  const candidateRequire = createRequire(archive + '/server/package.json')
  const cliMetadata = candidateRequire.resolve('prisma/package.json')
  const metadata = JSON.parse(await readFile(cliMetadata))
  const cli = resolve(cliMetadata, '..', typeof metadata.bin === 'string' ? metadata.bin : metadata.bin.prisma)
  await exec(process.execPath, [cli, 'migrate', 'deploy'], { cwd: archive + '/server', env: { ...process.env, ...env }, timeout: 300000 })
  console.log('PASS rollback-state setup: actual candidate Prisma migrations applied while old runtime stays installed')
} else if (mode === 'before') {
  assert.equal(JSON.parse(await readFile(app + '/version.json')).version, baseline)
  await verifyRootLauncherGitGate()
  const client = new Client({ connectionString: env.DATABASE_URL }); await client.connect()
  try {
    const admin = (await client.query("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1")).rows[0]
    assert.ok(admin)
    const { stdout: packageText } = await exec('tar', ['-xOf', archive, './server/package.json'])
    const applicationVersion = JSON.parse(packageText).version
    const { stdout: metadataText } = await exec('tar', ['-xOf', archive, './version.json'])
    const candidateVersion = JSON.parse(metadataText).version
    assert.ok(verifyPanelDigest(candidateVersion, process.arch === 'arm64' ? 'arm64' : 'amd64',
      hash(await readFile(archive)), (await readFile(archive + '.sig', 'utf8')).trim()), 'exact candidate publisher/version must verify before the old worker runs')
    migrateCandidateRepositoryConfiguration(archive,candidateVersion)
    // Unpublished semver candidates must exercise their actual signed target.
    // Plain previews retain the stable target supported by the published old worker.
    const target = /^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(candidateVersion) ? candidateVersion : 'v' + applicationVersion
    assert.match(target, /^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/)
    const task = (await client.query("INSERT INTO system_update_tasks(target_version,status,started_by_user_id,updated_at) VALUES($1,'pending',$2,NOW()) RETURNING id", [target, admin.id])).rows[0]
    const original = {}
    for (const file of identities) original[file] = hash(await readFile(file))
    const enrollment = JSON.parse(await readFile('/var/lib/incudal-gateway-controller/enrollment.json'))
    for (const component of Object.values(enrollment.components)) {
      assert.equal(component.version, baseline.slice(1))
      const envelope = JSON.parse(await readFile(component.directory + '/manifest.json'))
      const manifest = JSON.parse(Buffer.from(envelope.payload, 'base64'))
      assert.equal(manifest.files.length, 21)
    }
    const applied = (await client.query("SELECT count(*)::int AS n FROM _prisma_migrations WHERE migration_name='20261111170000_instance_renewal_price' AND finished_at IS NOT NULL AND rolled_back_at IS NULL")).rows[0].n
    assert.equal(applied, 1)
    await writeFile(stateFile, JSON.stringify({ taskId: task.id, target, applicationVersion, candidateVersion, baseline, original, atomic, oldApp: app, oldComponents: enrollment.components }), { mode: 0o600 })
    console.log(`PASS legacy baseline: genuine ${baseline} installed, original 21-file components and controller/network identity recorded`)
  } finally { await client.end() }
} else if (mode === 'worker') {
  const state = JSON.parse(await readFile(stateFile))
  const bytes = await readFile(archive), sha256 = hash(bytes), arch = process.arch === 'arm64' ? 'arm64' : 'amd64'
  const name = `incudal-${state.target}-linux-${arch}.tar.gz`
  const url = `https://github.com/masta-lee/mastaincus/releases/download/${state.target}/${name}`
  const manifestUrl = `https://github.com/masta-lee/mastaincus/releases/download/${state.target}/ota-manifest.json`
  const signature=(await readFile(archive+'.sig','utf8')).trim()
  const manifest = { artifacts: [{ name, platform: 'linux', arch, url, sha256, size: bytes.length,version:state.target,signature }] }
  const metadata = { tag_name: state.target, draft: false, assets: [
    { id: 1, name: 'ota-manifest.json', browser_download_url: manifestUrl },
    { id: 2, name, browser_download_url: url, size: bytes.length, digest: 'sha256:' + sha256 }
  ] }
  const fetchOriginal = globalThis.fetch
  globalThis.fetch = async (input, options) => {
    const address = String(input)
    if (address === `https://api.github.com/repos/masta-lee/mastaincus/releases/tags/${state.target}`) return Response.json(metadata)
    if (address === manifestUrl || address === 'https://api.github.com/repos/masta-lee/mastaincus/releases/assets/1') return Response.json(manifest)
    if (address === url || address === 'https://api.github.com/repos/masta-lee/mastaincus/releases/assets/2') {
      return new Response(Readable.toWeb(createReadStream(archive)), { headers: { 'content-length': String(bytes.length) } })
    }
    return fetchOriginal(input, options)
  }
  for (const [key, value] of Object.entries(env)) process.env[key] = value
  // Exercise the unchanged historical worker against the new repository.
  // Credentials and the on-disk identity remain those of the original install.
  process.env.SYSTEM_UPDATE_RELEASE_REPOSITORY = 'masta-lee/mastaincus'
  process.env.LC_ALL = 'C'
  process.env.INCUDAL_APP_DIR = app; process.env.INSTALL_DIR = '/opt/incudal'
  process.env.SYSTEM_UPDATE_APPLY_MODE = 'artifact'; process.env.SERVICE_NAME = 'incudal-backend'
  process.env.PATH = '/usr/local/libexec/incudal/ota-path:' + process.env.PATH
  process.argv = [process.execPath, app + '/server/dist/scripts/run-system-update-task.js', String(state.taskId), state.target]
  // Same platform maintenance lock as the root wrapper is held by the shell.
  await import(app + '/server/dist/scripts/run-system-update-task.js')
} else if (mode === 'rolled-back') {
  await verifyRootLauncherGitGate()
  const state = JSON.parse(await readFile(stateFile))
  const client = new Client({ connectionString: env.DATABASE_URL }); await client.connect()
  try {
    const task = (await client.query('SELECT status FROM system_update_tasks WHERE id=$1', [state.taskId])).rows[0]
    assert.equal(task.status, 'rolled_back')
    assert.equal(JSON.parse(await readFile(app + '/server/package.json')).version, state.baseline.slice(1))
    for (const file of identities) assert.equal(hash(await readFile(file)), state.original[file])
    const enrollment = JSON.parse(await readFile('/var/lib/incudal-gateway-controller/enrollment.json'))
    assert.ok(Object.values(enrollment.components).every(component => component.version === state.baseline.slice(1)))
    await exec('python3', ['-I', '-B', app + '/scripts/enroll-gateway-controller.py', '--verify'])
    await exec('systemctl', ['is-active', '--quiet', 'incudal-backend'])
    console.log('PASS actual old worker recovered after post-install failure: old runtime and component enrollment restored, original identities preserved')
  } finally { await client.end() }
} else {
  await verifyRootLauncherGitGate()
  const state = JSON.parse(await readFile(stateFile))
  const client = new Client({ connectionString: env.DATABASE_URL }); await client.connect()
  try {
    const task = (await client.query('SELECT status,backup_path FROM system_update_tasks WHERE id=$1', [state.taskId])).rows[0]
    assert.equal(task.status, 'success', 'the actual old online-update worker must finish without rollback')
    assert.equal(JSON.parse(await readFile(app + '/version.json')).version, state.candidateVersion)
    assert.equal(atomic, state.atomic)
    if (atomic) { assert.equal(task.backup_path, state.oldApp); assert.notEqual(app, state.oldApp) }
    for (const file of identities) assert.equal(hash(await readFile(file)), state.original[file], 'controller/network/environment identity preserved: ' + file)
    assert.equal((await client.query("SELECT count(*)::int AS n FROM _prisma_migrations WHERE migration_name='20261111170000_instance_renewal_price' AND finished_at IS NOT NULL AND rolled_back_at IS NULL")).rows[0].n, 1)
    const version = JSON.parse(await readFile(app + '/server/package.json'))
    assert.equal(version.version, state.applicationVersion)
    const enrollment = JSON.parse(await readFile('/var/lib/incudal-gateway-controller/enrollment.json'))
    for (const component of Object.values(enrollment.components)) {
      assert.equal(component.version, state.applicationVersion)
      assert.ok((await readFile(component.directory + '/scripts/ensure-time-sync.py')).length > 0)
    }
    assert.equal(hash(await readFile(app + '/scripts/ensure-time-sync.py')), hash(await readFile('/usr/local/libexec/incudal/ensure-time-sync.py')))
    await exec('systemctl', ['is-active', '--quiet', 'incudal-backend'])
    await exec('systemctl', ['is-enabled', '--quiet', 'incudal-time-sync.timer'])
    const { stdout } = await exec('curl', ['-fsS', '--max-time', '5', 'http://127.0.0.1:3001/api/health'])
    assert.equal(JSON.parse(stdout).status, 'ok')
    console.log(`PASS genuine ${state.baseline} worker -> new complete archive -> original identities preserved -> migrations/helpers/clock installed -> one healthy backend; candidate HTTP transport was local`)
  } finally { await client.end() }
}
