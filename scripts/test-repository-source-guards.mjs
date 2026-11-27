import assert from 'node:assert/strict'
import { hasCompletedRepositoryStartup, hasRecordedRepositoryStartup } from './repository-startup-execution-evidence.mjs'
import { readFileSync, existsSync, mkdtempSync, mkdirSync, writeFileSync, readdirSync, realpathSync, lstatSync, rmSync } from 'node:fs'
import { resolve, basename, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { runInNewContext } from 'node:vm'
import { createHash } from 'node:crypto'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'

const root = fileURLToPath(new URL('../', import.meta.url))
const read = path => readFileSync(resolve(root, path), 'utf8')
const repository = 'masta-lee/mastaincus'
const retiredRepository = 'mastalee928/payincus'
for (const path of ['README.md', 'scripts/install-panel.sh', 'scripts/init-env.sh', 'deploy/incudal-online-task.sh.example', 'server/src/lib/system-version.ts', 'server/src/routes/agent.ts', 'docs/fork-release.md']) {
  const content = read(path)
  assert.ok(content.includes(repository), `${path} must use the maintained repository`)
  assert.ok(!/VipMaxxxx\/payincus/i.test(content), `${path} must not direct installations or updates to the upstream repository`)
}
// Run the actual dependency-free repository selectors with isolated env data.
// Existing persisted defaults must migrate; explicit forks keep precedence.
function selectedRepository(path, name, env) {
  const declaration = read(path).match(new RegExp(`^function ${name}\\(\\): string \\{[\\s\\S]*?^\\}`, 'm'))?.[0]
  assert.ok(declaration, `${name} must retain a testable source selector`)
  return runInNewContext(`(${declaration.replace('(): string', '()')})()`, {
    process: { env: Object.freeze({ ...env }) }, defaultAgentReleaseRepository: repository
  }, { timeout: 1000 })
}
for (const [env, expected] of [
  [{}, repository],
  [{ SYSTEM_UPDATE_RELEASE_REPOSITORY: retiredRepository }, repository],
  [{ SYSTEM_UPDATE_RELEASE_REPOSITORY: `  ${retiredRepository.toUpperCase()}  ` }, repository],
  [{ GITHUB_REPO: retiredRepository }, repository],
  [{ SYSTEM_UPDATE_RELEASE_REPOSITORY: 'custom/panel', GITHUB_REPO: retiredRepository }, 'custom/panel'],
  [{ SYSTEM_UPDATE_RELEASE_REPOSITORY: '  ', GITHUB_REPO: 'custom/panel' }, 'custom/panel'],
  [{ SYSTEM_UPDATE_RELEASE_REPOSITORY: `${retiredRepository}-fork` }, `${retiredRepository}-fork`]
]) assert.equal(selectedRepository('server/src/lib/system-version.ts', 'getReleaseRepository', env), expected)
for (const [env, expected] of [
  [{}, repository],
  [{ INCUDAL_AGENT_RELEASE_REPOSITORY: retiredRepository }, repository],
  [{ INCUDAL_AGENT_RELEASE_REPOSITORY: ` ${retiredRepository.toUpperCase()} ` }, repository],
  [{ GITHUB_REPOSITORY: retiredRepository }, repository],
  [{ INCUDAL_AGENT_RELEASE_REPOSITORY: 'custom/agent', GITHUB_REPOSITORY: retiredRepository }, 'custom/agent'],
  [{ GITHUB_REPOSITORY: 'custom/agent' }, 'custom/agent'],
  [{ INCUDAL_AGENT_RELEASE_REPOSITORY: 'https://untrusted.invalid/source' }, repository],
  [{ INCUDAL_AGENT_RELEASE_REPOSITORY: `${retiredRepository}-fork` }, `${retiredRepository}-fork`]
]) assert.equal(selectedRepository('server/src/routes/agent.ts', 'getAgentReleaseRepository', env), expected)
const rootHelper = read('deploy/incudal-online-task.sh.example')
assert.ok(rootHelper.includes('verify_manifest\n  verify_git_control\n') &&
  rootHelper.includes('if [[ "$status" -eq 0 ]]; then\n    verify_git_control migrate-retired-origin\n    write_manifest'),
  'root OTA must preserve the original seal during work and migrate its exact retired Git origin only after success')
assert.ok(rootHelper.includes('config --local --get-all remote.origin.url') && rootHelper.includes('Git origin URL rewriting is forbidden'),
  'root OTA must verify the unique raw origin rather than accepting a rewritten custom URL')
assert.ok(rootHelper.includes('executable Git configuration is forbidden for root OTA') &&
  rootHelper.indexOf('executable Git configuration is forbidden for root OTA') < rootHelper.indexOf('remote set-url origin'),
  'origin migration must retain the root Git executable-configuration gate')
const taskPostflight = rootHelper.match(/if \[\[ "\$status" -eq 0 \]\]; then[\s\S]*?\n  fi\n  return "\$status"/)?.[0]
assert.ok(taskPostflight && taskPostflight.indexOf('write_manifest') < taskPostflight.indexOf('/usr/bin/env -i') &&
  taskPostflight.includes("== 0:0:755:1") && taskPostflight.includes('untrusted repository startup parent') &&
  taskPostflight.includes('/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /usr/bin/bash "$repository_startup"'),
  'successful root postflight must normalize a restored old helper after sealing the migrated origin, with protected paths and a clean environment')
for (const path of ['scripts/apply-verified-owner-candidate.mjs', 'scripts/smoke-legacy-online-upgrade.mjs']) {
  assert.match(read(path), /process\.env\.SYSTEM_UPDATE_RELEASE_REPOSITORY\s*=\s*'masta-lee\/mastaincus'/,
    `${path} must send the original worker to the replacement repository`)
}
const readme = read('README.md')
assert.ok(!/https:\/\/(?:[a-z]+\.)?payincus\.com|t\.me\/Payincus/.test(readme), 'README links must belong to this project')
for (const match of readme.matchAll(/\]\(([^)]+)\)|href="([^"]+)"/g)) {
  const link = match[1] || match[2]
  if (/^(https?:|#)/.test(link)) continue
  assert.ok(existsSync(resolve(root, link.split('#')[0])), `README target must exist: ${link}`)
}
assert.match(read('LICENSE'), /Copyright \(c\) 2026, VipMaxxxx/, 'original copyright must be retained')
const workflow = read('.github/workflows/release.yml')
for (const path of ['probe-management-gateway.py', 'probe-onboarding-resources.py', 'ensure-host-swap.py', 'configure-oci-node-network.sh', 'onboarding-gateway.py', 'gateway-domain-control.py', 'upgrade-onboarding-gateway.py', 'install-onboarding-gateway.sh', 'setup-onboarding-control.py', 'refresh-onboarding-gateway.sh', 'install-panel.sh']) {
  assert.ok(workflow.includes(`cp scripts/${path} release/scripts/`), `release must include ${path}`)
}
assert.ok(workflow.includes('fresh-install:'), 'publication must depend on fresh installation checks')
assert.ok(workflow.includes('- fresh-install'), 'Release must wait for fresh installation checks')
assert.ok(workflow.includes("if: always() && startsWith(github.ref, 'refs/tags/v') && needs.build.result == 'success' && needs.fresh-install.result == 'success' && needs.legacy-upgrade.result == 'success'"),
  'formal publication must survive the intentionally skipped preview-agent dependency but reject any failed build/install/upgrade gate')

// Execute the actual workflow shell with local subprocess controls. Neither gh
// nor sleep reaches the network, while checksum verification uses real coreutils.
const legacyDownloadStep = workflow.match(/      - name: 下载并校验原v1\.8\.14发行包[\s\S]*?        run: \|\r?\n([\s\S]*?)      - name: 原worker升级至新包/)?.[1]
assert.ok(legacyDownloadStep, 'the original release download step must remain independently executable')
const legacyDownloadShell = legacyDownloadStep.split(/\r?\n/).map(line => line.replace(/^          /, '')).join('\n')
const bashExecutable = process.platform === 'win32'
  ? [resolve(process.env.ProgramFiles || 'C:/Program Files', 'Git/bin/bash.exe'),
      resolve(process.env.ProgramFiles || 'C:/Program Files', 'Git/usr/bin/bash.exe')].find(existsSync)
  : '/usr/bin/bash'
assert.ok(bashExecutable && existsSync(bashExecutable), 'download subprocess controls require the existing native Bash toolchain')
const legacyShellPath = value => value.replaceAll('\\', '/').replace(/^([A-Za-z]):/, (_, drive) => '/' + drive.toLowerCase())
const mockGh = String.raw`#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -eq 1 && "$1" == --legacy-fixture-probe ]]; then exit 0; fi
[[ "$#" -eq 11 && "$1" == release && "$2" == download && "$3" == v1.8.14 ]]
[[ "$4" == --repo && "$5" == masta-lee/mastaincus && "$6" == --pattern && "$7" == "$CI_LEGACY_FIXTURE_ARCHIVE" ]]
[[ "$8" == --pattern && "$9" == "$CI_LEGACY_FIXTURE_ARCHIVE.sha256" ]]
shift 9
[[ "$1" == --dir ]]
download_dir="$2"
[[ "$download_dir" == "$RUNNER_TEMP"/incudal-legacy-download.*/attempt-* ]]
count=0
if [[ -f "$CI_LEGACY_FIXTURE_ROOT/calls" ]]; then read -r count < "$CI_LEGACY_FIXTURE_ROOT/calls"; fi
count=$((count + 1))
printf '%s\n' "$count" > "$CI_LEGACY_FIXTURE_ROOT/calls"
printf '%s\n' "$download_dir" >> "$CI_LEGACY_FIXTURE_ROOT/directories"
if [[ "$CI_LEGACY_FIXTURE_MODE" == continuous || ( "$CI_LEGACY_FIXTURE_MODE" == transient && "$count" -eq 1 ) ]]; then
  printf 'partial download\n' > "$download_dir/$CI_LEGACY_FIXTURE_ARCHIVE"
  printf 'release not found\n' >&2
  exit 1
fi
printf 'retained-original-v1.8.14-%s\n' "$CI_LEGACY_FIXTURE_ARCH" > "$download_dir/$CI_LEGACY_FIXTURE_ARCHIVE"
(cd "$download_dir" && sha256sum --binary "$CI_LEGACY_FIXTURE_ARCHIVE" > "$CI_LEGACY_FIXTURE_ARCHIVE.sha256")
if [[ "$CI_LEGACY_FIXTURE_MODE" == bad-checksum ]]; then
  printf 'corrupted bytes\n' >> "$download_dir/$CI_LEGACY_FIXTURE_ARCHIVE"
fi
`
const mockSleep = String.raw`#!/usr/bin/env bash
set -euo pipefail
[[ "$#" -eq 1 && ( "$1" == 2 || "$1" == 4 ) ]]
printf '%s\n' "$1" >> "$CI_LEGACY_FIXTURE_ROOT/waits"
`
const checksumControl = String.raw`#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == --check ]]; then printf 'check\n' >> "$CI_LEGACY_FIXTURE_ROOT/checks"; fi
exec /usr/bin/sha256sum "$@"
`
for (const arch of ['amd64', 'arm64']) for (const mode of ['transient', 'continuous', 'bad-checksum']) {
  const fixtureParent = realpathSync(tmpdir())
  const fixtureRoot = mkdtempSync(resolve(fixtureParent, 'mastaincus-legacy-download-control-'))
  const fixtureIdentity = realpathSync(fixtureRoot)
  assert.ok(fixtureIdentity.startsWith(fixtureParent + sep) && basename(fixtureIdentity).startsWith('mastaincus-legacy-download-control-'))
  try {
    const bin = resolve(fixtureRoot, 'bin'), runnerTemp = resolve(fixtureRoot, 'runner-temp')
    mkdirSync(bin); mkdirSync(runnerTemp)
    mkdirSync(resolve(runnerTemp, 'kept'))
    writeFileSync(resolve(runnerTemp, 'kept/sentinel'), 'unrelated temporary data')
    for (const [name, content] of [['gh', mockGh], ['sleep', mockSleep], ['sha256sum', checksumControl]]) {
      writeFileSync(resolve(bin, name), content, { mode: 0o755 })
    }
    const archive = 'incudal-v1.8.14-linux-' + arch + '.tar.gz'
    const fixtureEnv = { ...process.env, GITHUB_REPOSITORY: repository,
      RUNNER_TEMP: legacyShellPath(runnerTemp), CI_LEGACY_FIXTURE_BIN: legacyShellPath(bin),
      CI_LEGACY_FIXTURE_ROOT: legacyShellPath(fixtureRoot), CI_LEGACY_FIXTURE_ARCHIVE: archive,
      CI_LEGACY_FIXTURE_ARCH: arch, CI_LEGACY_FIXTURE_MODE: mode }
    for (const key of ['GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN']) delete fixtureEnv[key]
    const script = 'export PATH="$CI_LEGACY_FIXTURE_BIN:$PATH"\ngh --legacy-fixture-probe\n' +
      legacyDownloadShell.replaceAll('${{ matrix.arch }}', arch)
    const result = spawnSync(bashExecutable, ['--noprofile', '--norc', '-e', '-c', script],
      { cwd: fixtureRoot, env: fixtureEnv, encoding: 'utf8', timeout: 30_000 })
    assert.equal(result.error, undefined, arch + '/' + mode + ' must complete its actual subprocess')
    assert.ok(existsSync(resolve(fixtureRoot, 'calls')), arch + '/' + mode + ' must reach the controlled gh: ' + result.stderr + result.stdout)
    const readLines = name => existsSync(resolve(fixtureRoot, name))
      ? readFileSync(resolve(fixtureRoot, name), 'utf8').trim().split(/\r?\n/) : []
    const calls = Number(readFileSync(resolve(fixtureRoot, 'calls'), 'utf8').trim())
    assert.equal(calls, mode === 'transient' ? 2 : mode === 'continuous' ? 3 : 1, arch + '/' + mode + ' must retain its finite download bound')
    assert.deepEqual(readLines('waits'), mode === 'transient' ? ['2'] : mode === 'continuous' ? ['2', '4'] : [])
    assert.equal(new Set(readLines('directories')).size, calls, 'every retry must use a new private directory')
    assert.equal(readLines('checks').length, mode === 'continuous' ? 0 : 1, 'only a successful download reaches one real checksum check')
    const oldArtifact = resolve(fixtureRoot, 'old-artifact')
    if (mode === 'transient') {
      assert.equal(result.status, 0, result.stderr)
      const expected = 'retained-original-v1.8.14-' + arch + '\n'
      assert.equal(readFileSync(resolve(oldArtifact, archive), 'utf8'), expected, 'partial download bytes must not escape into the upgrade input')
      assert.equal(readFileSync(resolve(oldArtifact, archive + '.sha256'), 'utf8'),
        createHash('sha256').update(expected).digest('hex') + ' *' + archive + '\n')
      assert.deepEqual(readdirSync(oldArtifact).sort(), [archive, archive + '.sha256'].sort(), 'only the original archive and checksum may be handed to the worker')
    } else {
      assert.notEqual(result.status, 0, 'exhaustion and bad checksums must fail the actual workflow')
      assert.equal(existsSync(oldArtifact), false, 'failed input must never be handed to the original worker')
      if (mode === 'bad-checksum') assert.match(result.stdout, /FAILED/, 'the real checksum tool must reject corrupted bytes')
    }
    assert.equal(readFileSync(resolve(runnerTemp, 'kept/sentinel'), 'utf8'), 'unrelated temporary data')
    assert.deepEqual(readdirSync(runnerTemp), ['kept'], 'download cleanup must preserve unrelated temporary paths')
  } finally {
    assert.equal(realpathSync(fixtureRoot), fixtureIdentity, 'fixture cleanup must retain its exact temporary root')
    assert.ok(lstatSync(fixtureRoot).isDirectory() && !lstatSync(fixtureRoot).isSymbolicLink())
    rmSync(fixtureRoot, { recursive: true, force: false })
  }
}
console.log('Original release download subprocess controls passed: both architectures, finite retry, real checksum refusal and private cleanup')

const installer = read('scripts/install-panel.sh')
const pinnedHelpers = installer.match(/PINNED_STARTUP_HELPERS = frozenset\(\{([\s\S]*?)\}\)/)?.[1]
assert.ok(pinnedHelpers, 'startup normalization must retain independent complete helper content pins')
assert.deepEqual([...pinnedHelpers.matchAll(/'([a-f0-9]{64})'/g)].map(match => match[1]).sort(), [
  createHash('sha256').update(readFileSync(resolve(root, 'deploy/incudal-online-task.sh.example'))).digest('hex'),
  '15fd9cac0a7af20a2a8499b10637c7d3696c99ef1abe81eacce728134011219a'
].sort(), 'startup pin updates must follow the exact current helper bytes and original v1.8.13/v1.8.14 helper identity')
assert.ok(installer.includes('if source.sha not in PINNED_STARTUP_HELPERS:') &&
  installer.includes('if source.sha != source_digest(manifest.raw): refuse()') &&
  installer.includes('if not retained_secure and installed.raw not in (source.raw, converted): refuse()') &&
  installer.includes('if runtime() != (app, current): refuse()') &&
  rootHelper.includes('  verify_manifest\n  verify_git_control\n'),
  'known exact helpers may normalize during the pre-seal startup transition; unknown helpers, installed bytes, identity and actual root task seals remain guarded')
assert.ok(installer.includes("CURRENT_SECURE_HELPER = '" + createHash('sha256').update(readFileSync(resolve(root, 'deploy/incudal-online-task.sh.example'))).digest('hex') + "'") &&
  installer.includes('source.sha == LEGACY_HELPER and installed.sha == CURRENT_SECURE_HELPER') &&
  installer.includes("secure = hold(HELPERS + '/database-secure-task'") &&
  installer.includes('secure.sha != CURRENT_SECURE_HELPER or secure.raw != installed.raw'),
  'a retained security launcher after legacy rollback must require its exact current pin, exact legacy source and protected matching secure copy')
assert.ok(installer.includes('VERIFIED_LEGACY_DATABASE_PACKAGE=""') &&
  installer.includes('RELEASE_VERIFIED_THIS_RUN=false\n    VERIFIED_LEGACY_DATABASE_PACKAGE=""') &&
  installer.includes('database_migration_mode()') &&
  installer.includes('/usr/sbin/runuser -u "$RUN_USER" -- /usr/bin/env -i "PATH=$INSTALLER_SYSTEM_PATH" "ENV_FILE=$ENV_FILE" "HOME=$INSTALL_DIR" pnpm exec prisma migrate deploy') &&
  installer.includes('ExecStartPre=/usr/bin/env -i PATH=${INSTALLER_SYSTEM_PATH} HOME=${INSTALL_DIR} ENV_FILE=${ENV_FILE} /usr/bin/bash --noprofile --norc -c'),
  'only independently verified retained legacy archives may use their original unprivileged ORM during installation and the first startup, with fixed clean environment')
assert.ok(installer.includes("git_query(['config', '--local', '--get-regexp', dangerous]") &&
  installer.includes("git_query(['config', '--get-regexp', global_dangerous]") &&
  installer.includes("git_query(['remote', 'get-url', 'origin']) != raw") &&
  rootHelper.includes("config --local --get-regexp"),
  'metadata-only normalization must tolerate protected global LFS filters while rejecting repository execution settings, global includes/core settings and URL rewriting; root task execution keeps its own gate')
const backupInstaller = read('scripts/install-platform-backup.sh')
const legacyDrill = read('scripts/smoke-legacy-online-upgrade.sh')
const legacyWorkerDrill = read('scripts/smoke-legacy-online-upgrade.mjs')
assert.ok(installer.includes('ExecStartPost=+/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /usr/bin/bash /usr/local/libexec/incudal/incudal-repository-source-startup') &&
  backupInstaller.includes('/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/var/cache/incudal-ota /usr/bin/bash "$repository_installer" --install-repository-startup-guard'),
  'new installations and original-worker updates must keep repository correction across old startup hooks')
for (const path of ['deploy/incudal-online-update@.service.example', 'deploy/incudal-online-rollback@.service.example']) {
  assert.ok(/^After=.*\bincudal-backend\.service$/m.test(read(path)), `${path} must wait for the backend startup helper before admitting an update`)
}
assert.ok(legacyDrill.includes('stage=current-installer-restart') &&
  legacyWorkerDrill.includes('await verifyRootLauncherGitGate()') &&
  legacyWorkerDrill.includes("helper.toString('utf8').match(/^verify_git_control"),
  'legacy regression must exercise a real normal restart and the exact shipped root launcher Git gate')
assert.ok(legacyWorkerDrill.includes("'incudal-online-update@1.service'") &&
  legacyWorkerDrill.includes("'incudal-online-rollback@1.service'") &&
  !legacyWorkerDrill.includes("'incudal-online-update@.service'"),
  'systemd ordering regression must query real service instances rather than invalid template names')
assert.ok(workflow.includes('bash scripts/test-repository-startup-toolchain.sh') &&
  legacyDrill.includes('scripts/test-repository-startup-normalizer.py" "$old"') &&
  read('scripts/run-tests.mjs').includes("['test:repository-startup-normalizer', 'requires native Linux root;"),
  'actual Linux normalizer transition and refusal checks must run for both new and original package paths and remain explicitly classified')
const nodeFixture = read('scripts/test-repository-startup-toolchain.sh')
assert.ok(nodeFixture.includes('$(node -p process.execPath)') &&
  nodeFixture.includes('install -o root -g root -m 0755') &&
  nodeFixture.includes('== "$source_sha"') && nodeFixture.includes(' --node "$node_dir/node"') &&
  legacyDrill.indexOf('systemctl is-active --quiet incudal-backend') < legacyDrill.indexOf('scripts/test-repository-startup-normalizer.py" "$old"'),
  'pre-install native fixtures must use the declared build Node; genuine installed-worker regression must retain its actual system interpreter')
assert.ok(legacyDrill.includes('stage=actual-root-postflight-rollback') &&
  legacyDrill.includes('"incudal-online-rollback@${root_rollback_task}.service"') &&
  legacyDrill.includes('"incudal-online-update@${root_rollback_task}.service"') &&
  legacyWorkerDrill.includes('root-rollback-prepare') && legacyWorkerDrill.includes('root-rollback-wait') &&
  legacyWorkerDrill.includes('root duplicate task must preserve the completed rollback'),
  'rollback regression must use the real root units and admit the next duplicate worker without an extra backend restart')
const migrationDiagnostics = read('.github/workflows/repository-migration-diagnostics.yml')
const currentRollbackTrace = read('scripts/test-repository-current-rollback-native-trace.py')
assert.ok(migrationDiagnostics.includes("ref: '4a3d7c84aa66c2d2508344bfb8b0a6dd0bc54c78'") &&
  migrationDiagnostics.includes("artifact-ids: '15161578442'") &&
  migrationDiagnostics.includes('61dc194460d7f73953cca4ea9749cfec75c9d2972c40955c96e6474804d7af33') &&
  migrationDiagnostics.includes('UPGRADE_DRILL_INSTALLER_SOURCE=current') &&
  migrationDiagnostics.includes("reproducer_script='reproduction-source/scripts/smoke-legacy-online-upgrade.sh'") &&
  migrationDiagnostics.includes("reproducer_script='scripts/smoke-legacy-online-upgrade.sh'") &&
  migrationDiagnostics.includes('healthyCounterHarnessControl') &&
  migrationDiagnostics.includes('exit "$original_status"') &&
  migrationDiagnostics.includes("ref: 'c56f4fefc2f5f5c5b1e9048aa8c77305fa51336d'"),
  'current rollback diagnostics must pin their original 4a package/reproducer and retain the independent c56 historical probe')
assert.ok(currentRollbackTrace.includes("SOURCE_COMMIT = '4a3d7c84aa66c2d2508344bfb8b0a6dd0bc54c78'") &&
  currentRollbackTrace.includes("EXPECTED = '09cef9b5c92ea649d8ef03e97553a789313ff68897108322aeb3295d891ada83'") &&
  currentRollbackTrace.includes("os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'") &&
  currentRollbackTrace.includes("record(TARGET, required=True)") &&
  currentRollbackTrace.includes("stopped.get('MainPID') != 0") &&
  currentRollbackTrace.includes("os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK"),
  'diagnostics must reject local/production execution and authenticate the exact protected installed normalizer before tracing it')
assert.ok(currentRollbackTrace.includes("reply.get('type') != 'a(sasbttttuii)'") &&
  currentRollbackTrace.includes("values['ExecStartPre'] = native_exec_metadata('ExecStartPre')") &&
  currentRollbackTrace.includes("values['ExecStartPost'] = native_exec_metadata('ExecStartPost')") &&
  !currentRollbackTrace.includes("'--property=ActiveState,SubState,Result,ExecMainStatus,MainPID,InvocationID,ExecStartPre,ExecStartPost'"),
  'native D-Bus tuples must preserve every execution command and numeric status instead of overwriting repeated formatted properties')
assert.ok(currentRollbackTrace.includes('def observe_startup():') &&
  currentRollbackTrace.includes("'repositoryStartupExactCommand': executable == '/usr/bin/env'") &&
  currentRollbackTrace.includes("'stableInvocation': stable") &&
  currentRollbackTrace.includes('ExecMainStartTimestampMonotonic') &&
  currentRollbackTrace.includes("'executionSuccessDetermined': False") &&
  legacyDrill.includes('UPGRADE_DRILL_STARTUP_OBSERVE') &&
  legacyDrill.includes('trap stop_startup_observer EXIT') &&
  migrationDiagnostics.includes('UPGRADE_DRILL_STARTUP_OBSERVE="$fixture_control"') &&
  legacyWorkerDrill.includes('actual root startup correction must complete through the loaded backend unit'),
  'optional disposable-runner observation must bind native tuples to the invocation, stop its own child and retain the strict actual-startup assertion')
const executionUnit = {
  ActiveState: 'active', SubState: 'running', Result: 'success', InvocationID: 'a'.repeat(32), MainPID: 7,
  ExecMainStartTimestampMonotonic: 10, ActiveEnterTimestampMonotonic: 30,
  FragmentPath: [{path: '/etc/systemd/system/incudal-backend.service', sha256: 'b'.repeat(64),
    bytes: 100, uid: 0, gid: 0, mode: '0o644', links: 1}], DropInPaths: [],
  ExecStartPost: [{repositoryStartupExactCommand: true, ignoreErrors: false,
    source: 'native-systemd-dbus-execution-tuple', argumentsSha256: 'c'.repeat(64),
    exitCode: 1, exitStatus: 0, pid: 9, startRealtimeUsec: 100, stopRealtimeUsec: 110,
    startMonotonicUsec: 20, stopMonotonicUsec: 25}]
}
const executionNormalizer = {sha256: 'd'.repeat(64), bytes: 100, uid: 0, gid: 0, mode: '0o755', links: 1}
const completedSnapshot = {unit: executionUnit, normalizer: executionNormalizer}
assert.equal(hasCompletedRepositoryStartup(completedSnapshot), true)
const clockAdjustedSnapshot = structuredClone(completedSnapshot)
clockAdjustedSnapshot.unit.ExecStartPost[0].stopRealtimeUsec = 90
assert.equal(hasCompletedRepositoryStartup(clockAdjustedSnapshot), true,
  'normal wall-clock correction must retain successful monotonic startup execution')
for (const [field, value] of [['exitCode', 0], ['exitStatus', 7], ['pid', 0], ['ignoreErrors', true],
  ['startMonotonicUsec', 0], ['stopMonotonicUsec', 31], ['repositoryStartupExactCommand', false]]) {
  const invalid = structuredClone(completedSnapshot)
  invalid.unit.ExecStartPost[0][field] = value
  assert.equal(hasCompletedRepositoryStartup(invalid), false, `invalid execution ${field} must fail`)
}
const resetSnapshot = structuredClone(completedSnapshot)
for (const field of ['exitCode', 'exitStatus', 'pid', 'startRealtimeUsec', 'stopRealtimeUsec',
  'startMonotonicUsec', 'stopMonotonicUsec']) resetSnapshot.unit.ExecStartPost[0][field] = 0
const recordedExecution = [
  {phase: 'current-startup-observer-ready', readonly: true, normalizer: executionNormalizer},
  {phase: 'current-startup-observer-snapshot', stableInvocation: true, unit: executionUnit},
  {phase: 'current-startup-observer-finished', readonly: true, snapshots: 1, normalizer: executionNormalizer}
]
assert.equal(hasCompletedRepositoryStartup(resetSnapshot), false, 'reset fields alone never prove execution')
assert.equal(hasRecordedRepositoryStartup(resetSnapshot, recordedExecution), true)
assert.equal(hasRecordedRepositoryStartup(resetSnapshot, []), false)
assert.equal(hasRecordedRepositoryStartup(resetSnapshot, recordedExecution.slice(0, -1)), false)
for (const change of [
  value => {value.unit.InvocationID = 'e'.repeat(32)},
  value => {value.unit.MainPID = 8},
  value => {value.unit.ExecMainStartTimestampMonotonic = 11},
  value => {value.unit.FragmentPath[0].sha256 = 'e'.repeat(64)},
  value => {value.unit.ExecStartPost[0].argumentsSha256 = 'e'.repeat(64)},
  value => {value.unit.ExecStartPost[0].exitStatus = 7},
  value => {value.unit.ExecStartPost[0].source = 'unknown-source'},
  value => {value.unit.FragmentPath = []},
  value => {value.normalizer.mode = '0o777'},
  value => {value.unit.ActiveState = 'inactive'}
]) {
  const invalid = structuredClone(resetSnapshot)
  change(invalid)
  assert.equal(hasRecordedRepositoryStartup(invalid, recordedExecution), false, 'stale or changed execution evidence must fail')
}
const unstableExecution = structuredClone(recordedExecution)
unstableExecution[1].stableInvocation = false
assert.equal(hasRecordedRepositoryStartup(resetSnapshot, unstableExecution), false)
assert.ok(legacyWorkerDrill.includes('hasCompletedRepositoryStartup(snapshot)') &&
  legacyWorkerDrill.includes('hasRecordedRepositoryStartup(snapshot,reports)') &&
  legacyWorkerDrill.includes('fileFlags.O_NOFOLLOW') &&
  legacyDrill.indexOf('systemctl start "incudal-online-rollback@${root_rollback_task}.service"') <
    legacyDrill.indexOf('stop_startup_observer\n  node "$repo/scripts/smoke-legacy-online-upgrade.mjs" root-rollback-wait'),
  'root rollback must stop the read-only observer before validating its protected completed proof and original startup identity')
assert.match(legacyDrill, /\(\s*\n\s*umask 077\s*\n\s*exec [^\n]+--observe > "\$startup_observer_output"\s*\n\s*\) &/,
  'the observer proof must be created after its private umask takes effect, inside the subshell')
const fixtureBudget = legacyDrill.match(/reset_healthy_fixture_start_budget\(\) \{[\s\S]*?^\}/m)?.[0]
assert.ok(fixtureBudget && fixtureBudget.indexOf('systemctl is-active --quiet incudal-backend') < fixtureBudget.indexOf('systemctl reset-failed') &&
  fixtureBudget.includes('"$fixture_pid_after" == "$fixture_pid_before"') &&
  fixtureBudget.includes('"$fixture_limits_after" == "$fixture_limits_before"') &&
  [...legacyDrill.matchAll(/^[ \t]*reset_healthy_fixture_start_budget$/mg)].length === 2,
  'only healthy scenario boundaries may clear fixture restart counters; PID and real production limits must remain unchanged')
const faultAndRetry = legacyDrill.slice(legacyDrill.indexOf('if NODE_EXTRA_CA_CERTS='), legacyDrill.indexOf('stage=post-upgrade-verification'))
assert.ok(!faultAndRetry.includes('reset_healthy_fixture_start_budget') && !faultAndRetry.includes('reset-failed'),
  'the real fault and retry scenario must retain its uninterrupted original service restart protection')
assert.ok(legacyWorkerDrill.includes("const initialLegacyBefore=mode==='before'") &&
  legacyWorkerDrill.includes('startupInfo||initialLegacyBefore') &&
  legacyWorkerDrill.includes('startupInfo.nlink===1') &&
  legacyWorkerDrill.includes('equals(candidateStartup)'),
  'missing/invalid startup guards cannot pass current-install or post-candidate verification; exact signed startup bytes are mandatory')
assert.ok(legacyWorkerDrill.includes('assert.match(output,/^Job=(?:0)?$/m)') &&
  legacyWorkerDrill.includes('assert.match(output,/^Result=success$/m)') &&
  legacyWorkerDrill.includes('assert.match(output,/^ExecMainStatus=0$/m)'),
  'completed oneshots must retain successful natural exits and reject active jobs while accepting systemctl empty or zero no-job representations')
assert.ok(read('scripts/check-release-runtime-files.py').includes("'scripts/install-panel.sh'"),
  'the startup hook installer must be compared against its actual package bytes')
assert.ok(installer.includes('configure_host_pool_gateway'), 'installer must configure the management gateway')
assert.ok(installer.includes('--configure-host-pool'), 'existing installations need an explicit gateway setup entry')
assert.ok(installer.includes('python3 openssh-client openssh-server wireguard-tools'), 'installer must install gateway dependencies')
const gatewayInstaller = read('scripts/install-onboarding-gateway.sh')
const keyMode = gatewayInstaller.indexOf('chmod 600 "$app_key_path"')
const keyRead = gatewayInstaller.indexOf('app_public_key=$(ssh-keygen -y -f "$app_key_path")')
assert.ok(keyMode >= 0 && keyRead > keyMode, 'gateway installer must restrict the application key before OpenSSH reads it')
assert.ok(!existsSync(resolve(root, 'docs-site/docs/public/CNAME')), 'do not claim an upstream domain')
console.log('Repository source, retired-default migration and fresh installation guards passed')
