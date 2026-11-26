import assert from 'node:assert/strict'
import { readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { runInNewContext } from 'node:vm'
import { createHash } from 'node:crypto'

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
const installer = read('scripts/install-panel.sh')
const pinnedHelpers = installer.match(/PINNED_STARTUP_HELPERS = frozenset\(\{([\s\S]*?)\}\)/)?.[1]
assert.ok(pinnedHelpers, 'startup normalization must retain independent complete helper content pins')
assert.deepEqual([...pinnedHelpers.matchAll(/'([a-f0-9]{64})'/g)].map(match => match[1]).sort(), [
  createHash('sha256').update(readFileSync(resolve(root, 'deploy/incudal-online-task.sh.example'))).digest('hex'),
  '15fd9cac0a7af20a2a8499b10637c7d3696c99ef1abe81eacce728134011219a'
].sort(), 'startup pin updates must follow the exact current helper bytes and original v1.8.13/v1.8.14 helper identity')
assert.ok(installer.includes('if source.sha not in PINNED_STARTUP_HELPERS:') &&
  installer.includes('if source.sha != source_digest(manifest.raw): refuse()') &&
  installer.includes('if installed.raw not in (source.raw, converted): refuse()') &&
  installer.includes('if runtime() != (app, current): refuse()') &&
  rootHelper.includes('  verify_manifest\n  verify_git_control\n'),
  'known exact helpers may normalize during the pre-seal startup transition; unknown helpers, installed bytes, identity and actual root task seals remain guarded')
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
assert.ok(workflow.includes('/usr/bin/python3 -I -B scripts/test-repository-startup-normalizer.py') &&
  legacyDrill.includes('scripts/test-repository-startup-normalizer.py" "$old"') &&
  read('scripts/run-tests.mjs').includes("['test:repository-startup-normalizer', 'requires native Linux root;"),
  'actual Linux normalizer transition and refusal checks must run for both new and original package paths and remain explicitly classified')
assert.ok(legacyDrill.includes('stage=actual-root-postflight-rollback') &&
  legacyDrill.includes('"incudal-online-rollback@${root_rollback_task}.service"') &&
  legacyDrill.includes('"incudal-online-update@${root_rollback_task}.service"') &&
  legacyWorkerDrill.includes('root-rollback-prepare') && legacyWorkerDrill.includes('root-rollback-wait') &&
  legacyWorkerDrill.includes('root duplicate task must preserve the completed rollback'),
  'rollback regression must use the real root units and admit the next duplicate worker without an extra backend restart')
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
