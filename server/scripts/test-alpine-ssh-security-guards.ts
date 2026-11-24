import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { generateContainerConfig } from '../src/lib/incus-config-container.js'
import { generateVmConfig } from '../src/lib/incus-config-vm.js'
import { alpineSshSecurityScript, assertAlpineSshSecurityInspection } from '../src/lib/alpine-ssh-security.js'
import { alpinePythonPackagePreparation } from '../src/lib/alpine-python-init.js'

for (const branch of ['3.19', '3.20', '3.21', '3.22', '3.23', '3.24']) {
  for (const generate of [generateContainerConfig, generateVmConfig]) {
    const data = generate({ instanceName: 'alpine-ssh-guard', imageAlias: `images:alpine/${branch}/cloud`, rootPassword: 'isolated-existing-password' }).configPayload['user.user-data']
    assert.ok(data.includes('alpine_ssh_security_update install') && data.includes('alpine_ssh_minimum'), 'both initializers install and verify the official patch')
    assert.ok(data.includes('PasswordAuthentication yes') && data.includes('ssh_pwauth: true'))
    assert.ok(!data.includes('--allow-untrusted') && !data.includes('s/https:/http:/'))
    assert.ok(!data.includes('echo "PasswordAuthentication no"') && !data.includes('PasswordAuthentication no/'))
    assert.ok(data.includes('prepare_alpine_python_packages') && data.includes('python3-ndbm'), 'fresh Alpine container and VM align Python before split-package dependency installation')
    // Both generators retain Alpine password login and verify parsed policy.
    if (generate === generateVmConfig) assert.ok(data.includes('passwordauthentication yes$'))
  }
}
for (const mode of ['clean', 'partial', 'repair-failed', 'no-python']) {
  const shell = spawnSync(process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/sh', [], {
    input: `set -eu\n${alpinePythonPackagePreparation}\n` + `
trace=''
apk() {
  if [ "$1" = info ]; then [ '${mode}' != no-python ] && [ "$3" = python3 ]; return; fi
  trace="$trace $5"
  if [ "$5" = upgrade ]; then [ '${mode}' = clean ]; else [ '${mode}' != repair-failed ]; fi
}
if prepare_alpine_python_packages; then result=ok; else result=failed; fi
printf '%s|%s' "$result" "$trace"
`, encoding: 'utf8', windowsHide: true
  })
  assert.equal(shell.status, 0, shell.stderr)
  const expected = mode === 'clean' ? 'ok| upgrade' : mode === 'partial' ? 'ok| upgrade fix' : mode === 'repair-failed' ? 'failed| upgrade fix' : 'ok|'
  assert.equal(shell.stdout, expected)
}
assert.doesNotThrow(() => assertAlpineSshSecurityInspection('INCUDAL_SSH_NOT_ALPINE\n'))
assert.doesNotThrow(() => assertAlpineSshSecurityInspection('INCUDAL_ALPINE_SSH_FIXED\n'))
for (const output of ['', 'apk unavailable', 'prefix INCUDAL_ALPINE_SSH_FIXED', 'INCUDAL_ALPINE_SSH_UNPATCHED']) {
  assert.throws(() => assertAlpineSshSecurityInspection(output))
}
assert.ok(alpineSshSecurityScript.includes('--repositories-file') && alpineSshSecurityScript.includes('openssh-server~'))
assert.ok(alpineSshSecurityScript.includes('rc-service sshd reload') && !alpineSshSecurityScript.includes('sshd restart'))
assert.ok(alpineSshSecurityScript.includes('/proc/$alpine_ssh_pid/maps') && alpineSshSecurityScript.includes('(deleted)') && alpineSshSecurityScript.includes('/proc/$alpine_ssh_pid/ns/pid') && alpineSshSecurityScript.includes('/proc/$alpine_ssh_pid/root'), 'listener receipt verifies same-root executable library mappings as well as the installed binary')
assert.ok(alpineSshSecurityScript.includes('flock -w 2 9'),'allow bounded acquisition after BusyBox watchdog exits, without releasing a live inherited lock')
assert.ok(alpineSshSecurityScript.includes('cmp -s') && !alpineSshSecurityScript.includes('chpasswd') && !/^\s*ssh-keygen\b/m.test(alpineSshSecurityScript))
const delivery = readFileSync(new URL('../src/services/dedicated-delivery.ts', import.meta.url), 'utf8')
assert.ok(delivery.indexOf('assertAlpineSshSecurityInspection(result.stdout)') < delivery.indexOf('await checkSshLogin(publicIp'))
const hostRoute = readFileSync(new URL('../src/routes/hosts.ts', import.meta.url), 'utf8')
assert.ok(hostRoute.includes("script.replace('# INJECT_ALPINE_SSH_SECURITY', () => securityScript)"))
// Exercise the same public tsx API and real preflight import as the native
// entry without requiring Docker. Node's raw register(tsx/esm) is rejected.
const nativeSource=readFileSync(new URL('../../scripts/test-alpine-ssh-native.mjs',import.meta.url),'utf8')
const nativeBootstrap=nativeSource.split("assert.equal(process.platform, 'linux'")[0]
const bootstrap=spawnSync(process.execPath,['--input-type=module','--eval',nativeBootstrap+
  '\nassert.ok(alpineSshPreflightScript.includes("MemAvailable"));assert.equal(readAlpineSshPreflight("INCUDAL_SSH_PREFLIGHT aarch64 262144 0 262144 1024 0 0").status,"verified")'],
  {cwd:new URL('../../scripts/',import.meta.url),encoding:'utf8',windowsHide:true})
assert.equal(bootstrap.status,0,bootstrap.stdout+bootstrap.stderr)
console.log('PASS Alpine SSH guards: signed same-branch patch, password policy, missing inspection refusal, reload and identity preservation')
