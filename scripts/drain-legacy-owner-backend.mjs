// Drain an enrolled legacy backend before its installed updater calls stop.
// This avoids the old unit's short stop budget without replacing live code,
// changing systemd policy or stopping any customer service.
import assert from 'node:assert/strict'
import { readFileSync, statSync, readlinkSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import {realpathSync} from 'node:fs'

export async function drainOwnedBackend(read, signal, wait = ms => new Promise(resolve => setTimeout(resolve, ms)), now = Date.now) {
  const before = read(), pid = Number(before.MainPID)
  assert.ok(pid > 1 && before.Result === 'success' && before.ActiveState === 'active')
  signal()
  const deadline = now() + 35 * 60 * 1000
  while (now() < deadline) {
    const current = read()
    if (current.MainPID === '0') {
      assert.equal(current.Result, 'success', 'legacy backend did not drain successfully')
      assert.equal(current.ActiveState, 'inactive')
      return
    }
    assert.equal(Number(current.MainPID), pid, 'legacy backend process changed while draining')
    await wait(250)
  }
  throw Error('OWNER_LEGACY_BACKEND_DRAIN_PENDING')
}

export async function drainLegacyOwnerBackend(app) {
  assert.equal(process.platform, 'linux'); assert.equal(process.getuid(), 0)
  const show = () => Object.fromEntries(execFileSync('/usr/bin/systemctl', ['show', 'incudal-backend.service', '--property=MainPID,User,Group,WorkingDirectory,Restart,Result,ActiveState'], { encoding: 'utf8', timeout: 10000 }).trim().split('\n').map(line => line.split('=')))
  const before = show(), pid = Number(before.MainPID)
  assert.ok(pid > 1 && before.User === 'incudal' && before.Group === 'incudal' && before.Result === 'success' && before.ActiveState === 'active')
  assert.ok(before.Restart === 'on-failure' && ['/opt/incudal', '/opt/incudal/current'].includes(before.WorkingDirectory))
  assert.equal(readlinkSync(`/proc/${pid}/exe`), '/usr/bin/node')
  assert.ok(readFileSync(`/proc/${pid}/cmdline`).equals(Buffer.from(`/usr/bin/node\0${before.WorkingDirectory}/server/dist/app.js\0`)))
  const installed = statSync('/usr/bin/node'), running = statSync(`/proc/${pid}/exe`)
  assert.equal(installed.ino, running.ino); assert.equal(installed.dev, running.dev)
  assert.ok(app === '/opt/incudal' || app.startsWith('/opt/incudal/releases/'))
  assert.equal(realpathSync(before.WorkingDirectory), app)
  assert.equal(readlinkSync(`/proc/${pid}/ns/pid`), readlinkSync('/proc/1/ns/pid'))
  // Signal only systemd's authenticated main process. Normal exit=0 does not
  // restart an on-failure service; errors remain failures and stop deployment.
  await drainOwnedBackend(show, () => execFileSync('/usr/bin/systemctl', ['kill', '--kill-whom=main', '--signal=SIGTERM', 'incudal-backend.service'], { stdio: 'pipe', timeout: 10000 }))
  console.log('OWNER_LEGACY_BACKEND_DRAIN_CONFIRMED')
}
