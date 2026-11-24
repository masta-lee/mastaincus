// Drain an enrolled legacy backend before its installed updater calls stop.
// This avoids the old unit's short stop budget without replacing live code,
// changing systemd policy or stopping any customer service.
import assert from 'node:assert/strict'
import { readFileSync, statSync, readlinkSync,realpathSync } from 'node:fs'
import { execFileSync } from 'node:child_process'

export function knownLegacyCloseTimeout(version, journal) {
  if(version?.gitCommit!=='994fff285e9b')return false
  let messages
  try{messages=journal.trim().split('\n').map(line=>JSON.parse(line).MESSAGE).filter(Boolean)}catch{return false}
  const errors=messages.flatMap(message=>{try{const value=JSON.parse(message);return value.level===50?[value]:[]}catch{return []}})
  return errors.length===1&&errors[0].err?.type==='FastifyError'&&String(errors[0].err?.stack).includes('/avvio/boot.js:487:21')&&String(errors[0].err?.message).startsWith('Plugin did not start in time:')
}

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
  try { await drainOwnedBackend(show, () => execFileSync('/usr/bin/systemctl', ['kill', '--kill-whom=main', '--signal=SIGTERM', 'incudal-backend.service'], { stdio: 'pipe', timeout: 10000 })) }
  catch(error) {
    const failed=show()
    if(failed.MainPID!=='0'||failed.Result!=='exit-code')throw error
    // Only the owner's exact sealed legacy source can have this known old
    // timed preClose defect. Do not trust arbitrary exit failures or restart
    // a different PID. Preserve the error and let the outer caller verify all
    // tasks/customer baselines before invoking the original update worker.
    const version=JSON.parse(readFileSync(app+'/version.json','utf8'))
    if(version.gitCommit!=='994fff285e9b')throw error
    const journal=execFileSync('/usr/bin/journalctl',['-u','incudal-backend.service','_PID='+pid,'-n','30','--no-pager','-o','json'],{encoding:'utf8',timeout:10000,maxBuffer:262144})
    if(!knownLegacyCloseTimeout(version,journal))throw error
    if(show().MainPID!=='0')throw error
    execFileSync('/usr/bin/systemctl',['stop','incudal-backend.service'],{stdio:'pipe',timeout:10000})
    assert.equal(show().MainPID,'0');assert.equal(show().ActiveState,'inactive')
    console.log('OWNER_LEGACY_KNOWN_PRECLOSE_TIMEOUT_EXITED; original error retained, quiescence checks required')
    return {legacyExitTimeout:true,pid,version:version.gitCommit}
  }
  console.log('OWNER_LEGACY_BACKEND_DRAIN_CONFIRMED')
  return {legacyExitTimeout:false,pid}
}
