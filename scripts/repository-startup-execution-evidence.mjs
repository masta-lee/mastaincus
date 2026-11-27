// Test-only validation of native systemd execution records. A daemon-reload can
// reset ExecStartPost metadata while the same backend invocation keeps running.
const executionFields = ['pid', 'exitCode', 'exitStatus', 'startRealtimeUsec',
  'startMonotonicUsec', 'stopRealtimeUsec', 'stopMonotonicUsec']

function repositoryStartup(unit) {
  if (!Array.isArray(unit?.ExecStartPost)) return undefined
  const entries = unit.ExecStartPost.filter(entry => entry?.repositoryStartupExactCommand === true)
  return entries.length === 1 ? entries[0] : undefined
}

function activeInvocation(unit) {
  return unit?.ActiveState === 'active' && unit.SubState === 'running' && unit.Result === 'success' &&
    /^[a-f0-9]{32}$/.test(unit.InvocationID || '') && Number.isSafeInteger(unit.MainPID) && unit.MainPID > 0 &&
    Number.isSafeInteger(unit.ExecMainStartTimestampMonotonic) && unit.ExecMainStartTimestampMonotonic > 0 &&
    Number.isSafeInteger(unit.ActiveEnterTimestampMonotonic) &&
    unit.ActiveEnterTimestampMonotonic >= unit.ExecMainStartTimestampMonotonic
}

function sameProtectedFiles(before, after) {
  if (!Array.isArray(before) || !Array.isArray(after) || before.length !== after.length) return false
  return before.every((file, index) => {
    const other = after[index]
    return typeof file?.path === 'string' && file.path === other?.path &&
      /^[a-f0-9]{64}$/.test(file.sha256 || '') && file.sha256 === other.sha256 &&
      Number.isSafeInteger(file.bytes) && file.bytes > 0 && file.bytes === other.bytes &&
      file.uid === 0 && other.uid === 0 && file.gid === 0 && other.gid === 0 &&
      file.links === 1 && other.links === 1 && /^0o[0-7]{3}$/.test(file.mode || '') &&
      file.mode === other.mode && !(parseInt(file.mode.slice(2), 8) & 0o022)
  })
}

function sameNormalizer(before, after) {
  return before?.sha256 === after?.sha256 && /^[a-f0-9]{64}$/.test(after?.sha256 || '') &&
    Number.isSafeInteger(after.bytes) && after.bytes > 0 && before.bytes === after.bytes &&
    before.uid === 0 && after.uid === 0 && before.gid === 0 && after.gid === 0 &&
    before.links === 1 && after.links === 1 && before.mode === '0o755' && after.mode === '0o755'
}

export function hasCompletedRepositoryStartup(snapshot) {
  const unit = snapshot?.unit
  const entry = repositoryStartup(unit)
  if (!activeInvocation(unit) || !entry || entry.ignoreErrors !== false ||
      entry.source !== 'native-systemd-dbus-execution-tuple') return false
  return executionFields.every(field => Number.isSafeInteger(entry[field]) && entry[field] >= 0) &&
    entry.exitCode === 1 && entry.exitStatus === 0 && entry.pid > 0 &&
    entry.startRealtimeUsec > 0 && entry.stopRealtimeUsec > 0 &&
    entry.startMonotonicUsec >= unit.ExecMainStartTimestampMonotonic &&
    entry.stopMonotonicUsec >= entry.startMonotonicUsec &&
    entry.stopMonotonicUsec <= unit.ActiveEnterTimestampMonotonic
}

export function hasRecordedRepositoryStartup(snapshot, reports) {
  const unit = snapshot?.unit
  const current = repositoryStartup(unit)
  if (!activeInvocation(unit) || !current || current.ignoreErrors !== false ||
      current.source !== 'native-systemd-dbus-execution-tuple' ||
      !Array.isArray(unit.FragmentPath) || unit.FragmentPath.length !== 1 ||
      !executionFields.every(field => current[field] === 0) || !Array.isArray(reports) ||
      reports.length < 3 || reports.length > 512) return false
  const ready = reports[0]
  const finished = reports.at(-1)
  if (ready?.phase !== 'current-startup-observer-ready' || ready.readonly !== true ||
      finished?.phase !== 'current-startup-observer-finished' || finished.readonly !== true ||
      !sameNormalizer(ready.normalizer, snapshot.normalizer) ||
      !sameNormalizer(finished.normalizer, snapshot.normalizer)) return false
  const samples = reports.filter(report => report?.phase === 'current-startup-observer-snapshot')
  if (finished.snapshots !== samples.length) return false
  return samples.some(sample => {
    const observed = sample.unit
    const entry = repositoryStartup(observed)
    return sample.stableInvocation === true && hasCompletedRepositoryStartup(sample) &&
      observed.InvocationID === unit.InvocationID && observed.MainPID === unit.MainPID &&
      observed.ExecMainStartTimestampMonotonic === unit.ExecMainStartTimestampMonotonic &&
      observed.ActiveEnterTimestampMonotonic === unit.ActiveEnterTimestampMonotonic &&
      sameProtectedFiles(observed.FragmentPath, unit.FragmentPath) &&
      sameProtectedFiles(observed.DropInPaths, unit.DropInPaths) &&
      /^[a-f0-9]{64}$/.test(entry.argumentsSha256 || '') && entry.argumentsSha256 === current.argumentsSha256
  })
}
