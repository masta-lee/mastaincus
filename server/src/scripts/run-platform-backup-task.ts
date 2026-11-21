import '../config/env.js'
import { runPlatformBackupTask, readWorkerRequest } from '../services/platform-backup-worker.js'
import { closePrismaDatabase, initializeFinancialDatabaseIntegrity } from '../db/prisma.js'

// The fixed root helper validates the sealed application and holds the operation flock.
try {
  const request = await readWorkerRequest(process.argv[2] || '')
  // A damaged current database must not prevent restoring an authenticated
  // backup. Export and reopening still require the current finance baseline.
  if (request.kind === 'backup' || request.kind === 'resume') await initializeFinancialDatabaseIntegrity()
  await runPlatformBackupTask(request)
} catch {
  // Never print SDK errors, environment values or database utility output.
  process.stderr.write('Platform backup task could not start; inspect the protected task status.\n')
  process.exitCode = 1
}
finally { try { await closePrismaDatabase() } catch { process.exitCode = 1 } }
// Imported authentication modules own periodic timers. This is a completed
// oneshot, not a backend: release its operation lock after awaited work/cleanup.
process.exit(process.exitCode || 0)
