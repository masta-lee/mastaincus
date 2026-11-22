import { constants } from 'node:fs'
import { open, lstat } from 'node:fs/promises'

// Privileged migration credentials never enter the business process or a
// utility running under its OS uid (which could read a peer's /proc environ).
export async function retainedMigrationIdentity(runtime: URL): Promise<URL> {
  if (process.platform !== 'linux' || process.getuid?.() !== 0) throw new Error('DATABASE_MIGRATION_ROOT_REQUIRED')
  const directory = '/var/lib/incudal-database', info = await lstat(directory)
  if (!info.isDirectory() || info.uid !== 0 || (info.mode & 0o077) !== 0) throw new Error('DATABASE_MIGRATION_IDENTITY_UNTRUSTED')
  const file = await open(directory + '/migration.url', constants.O_RDONLY | constants.O_NOFOLLOW)
  try {
    const stat = await file.stat()
    if (!stat.isFile() || stat.uid !== 0 || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 || stat.size > 4096) throw new Error('DATABASE_MIGRATION_IDENTITY_UNTRUSTED')
    const url = new URL((await file.readFile('utf8')).trim())
    if (!['postgresql:', 'postgres:'].includes(url.protocol) || !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) || url.hostname !== runtime.hostname || (url.port || '5432') !== (runtime.port || '5432') || url.pathname !== runtime.pathname || url.username !== 'incudal_migrate' || !url.password || url.hash) throw new Error('DATABASE_MIGRATION_IDENTITY_UNTRUSTED')
    return url
  } finally { await file.close() }
}
