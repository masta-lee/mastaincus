import { execFile } from 'node:child_process'
import { lstat } from 'node:fs/promises'
import { promisify } from 'node:util'
import { ensure, BackupError } from './platform-backup-core.js'

const exec = promisify(execFile)
type LocaleRuntime = { list(): Promise<string[]>; generate(source: string, name: string): Promise<void>; standalone?(name: string): Promise<boolean> }
const key = (value: string) => value.toLowerCase().replace(/utf-8/g, 'utf8')
const localePattern = /^([a-z]{2,3}_[A-Z]{2})\.(?:UTF-8|utf8)(@[a-z0-9]{1,20})?$/
async function standaloneLocale(name: string) {
  if (['c', 'c.utf8', 'posix'].includes(key(name))) return true
  if (!localePattern.test(name)) return false
  // A running postmaster can retain the old locale-archive mapping after
  // localedef grows it. Individual locale files are visible to its children
  // immediately, including when locale -a already lists an archive-only name.
  for (const candidate of new Set([name, name.replace(/UTF-8/g, 'utf8')])) {
    const directory = `/usr/lib/locale/${candidate}`
    const info = await lstat(directory).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return null
      throw error
    })
    if (!info) continue
    ensure(info.isDirectory() && !info.isSymbolicLink() && info.uid === 0 && !(info.mode & 0o022) && (info.mode & 0o555) === 0o555,
      'OSS_DATABASE_LOCALE_UNAVAILABLE', 409)
    for (const category of ['LC_COLLATE', 'LC_CTYPE']) {
      const file = await lstat(`${directory}/${category}`).catch(() => null)
      if (!file) return false
      ensure(file.isFile() && !file.isSymbolicLink() && file.uid === 0 && !(file.mode & 0o022) && (file.mode & 0o444) === 0o444,
        'OSS_DATABASE_LOCALE_UNAVAILABLE', 409)
    }
    return true
  }
  return false
}
const system: LocaleRuntime = {
  standalone: standaloneLocale,
  async list() {
    try { return (await exec('/usr/bin/locale', ['-a'], { timeout: 10000, env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' } })).stdout.split(/\r?\n/) }
    catch { throw new BackupError('OSS_DATABASE_LOCALE_UNAVAILABLE', 409) }
  },
  async generate(source, name) {
    try {
      // Only system definitions are used. No archived locale files,
      // global locale change, package install or postgres restart is involved.
      // The fixed shell only sets this child's umask for public system locale
      // data. All validated names remain argv; the root worker's 077 is intact.
      await exec('/usr/bin/bash', ['-c', 'umask 022; exec /usr/bin/localedef "$@"', 'incudal-locale',
        '--no-archive', '-i', source, '-f', 'UTF-8', name], {
        timeout: 120000, maxBuffer: 65536, env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' }
      })
    } catch { throw new BackupError('OSS_DATABASE_LOCALE_UNAVAILABLE', 409) }
  }
}

export async function ensureBackupLocales(required: string[], runtime: LocaleRuntime = system) {
  let installed = await runtime.list()
  for (const name of required) {
    ensure(typeof name === 'string' && name.length <= 80 && !/[\x00-\x20/\\]/.test(name), 'OSS_DATABASE_LOCALE_UNSUPPORTED', 409)
    if (installed.some(value => key(value) === key(name)) && (!runtime.standalone || await runtime.standalone(name))) continue
    // Supported platform databases use libc UTF-8. Reject option/path injection
    // and never silently substitute C for the original collation.
    const match = localePattern.exec(name)
    ensure(match, 'OSS_DATABASE_LOCALE_UNSUPPORTED', 409)
    await runtime.generate(match[1] + (match[2] || ''), name)
    installed = await runtime.list()
    ensure(installed.some(value => key(value) === key(name)) && (!runtime.standalone || await runtime.standalone(name)),
      'OSS_DATABASE_LOCALE_UNAVAILABLE', 409)
  }
}
