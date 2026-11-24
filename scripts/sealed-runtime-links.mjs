import { execFileSync } from 'node:child_process'

// Preserve the launcher's exact Bash %q format and locale-aware sort ordering. Read every
// target with one find instead of spawning readlink for each package entry.
export function sealedRuntimeLinks(app) {
  const args = ['.', '-xdev', '-type', 'l']
  for (const path of ['server/certs', '.npm', '.cache', '.incudal-update-downloads', 'update-logs', 'agent-release']) args.push('!', '-path', './' + path + '/*')
  args.push('-printf', '%p\\0%l\\0')
  const bytes = execFileSync('find', args, { cwd: app, timeout: 30000, maxBuffer: 4 * 1024 * 1024 })
  const rows = new TextDecoder('utf-8', { fatal: true }).decode(bytes).split('\0')
  if (rows.pop() !== '' || rows.length % 2) throw Error('SEALED_RUNTIME_LINK_QUERY_FAILED')
  const pairs = []
  // The existing seal uses command substitution, which removes trailing LF.
  for (let i = 0; i < rows.length; i += 2) pairs.push([rows[i], rows[i + 1].replace(/\n+$/, '')])
  const targets = new Map(pairs)
  if (targets.size !== pairs.length) throw Error('SEALED_RUNTIME_LINK_QUERY_FAILED')
  // The installed root launcher uses sort -z under its inherited locale.
  // Byte ordering differs for scoped pnpm package names in en_US.UTF-8.
  const sorted = execFileSync('sort', ['-z'], { input: Buffer.from(pairs.map(pair => pair[0] + '\0').join('')),
    encoding: 'utf8', timeout: 30000, maxBuffer: 4 * 1024 * 1024 }).split('\0')
  if (sorted.pop() !== '' || sorted.length !== pairs.length || sorted.some(path => !targets.has(path))) throw Error('SEALED_RUNTIME_LINK_QUERY_FAILED')
  const input = Buffer.from(sorted.map(path => path + '\0' + targets.get(path) + '\0').join(''))
  return execFileSync('/bin/bash', ['-c', 'while IFS= read -r -d "" link && IFS= read -r -d "" target; do printf "%q -> %q\\n" "$link" "$target"; done'],
    { cwd: app, input, encoding: 'utf8', timeout: 30000, maxBuffer: 4 * 1024 * 1024 })
}
