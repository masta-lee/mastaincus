import { execFileSync } from 'node:child_process'
import { mkdir, mkdtemp, readFile, readdir, lstat, copyFile, rm } from 'node:fs/promises'
import { dirname, resolve, join } from 'node:path'
import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'

export async function downloadCompatibilityArtifact(runId, architecture, directory, dependencies = {}) {
  if (!/^[1-9][0-9]+$/.test(String(runId)) || !['amd64', 'arm64'].includes(architecture)) throw Error('INCUS_ARTIFACT_REQUEST_INVALID')
  const target = resolve(directory)
  await mkdir(dirname(target), { recursive: true })
  const execute = dependencies.execute || ((args) => execFileSync('gh', args, { stdio: 'pipe', timeout: 60000, maxBuffer: 1048576, windowsHide: true }))
  const pause = dependencies.pause || ((milliseconds) => new Promise(resolve => setTimeout(resolve, milliseconds)))
  for (let attempt = 0; attempt < 3; attempt++) {
    const stage = await mkdtemp(join(dirname(target), '.incus-artifact-'))
    try {
      try { await execute(['run', 'download', String(runId), '--name', 'incudal-incusd-sysinfo-' + architecture, '--dir', stage]) }
      catch (error) {
        // gh can include its temporary signed Azure URL and authentication
        // query in an exception. Classify locally; never print/rethrow it.
        const detail = String(error?.stderr || error?.message || '')
        if (attempt < 2 && /HTTP (?:5[0-9]{2}|429)|ECONNRESET|ETIMEDOUT|EAI_AGAIN|Egress is over the account limit|connection reset|temporary failure/i.test(detail)) {
          await pause((attempt + 1) * 1000)
          continue
        }
        throw Error('INCUS_ARTIFACT_DOWNLOAD_UNAVAILABLE')
      }
      const files = ['incusd', 'incusd-manifest.json']
      if ((await readdir(stage)).sort().join(',') !== files.sort().join(',')) throw Error('INCUS_ARTIFACT_CONTENT_INVALID')
      for (const name of files) {
        const info = await lstat(join(stage, name))
        if (!info.isFile() || info.isSymbolicLink() || info.size > (name === 'incusd' ? 100000000 : 65536)) throw Error('INCUS_ARTIFACT_CONTENT_INVALID')
      }
      const metadata = JSON.parse(await readFile(join(stage, 'incusd-manifest.json'), 'utf8'))
      const binary = await readFile(join(stage, 'incusd'))
      if (binary.length < 20 || metadata.size !== binary.length || metadata.sha256 !== createHash('sha256').update(binary).digest('hex') ||
        binary.readUInt16LE(18) !== (architecture === 'amd64' ? 62 : 183)) throw Error('INCUS_ARTIFACT_CONTENT_INVALID')
      await mkdir(target, { recursive: true })
      if ((await lstat(target)).isSymbolicLink()) throw Error('INCUS_ARTIFACT_TARGET_INVALID')
      for (const name of files) {
        const output = join(target, name)
        try {
          const info = await lstat(output)
          if (!info.isFile() || info.isSymbolicLink() || !(await readFile(output)).equals(await readFile(join(stage, name)))) throw Error('INCUS_ARTIFACT_TARGET_CONFLICT')
        } catch (error) {
          if (error?.code !== 'ENOENT') throw error
          await copyFile(join(stage, name), output, 1)
        }
      }
      return
    } finally { await rm(stage, { recursive: true, force: true }) }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 5) throw Error('INCUS_ARTIFACT_REQUEST_INVALID')
    await downloadCompatibilityArtifact(process.argv[2], process.argv[3], process.argv[4])
  } catch (error) {
    console.error(/^INCUS_ARTIFACT_[A-Z_]+$/.test(error?.message || '') ? error.message : 'INCUS_ARTIFACT_CHECK_FAILED')
    process.exitCode = 1
  }
}
