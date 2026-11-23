import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile, readdir, mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { createHash } from 'node:crypto'
import { downloadCompatibilityArtifact } from './download-ci-artifact.mjs'

const root = await mkdtemp(join(tmpdir(), 'incus-artifact-download-'))
try {
  let attempts = 0
  const binary = Buffer.alloc(32)
  binary.writeUInt16LE(62, 18)
  const execute = async (args) => {
    const stage = args.at(-1)
    await writeFile(join(stage, 'incusd'), binary)
    await writeFile(join(stage, 'incusd-manifest.json'), JSON.stringify({ size: binary.length, sha256: createHash('sha256').update(binary).digest('hex') }))
  }
  // Real staging, parsing, hash and publication; injected transport failures
  // model a 503 without emitting its secret temporary URL.
  await downloadCompatibilityArtifact('12345', 'amd64', join(root, 'output'), {
    execute: args => { attempts++; if (attempts < 3) throw { stderr: 'HTTP 503 Egress is over the account limit https://private/?sig=secret' }; return execute(args) },
    pause: async () => {}
  })
  assert.equal(attempts, 3)
  assert.deepEqual((await readdir(join(root, 'output'))).sort(), ['incusd', 'incusd-manifest.json'])
  assert.equal((await readdir(root)).filter(name => name.startsWith('.incus-artifact')).length, 0)
  await assert.rejects(downloadCompatibilityArtifact('12345', 'amd64', join(root, 'denied'), {
    execute: () => { throw { stderr: 'HTTP 403 https://private/?sig=secret' } }, pause: async () => {}
  }), error => error.message === 'INCUS_ARTIFACT_DOWNLOAD_UNAVAILABLE' && !String(error).includes('secret'))
  await assert.rejects(downloadCompatibilityArtifact('bad', 'amd64', join(root, 'bad')))
  await mkdir(join(root, 'conflict'))
  await writeFile(join(root, 'conflict/incusd'), 'wrong bytes')
  await assert.rejects(downloadCompatibilityArtifact('12345', 'amd64', join(root, 'conflict'), { execute, pause: async () => {} }), /TARGET_CONFLICT/)
  console.log('PASS CI artifact download: bounded transient retries, secret-free errors, strict complete content and conflict rejection')
} finally { await rm(root, { recursive: true, force: true }) }
