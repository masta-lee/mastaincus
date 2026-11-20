import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, writeFile, rm, readdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
const directory = await mkdtemp(join(tmpdir(), 'system-image-cache-'))
process.env.SYSTEM_IMAGE_CACHE_DIR = directory
const { cacheSystemImage, imagePartPath, cachedSystemImagePresent } = await import('../src/services/system-image-cache.js')
const metadata = Buffer.from('isolated Incus metadata fixture'), root = Buffer.from('isolated rootfs fixture'), vm = Buffer.from('isolated VM rootfs fixture')
const sha = (data: Buffer) => createHash('sha256').update(data).digest('hex')
const parts = { meta: { path: 'images/debian/bookworm/amd64/cloud/20261113_05:24/incus.tar.xz', size: metadata.length, sha256: sha(metadata), ftype: 'incus.tar.xz',
  combined_rootxz_sha256: sha(Buffer.concat([metadata, root])), 'combined_disk-kvm-img_sha256': sha(Buffer.concat([metadata, vm])) },
  root: { path: 'images/debian/bookworm/amd64/cloud/20261113_05:24/rootfs.tar.xz', size: root.length, sha256: sha(root), ftype: 'root.tar.xz' },
  vm: { path: 'images/debian/bookworm/amd64/cloud/20261113_05:24/disk.qcow2', size: vm.length, sha256: sha(vm), ftype: 'disk-kvm.img' } }
const catalog = { products: { test: { arch: 'amd64', aliases: 'debian/12/cloud', versions: { '20261113_00:00': { items: parts } } } } }
let catalogReads = 0, metadataReads = 0, rootReads = 0, vmReads = 0
let catalogFaults = 2
const original = globalThis.fetch
globalThis.fetch = (async (input: unknown) => {
  const url = String(input)
  if (url.endsWith('/streams/v1/images.json')) {
    catalogReads++
    if (catalogFaults-- > 0) {
      if (catalogFaults === 1) throw new TypeError('fetch failed', { cause: new AggregateError([
        Object.assign(Error('timeout'), { code: 'ETIMEDOUT' }), Object.assign(Error('IPv6 unavailable'), { code: 'ENETUNREACH' })
      ], 'all addresses unavailable') })
      return new Response('temporarily unavailable', { status: 503 })
    }
    return new Response(JSON.stringify(catalog))
  }
  if (url.endsWith(parts.meta.path)) { metadataReads++; return new Response(metadata) }
  if (url.endsWith(parts.root.path)) { rootReads++; return new Response(root) }
  if (url.endsWith(parts.vm.path)) { vmReads++; return new Response(vm) }
  throw Error('unexpected network target')
}) as typeof fetch
try {
  for (const alias of ['images:debian/11/cloud', 'images:debian/11/cloud/arm64', 'images:ubuntu/25.10/cloud', 'images:ubuntu/questing/cloud/arm64']) {
    await assert.rejects(cacheSystemImage(alias, 'x86_64', 'container'), /SYSTEM_IMAGE_RETIRED/)
    assert.equal(await cachedSystemImagePresent(alias, 'x86_64', 'container'), false)
  }
  assert.equal(catalogReads, 0, 'retired images do not download or reuse old cache receipts')
  const first = await Promise.all(Array.from({ length: 4 }, () => cacheSystemImage('images:debian/12/cloud', 'x86_64', 'container')))
  assert.ok(first.every(image => image.fingerprint === parts.meta.combined_rootxz_sha256))
  assert.deepEqual([catalogReads, metadataReads, rootReads], [3, 1, 1], 'temporary dual-stack connection and HTTP503 recover under one concurrent request')
  await cacheSystemImage('images:debian/12/cloud', 'x86_64', 'vm')
  assert.equal(metadataReads, 1, 'container and VM share the same immutable metadata file')
  assert.equal(vmReads, 1)
  const localFile = await imagePartPath(first[0].parts[1])
  const before = await readFile(localFile)
  // A new process/code runtime uses only the durable receipt and files.
  const program = `import {cacheSystemImage} from './src/services/system-image-cache.ts'; globalThis.fetch=async()=>{throw Error('repeat download forbidden')};
    const image=await cacheSystemImage('images:debian/12/cloud','x86_64','container'); if(image.fingerprint!=='${first[0].fingerprint}')throw Error('pin changed');`
  await promisify(execFile)(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', program], { cwd: process.cwd(), env: process.env, timeout: 30000 })
  assert.equal(await cachedSystemImagePresent('images:debian/12/cloud', 'x86_64', 'container'), true)
  await writeFile(localFile, Buffer.from('corrupted'))
  await cacheSystemImage('images:debian/12/cloud', 'x86_64', 'container')
  assert.deepEqual(await readFile(localFile), before)
  assert.deepEqual([catalogReads, metadataReads, rootReads], [3, 1, 2], 'corruption repairs only original rootfs part and keeps upstream pin')
  await rm(localFile)
  await cacheSystemImage('images:debian/12/cloud', 'x86_64', 'container')
  assert.equal(rootReads, 3, 'missing file is recovered under the same receipt')
  await assert.rejects(cacheSystemImage('images:debian/12/cloud/arm64', 'x86_64', 'container'), /ARCHITECTURE_MISMATCH/)
  assert.equal(catalogReads, 3, 'invalid request does not fetch a new catalog')
  const goodFetch = globalThis.fetch
  for (const failure of ['body', 'tls', 'hash', '404', 'exhausted', 'cancel'] as const) {
    await rm(localFile)
    let attempts = 0
    const controller = new AbortController()
    globalThis.fetch = (async () => {
      attempts++
      if (failure === 'body' && attempts === 1) return new Response(new ReadableStream({
        start(stream) { stream.enqueue(root.subarray(0, 3)); stream.error(Object.assign(Error('interrupted'), { code: 'ECONNRESET' })) }
      }))
      if (failure === 'tls') throw new TypeError('fetch failed', { cause: Object.assign(Error('certificate'), { code: 'CERT_HAS_EXPIRED' }) })
      if (failure === 'hash') return new Response(Buffer.alloc(root.length))
      if (failure === '404') return new Response('missing', { status: 404 })
      if (failure === 'exhausted') return new Response('unavailable', { status: 503 })
      if (failure === 'cancel') { controller.abort(); throw Object.assign(Error('interrupted'), { code: 'ECONNRESET' }) }
      return new Response(root)
    }) as typeof fetch
    const result = cacheSystemImage('images:debian/12/cloud', 'x86_64', 'container', controller.signal)
    if (failure === 'body') {
      await result; assert.equal(attempts, 2); assert.deepEqual(await readFile(localFile), before)
    } else {
      await assert.rejects(result)
      assert.equal(attempts, failure === 'exhausted' ? 3 : 1, 'only temporary transport failures are retried')
      await assert.rejects(readFile(localFile), { code: 'ENOENT' })
    }
    assert.equal((await readdir(directory)).some(name => name.endsWith('.download')), false, 'failed transfers leave no partial image')
    globalThis.fetch = goodFetch
    if (failure !== 'body') await cacheSystemImage('images:debian/12/cloud', 'x86_64', 'container')
  }
  const archiveCheck = await readFile('../scripts/check-release-runtime-files.py', 'utf8')
  assert.ok(archiveCheck.includes("Persistent image library must not be bundled with program updates"))
  const installed = await readFile('../scripts/install-platform-backup.sh', 'utf8')
  assert.ok(installed.includes('install -d -o incudal -g incudal -m 0750 /var/lib/incudal-images') &&
    installed.includes('ReadWritePaths=/var/lib/incudal-images'), 'old worker install hook prepares the persistent library outside releases')
  console.log('PASS persistent image library: single/concurrent download, shared parts, fresh process offline reuse, original-pin repair and missing-file recovery; separate from release directories')
} finally { globalThis.fetch = original; await rm(directory, { recursive: true, force: true }) }
