import { getPatcher } from 'webdav'
import { Readable } from 'node:stream'
import { safeFetch } from '../lib/outbound-security.js'
import { limitReadable, readBoundedResponse } from '../lib/bounded-response.js'

// WebDAV's SDK ignores axios-style maxContentLength/maxBodyLength. Override
// its documented fetch boundary, so limits apply before text/XML parsing and
// streaming uses Node backpressure instead of collecting a complete backup.
getPatcher().patch('fetch', async (...args: unknown[]) => {
  const url = String(args[0]), options = args[1] as RequestInit & { body?: any }
  const large = options.method === 'GET' || options.method === 'PUT'
  const deadline = AbortSignal.timeout(large ? 6 * 60 * 60 * 1000 : 60000)
  const init: RequestInit & { duplex?: string } = { ...options, redirect: 'manual', signal: options.signal ? AbortSignal.any([options.signal, deadline]) : deadline }
  if (options.body instanceof Readable) { init.body = limitReadable(options.body) as any; init.duplex = 'half' }
  let response: Response
  try { response = await safeFetch(url, init, 'WebDAV') }
  catch(error) { if(options.body instanceof Readable)options.body.destroy();throw error }
  if(options.body instanceof Readable) options.body.destroy()
  if (response.status >= 300 && response.status < 400) { await response.body?.cancel(); throw new Error('STORAGE_REDIRECT_REFUSED') }
  const body = response.body ? limitReadable(Readable.fromWeb(response.body as any), options.method === 'GET' ? 32 * 1024 ** 3 : 2 * 1024 ** 2) : Readable.from([])
  return new Proxy(response, { get(target, property) {
    if (property === 'body') return body
    if (property === 'text') return () => readBoundedResponse(body, 2 * 1024 ** 2)
    const value = Reflect.get(target, property, target)
    return typeof value === 'function' ? value.bind(target) : value
  } })
})
