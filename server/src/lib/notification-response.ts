import { Readable } from 'node:stream'
import { readBoundedResponse } from './bounded-response.js'
import { sanitizeTokensInString } from './log-sanitizer.js'

export async function readNotificationBody(response: Response): Promise<string> {
  if (!response.body) return ''
  return await readBoundedResponse(Readable.fromWeb(response.body as any), 64 * 1024)
}

export async function readTelegramResponse(response: Response): Promise<{ ok: boolean; description?: string }> {
  const value = JSON.parse(await readNotificationBody(response))
  if (!value || typeof value !== 'object' || typeof value.ok !== 'boolean') throw new Error('NOTIFICATION_RESPONSE_INVALID')
  return { ok: value.ok, ...(typeof value.description === 'string' ? { description: sanitizeTokensInString(value.description).slice(0, 2000) } : {}) }
}
