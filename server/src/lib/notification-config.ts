import { encryptSensitiveData, decryptSensitiveDataStrict } from './security.js'

export function sealNotificationConfig(value: Record<string, unknown>): Record<string, string | number> {
  return { version: 1, sealed: encryptSensitiveData(JSON.stringify(value)) }
}
export function openNotificationConfig(input: unknown): Record<string, unknown> {
  // This function accepts persisted envelopes only; callers holding a decoded
  // snapshot must keep it local and never feed it back through this boundary.
  const envelope = typeof input === 'string' ? JSON.parse(input) : input as Record<string, unknown>
  if (!envelope || envelope.version !== 1 || typeof envelope.sealed !== 'string') throw new Error('NOTIFICATION_CONFIG_AUTHENTICATION_REQUIRED')
  const decrypted = decryptSensitiveDataStrict(envelope.sealed)
  if (!decrypted) throw new Error('NOTIFICATION_CONFIG_AUTHENTICATION_INVALID')
  const value = JSON.parse(decrypted)
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('NOTIFICATION_CONFIG_INVALID')
  return value
}
