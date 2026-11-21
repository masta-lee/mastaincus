import { decryptSensitiveDataStrict, encryptSensitiveData } from './security.js'

export interface RechargeProviderConfigSnapshot {
  type: string
  config: Record<string, unknown>
  capturedAt: string
}

export function buildRechargeProviderConfigSnapshot(
  type: string,
  config: Record<string, unknown>
): string {
  return encryptSensitiveData(JSON.stringify({
    type,
    config,
    capturedAt: new Date().toISOString()
  }))
}

export function parseRechargeProviderConfigSnapshot(
  value: unknown
): RechargeProviderConfigSnapshot | null {
  if (typeof value !== 'string' || !value.trim()) {
    return null
  }

  try {
    const decrypted = decryptSensitiveDataStrict(value)
    if (!decrypted) {
      return null
    }

    const parsed = JSON.parse(decrypted) as RechargeProviderConfigSnapshot
    if (
      !parsed ||
      typeof parsed !== 'object' ||
      typeof parsed.type !== 'string' ||
      !parsed.config ||
      typeof parsed.config !== 'object' ||
      Array.isArray(parsed.config)
    ) {
      return null
    }

    return parsed
  } catch {
    return null
  }
}

export function resolveRechargeProviderConfigSnapshot(
  providerType: string,
  currentConfig: Record<string, unknown>,
  snapshotValue: unknown
): { config: Record<string, unknown>; source: 'snapshot' | 'provider' } {
  // Missing snapshots belong to pre-snapshot orders. An existing but invalid
  // snapshot is a trust failure, never authority to switch merchant/key.
  if (snapshotValue === null || snapshotValue === undefined || snapshotValue === '') return { config: currentConfig, source: 'provider' }
  const snapshot = parseRechargeProviderConfigSnapshot(snapshotValue)
  if (snapshot && snapshot.type === providerType) {
    return { config: snapshot.config, source: 'snapshot' }
  }
  throw new Error('RECHARGE_PROVIDER_SNAPSHOT_INVALID')
}
