import { isIP } from 'node:net'

/** Use the proxy-validated request.ip only. IPv6 /64 rotation is one source. */
export function registrationSource(ip: string): { ip: string; source: string } {
  const raw = /^::ffff:/i.test(ip) && isIP(ip.slice(7)) === 4 ? ip.slice(7) : ip
  if (isIP(raw) === 4) return { ip: raw, source: raw }
  if (isIP(raw) !== 6 || raw.includes('%')) throw Error('REGISTRATION_SOURCE_INVALID')
  const normalized = new URL(`http://[${raw}]/`).hostname.slice(1, -1)
  const mapped = /^::ffff:([a-f0-9]{1,4}):([a-f0-9]{1,4})$/.exec(normalized)
  if (mapped) {
    const high = parseInt(mapped[1],16), low = parseInt(mapped[2],16)
    const ipv4 = `${high>>>8}.${high&255}.${low>>>8}.${low&255}`
    return {ip:ipv4,source:ipv4}
  }
  const [left, right = ''] = normalized.split('::')
  const prefix = left ? left.split(':') : [], suffix = right ? right.split(':') : []
  const parts = normalized.includes('::') ? [...prefix, ...Array(8 - prefix.length - suffix.length).fill('0'), ...suffix] : prefix
  const network = parts.slice(0, 4).map(p => parseInt(p, 16).toString(16)).join(':') + '::'
  return { ip: normalized, source: new URL(`http://[${network}]/`).hostname.slice(1,-1) + '/64' }
}
