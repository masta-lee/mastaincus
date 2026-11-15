import { isIP } from 'node:net'
import { sanitizeTokensInString } from './log-sanitizer.js'

const internalKeys = /^(?:host|hostName|oldHostName|newHostName|hostId|hostIp|hostIpAddress|managementIp|managementHost|incusId|oci|ociAccount|ociAccountName|accountLabel|privateIp|internalIp|secret|token|password|rootPassword|sourceHost|targetHost|storageName)$/i
const internalKey = (key: string) => internalKeys.test(key.replace(/[_-]/g, ''))
function publicAddress(ip: string): boolean {
  if (isIP(ip) === 4) {
    const [a,b] = ip.split('.').map(Number)
    return !(a===0||a===10||a===127||a===169&&b===254||a===172&&b>=16&&b<=31||a===192&&b===168||a===100&&b>=64&&b<=127||a>=224)
  }
  return isIP(ip) === 6 && /^[23][a-f0-9]{0,3}:/i.test(ip)
}
export function customerNotificationData<T extends Record<string, unknown>>(input: T): T {
  const internal: string[] = []
  const collect = (value: unknown, sensitive = false): void => {
    if (typeof value === 'string' && sensitive && value.length > 2) internal.push(value)
    else if (Array.isArray(value)) value.forEach(item => collect(item, sensitive))
    else if (value && typeof value === 'object') for (const [key, item] of Object.entries(value)) collect(item, sensitive || internalKey(key))
  }
  collect(input)
  const clean = (value: unknown): unknown => {
    if (typeof value === 'string') {
      let text = sanitizeTokensInString(value)
      for (const word of internal) text = text.split(word).join('内部资源')
      text = text.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, ip => publicAddress(ip) ? ip : '[内部地址]')
      text = text.replace(/(?:[a-f0-9]{0,4}:){2,}[a-f0-9:]+(?:%[a-z0-9_-]+)?/gi, ip => isIP(ip.split('%')[0]) ? publicAddress(ip.split('%')[0]) ? ip : '[内部地址]' : ip)
      return text
    }
    if (Array.isArray(value)) return value.map(clean)
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).filter(([key])=>!internalKey(key)).map(([key,item])=>[key,clean(item)]))
    return value
  }
  const data = clean(input) as T
  // Operational exceptions contain commands, node names and raw provider data.
  for (const key of ['error','failReason'] as const) if (input[key]) (data as Record<string,unknown>)[key] = '操作暂未完成，请在面板查看状态或提交工单'
  for (const key of ['reason','deleteReason','suspendReason'] as const) {
    const value = input[key]
    if (typeof value === 'string' && /incus|OCI|UUID|\/var\/|\/opt\/|Traceback|Error:|HOST_|POOL_|https?:\/\/|\[内部地址\]|内部资源/i.test(String(data[key]))) {
      (data as Record<string,unknown>)[key] = '请在面板查看处理结果，或提交工单'
    }
  }
  return data
}

export function customerNotificationText(message: string): string {
  const text = message.replace(/(?:^|\n)\s*(?:节点|原节点|新节点|宿主(?:机)?|OCI\s*(?:账户|账号)|内网(?:IP|地址)|host(?:name)?|oci[_ -]?account)\s*[:：][^\n]*(?=\n|$)/gi, '').replace(/\n{3,}/g,'\n\n').trim()
  return customerNotificationData({ text }).text
}
