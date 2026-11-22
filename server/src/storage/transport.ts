import { Agent as HttpAgent } from 'node:http'
import { Agent as HttpsAgent } from 'node:https'
import type { LookupFunction } from 'node:net'
import { isIP } from 'node:net'
import { revalidatingLookup, isIpPrivateOrReserved } from '../lib/outbound-security.js'

const lookup: LookupFunction = (host, options, callback) => revalidatingLookup(host, options, callback)
// Node skips lookup for literal IPs. Check createConnection too so a redirect
// cannot bypass the DNS hook by changing a public hostname to a private IP.
function publicSocketHost(host: unknown) {
  const text=String(host||'').replace(/^\[|\]$/g,'')
  if (!text || isIP(text) && isIpPrivateOrReserved(text)) throw new Error('STORAGE_PRIVATE_CONNECTION_REFUSED')
}
class StorageHttpAgent extends HttpAgent {
  createConnection(options: any, callback: any): any { publicSocketHost(options.host); return super.createConnection(options,callback) }
}
class StorageHttpsAgent extends HttpsAgent {
  createConnection(options: any, callback: any): any { publicSocketHost(options.host); return super.createConnection(options,callback) }
}
export const storageHttpAgent = new StorageHttpAgent({lookup,keepAlive:true,maxSockets:8,maxTotalSockets:16})
export const storageHttpsAgent = new StorageHttpsAgent({lookup,keepAlive:true,maxSockets:8,maxTotalSockets:16,rejectUnauthorized:true})
export function rejectStorageControlCharacters(value: unknown) {
  if (typeof value === 'string' && /[\x00-\x1f\x7f]/.test(value)) throw new Error('STORAGE_CONTROL_CHARACTER_REFUSED')
}
