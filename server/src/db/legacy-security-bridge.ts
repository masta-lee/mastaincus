// Retained only for rollback to an authenticated pre-security release. Verify
// and seal through the current security implementation, presenting legacy
// configuration shapes after verification. No database rows are re-baselined.
import { prisma as secured, closePrismaDatabase, getDbPoolStats, normalizeLegacyNetworkModes } from './prisma.js'
import { SENSITIVE_CONFIG_KEYS } from './system-config.js'
import { encryptSensitiveData, decryptSensitiveDataStrict } from '../lib/security.js'
import { openNotificationConfig, sealNotificationConfig } from '../lib/notification-config.js'

function encode(model: string, args: any) {
  const output = { ...args }
  for (const key of ['data','create','update']) if (args?.[key]) {
    const data = { ...args[key] }
    if (model === 'systemConfig' && typeof data.value === 'string' && SENSITIVE_CONFIG_KEYS.has(data.key || args.where?.key)) {
      // New retained db helpers already encrypt secrets. Preserve only a valid
      // authenticated envelope, avoiding a second layer on rollback writes.
      const sealed=/^[a-f0-9]{32}:[a-f0-9]{32}:/i.test(data.value)
      if(sealed&&decryptSensitiveDataStrict(data.value)===null)throw Error('SYSTEM_SECRET_AUTHENTICATION_INVALID')
      data.value = data.value && !sealed ? encryptSensitiveData(data.value) : data.value
    }
    if (['notificationChannel','lotteryNotificationConfig'].includes(model) && data.config) {
      const config = typeof data.config === 'string' ? JSON.parse(data.config) : data.config
      data.config = config.version === 1 && typeof config.sealed === 'string' ? (openNotificationConfig(config), config) : sealNotificationConfig(config)
    }
    output[key] = data
  }
  return output
}
function decode(model: string, value: any): any {
  if (!value) return value
  if (Array.isArray(value)) return value.map(row => decode(model,row))
  const row = { ...value }
  if (model === 'systemConfig' && SENSITIVE_CONFIG_KEYS.has(row.key) && row.value) {
    const text = decryptSensitiveDataStrict(row.value)
    if (text === null) throw Error('SYSTEM_SECRET_AUTHENTICATION_INVALID')
    row.value = text
  }
  if (['notificationChannel','lotteryNotificationConfig'].includes(model) && row.config) row.config = openNotificationConfig(row.config)
  if (model === 'lottery' && row.notificationConfig) row.notificationConfig = decode('lotteryNotificationConfig', row.notificationConfig)
  return row
}
function bridge(client: any): any {
  return new Proxy(client,{get(target,property){
    if (property === '$transaction') return (action:any,options:any) => {
      // The protected client rejects protected operations in an array before
      // they execute; unrelated lazy Prisma operations retain their semantics.
      if (Array.isArray(action)) return target.$transaction(action,options)
      return target.$transaction((transaction:any)=>action(bridge(transaction)),options)
    }
    const delegate=target[property]
    if (!['systemConfig','notificationChannel','lotteryNotificationConfig','lottery'].includes(String(property))) return typeof delegate==='function'?delegate.bind(target):delegate
    return new Proxy(delegate,{get(object,operation){
      const method=object[operation]
      if(typeof method!=='function')return method
      return async(args:any={})=>{
        const model=String(property)
        if(model==='systemConfig'&&args.data?.value!==undefined&&!args.data.key&&!args.where?.key){
          const existing=await object.findUnique({where:args.where,select:{key:true}})
          if(existing)args={...args,data:{...args.data,key:existing.key}}
        }
        const query=encode(model,args)
        if(model==='systemConfig'&&query.select?.value)query.select={...query.select,key:true}
        const value=decode(model,await method.call(object,query))
        const project=(row:any)=>args.select&&row?Object.fromEntries(Object.entries(row).filter(([key])=>args.select[key])):row
        return Array.isArray(value)?value.map(project):project(value)
      }
    }})
  }})
}
export const prisma=bridge(secured)
export { closePrismaDatabase, getDbPoolStats, normalizeLegacyNetworkModes }
export default prisma
