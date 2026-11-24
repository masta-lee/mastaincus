import { readFile } from 'node:fs/promises'
import { connectOnboardingSsh, gatewayConfigured, sshExec } from './onboarding-ssh.js'
import type { HostSecurityTarget } from './host-security-inspection.js'
import type { HostMaintenanceIntent } from '../lib/host-maintenance-plan.js'

export type MaintenanceOperation = Pick<HostMaintenanceIntent,'requestId'|'identityHash'|'bootId'|'prepareHash'|'recipe'|'architecture'> &
  {action:'prepare'|'status'|'reboot'|'rollback'|'restore-customers';customers?:HostMaintenanceIntent['customers'];deadline?:string}
export type MaintenanceReceipt = {nodeId:string;requestId:string;identityHash:string;prepareHash:string;originalBootId:string;
  bootId:string;architecture:string;recipe:string;phase:'absent'|'prepared'|'preparing'|'reboot-intent'|'customers-restored'|'rolled-back'}
export function maintenanceWireExpiry(operation:MaintenanceOperation,now=Date.now()):number {
  const expiresAt=now+59000
  if(!['prepare','reboot'].includes(operation.action))return expiresAt
  const deadline=Date.parse(operation.deadline||'')
  if(!Number.isFinite(deadline)||deadline<=now)throw Error('HARDENING_REQUEST_EXPIRED')
  return Math.min(expiresAt,deadline)
}
/** Select the wire protocol explicitly: callers may hold a larger durable
 * intent, but neither customer baselines nor database phases leave the server. */
export function maintenanceWireOperation(operation:MaintenanceOperation,nodeId:string,expiresAt:number) {
  return {action:operation.action,nodeId,requestId:operation.requestId,identityHash:operation.identityHash,
    bootId:operation.bootId,prepareHash:operation.prepareHash,recipe:operation.recipe,
    architecture:operation.architecture,expiresAt,customers:(operation.customers||[]).map(customer=>({
      name:customer.incusId,uuid:customer.uuid,attempt:customer.attempt,state:customer.state,autostart:customer.boot?.autostart??null}))}
}
export async function hostMaintenanceGatewayExchange(target:HostSecurityTarget,wire:Record<string,unknown>):Promise<unknown> {
  const node=target.onboardingNode
  if(!gatewayConfigured()||!node?.managementIp||!node.nodePublicKey||!node.sshFingerprint||target.managementSshHost!==node.managementIp||
    target.managementSshPort!==node.sshPort||target.managementSshUser!=='root'||wire.nodeId!==node.id)throw Error('HARDENING_IDENTITY_MISSING')
  const input=JSON.stringify({managementIp:node.managementIp,sshPort:node.sshPort,sshFingerprint:node.sshFingerprint,nodePublicKey:node.nodePublicKey,
    operation:wire})
  if(Buffer.byteLength(input,'utf8')>8192)throw Error('HARDENING_REMOTE_RESULT_UNKNOWN')
  const key=await readFile(process.env.ONBOARDING_GATEWAY_KEY_PATH!)
  const client=await connectOnboardingSsh({host:process.env.ONBOARDING_GATEWAY_HOST!,port:Number(process.env.ONBOARDING_GATEWAY_PORT||22),privateKey:key},
    async fingerprint=>fingerprint===process.env.ONBOARDING_GATEWAY_FINGERPRINT)
  try{
    const reply=await sshExec(client,`security-maintenance ${node.id}`,input,60000,8192)
    try{return JSON.parse(reply) as unknown}catch{throw Error('HARDENING_REMOTE_RESULT_UNKNOWN')}
  }finally{client.destroy()}
}
export async function hostMaintenanceCommand(target:HostSecurityTarget,operation:MaintenanceOperation):Promise<MaintenanceReceipt> {
    const node=target.onboardingNode
    if(!node)throw Error('HARDENING_IDENTITY_MISSING')
    const receipt=await hostMaintenanceGatewayExchange(target,maintenanceWireOperation(operation,node.id,maintenanceWireExpiry(operation))) as MaintenanceReceipt
    if(!receipt||Object.keys(receipt).sort().join(',')!=='architecture,bootId,identityHash,nodeId,originalBootId,phase,prepareHash,recipe,requestId'||
      receipt.nodeId!==node.id||receipt.requestId!==operation.requestId||receipt.identityHash!==operation.identityHash||
      receipt.originalBootId!==operation.bootId||receipt.architecture!==operation.architecture||receipt.recipe!==operation.recipe||
      !/^[a-f0-9]{64}$/.test(receipt.prepareHash)||!/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(receipt.bootId)||
      !['absent','prepared','preparing','reboot-intent','customers-restored','rolled-back'].includes(receipt.phase)||
      receipt.phase==='absent'&&(operation.action!=='status'||operation.prepareHash!=='0'.repeat(64)||receipt.prepareHash!=='0'.repeat(64))||
      operation.action!=='prepare'&&!(operation.action==='status'&&operation.prepareHash==='0'.repeat(64))&&receipt.prepareHash!==operation.prepareHash)throw Error('HARDENING_REMOTE_RESULT_UNKNOWN')
    return receipt
}
