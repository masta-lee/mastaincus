/** The recursive API groups contain operation objects, including terminal
 * entries retained by Incus. An unreadable group is never evidence of idleness. */
export function incusOperationsIdle(value:unknown):boolean {
  if(!value||typeof value!=='object'||Array.isArray(value))return false
  const prototype=Object.getPrototypeOf(value)
  if(prototype!==Object.prototype&&prototype!==null)return false
  return Object.values(value).every(group=>Array.isArray(group)&&group.every(operation=>
    operation&&typeof operation==='object'&&!Array.isArray(operation)&&
    ['Success','Failure','Cancelled'].includes(operation.status)))
}
