import type { FastifyReply, FastifyRequest } from 'fastify'

const counts = new Map<number,number>()
const uploadReservations=new WeakMap<FastifyRequest,{release:()=>void;timer:ReturnType<typeof setTimeout>;processing:boolean}>()
let activeUploads=0,activeStorageTests=0
export async function ticketUploadBudget(request: FastifyRequest,reply: FastifyReply) {
  const multipart=String(request.headers['content-type']||'').startsWith('multipart/form-data')
  if(!multipart)return
  const id=request.user.id
  if(activeUploads>=1 || counts.has(id))return reply.code(429).send({code:'UPLOAD_BUSY',error:'图片上传正在处理，请稍后重试'})
  activeUploads++;counts.set(id,1)
  let released=false
  const release=()=>{if(released)return;released=true;activeUploads--;counts.delete(id)}
  const timeout=setTimeout(()=>{request.raw.destroy(new Error('UPLOAD_DEADLINE_EXCEEDED'));if(!reservation.processing)release()},120000)
  const reservation={release,timer:timeout,processing:false}
  uploadReservations.set(request,reservation)
  timeout.unref()
  const complete=()=>{if(!reservation.processing){clearTimeout(timeout);release()}}
  reply.raw.once('finish',complete);reply.raw.once('close',complete);request.raw.once('aborted',complete)
}
export function beginTicketUploadProcessing(request:FastifyRequest){const reservation=uploadReservations.get(request);if(reservation)reservation.processing=true}
export function completeTicketUploadProcessing(request:FastifyRequest){const reservation=uploadReservations.get(request);if(reservation){clearTimeout(reservation.timer);reservation.release();uploadReservations.delete(request)}}
export async function runStorageTest<T>(action:()=>Promise<T>):Promise<T>{
  if(activeStorageTests>=4)throw Object.assign(new Error('存储连接测试繁忙，请稍后重试'),{statusCode:429})
  activeStorageTests++
  try{return await action()}finally{activeStorageTests--}
}
