import { Transform, type Readable } from 'node:stream'

export async function readBoundedResponse(body: AsyncIterable<Uint8Array> & { destroy?: (error?: Error) => unknown }, limit: number): Promise<string> {
  const chunks: Buffer[] = []; let bytes=0
  try {
    for await(const chunk of body){const buffer=Buffer.from(chunk);bytes+=buffer.length;if(bytes>limit)throw new Error('UPSTREAM_RESPONSE_TOO_LARGE');chunks.push(buffer)}
    return Buffer.concat(chunks).toString('utf8')
  } catch(error){body.destroy?.(error as Error);throw error}
}
export function limitReadable(stream: Readable, limit=32*1024**3): Readable {
  let bytes=0
  const bounded=new Transform({transform(chunk,_encoding,callback){bytes+=Buffer.byteLength(chunk);if(bytes>limit)callback(new Error('STORAGE_STREAM_TOO_LARGE'));else callback(null,chunk)}})
  stream.once('error',error=>bounded.destroy(error));bounded.once('close',()=>stream.destroy())
  return stream.pipe(bounded)
}
