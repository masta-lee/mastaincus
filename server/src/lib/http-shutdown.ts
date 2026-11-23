import type { FastifyInstance } from 'fastify'

/** A request finishing after server.close() can leave another idle keepalive
 * socket. Reap only idle HTTP connections while active handlers/work drain. */
export async function closeApplicationHttp(fastify: FastifyInstance): Promise<void> {
  const closeIdle = () => fastify.server.closeIdleConnections?.()
  const timer = setInterval(closeIdle, 100)
  timer.unref()
  try { await fastify.close() }
  finally { clearInterval(timer) }
}
