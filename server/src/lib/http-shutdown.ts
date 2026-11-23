import type { FastifyInstance } from 'fastify'

/** A request finishing after server.close() can leave another idle keepalive
 * socket. Reap only idle HTTP connections while active handlers/work drain. */
export async function closeApplicationHttp(fastify: FastifyInstance, drain?: () => Promise<void>): Promise<void> {
  const closeIdle = () => fastify.server.closeIdleConnections?.()
  const timer = setInterval(closeIdle, 100)
  timer.unref()
  try {
    if (drain) {
      // Fastify's internal preClose handler shares Avvio's short plugin
      // timeout. Stop new connections and drain long resource work before
      // entering that handler; its repeated worker stops are then settled.
      const httpClosed = new Promise<void>((resolve, reject) => {
        fastify.server.close(error => {
          if (error && (error as NodeJS.ErrnoException).code !== 'ERR_SERVER_NOT_RUNNING') reject(error)
          else resolve()
        })
      })
      void httpClosed.catch(() => {})
      let background: Promise<void>
      try { background = drain() } catch (error) { background = Promise.reject(error) }
      const results = await Promise.allSettled([httpClosed, background])
      const failed = results.find(result => result.status === 'rejected')
      if (failed?.status === 'rejected') throw failed.reason
    }
    await fastify.close()
  }
  finally { clearInterval(timer) }
}
