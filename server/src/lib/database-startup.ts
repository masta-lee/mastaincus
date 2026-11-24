/** Read-only admission before any startup migration, financial work or worker. */
export async function waitForStartupDatabase(
  query: () => Promise<unknown>,
  isStopping: () => boolean,
  options: {
    timeoutMs?: number
    now?: () => number
    sleep?: (milliseconds: number) => Promise<void>
  } = {},
): Promise<boolean> {
  const now = options.now ?? (() => performance.now())
  const sleep = options.sleep ?? (milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)))
  const deadline = now() + (options.timeoutMs ?? 120_000)
  let delay = 250
  while (!isStopping()) {
    try {
      // The original pool enforces its connection and query deadlines. Wait
      // for the attempt to settle; never leave a raced query running behind.
      await query()
      return !isStopping()
    } catch (error) {
      if (isStopping()) return false
      if (!isTransientInitialConnectionError(error) || now() >= deadline) throw error
      const until = Math.min(deadline, now() + delay)
      while (!isStopping() && now() < until) await sleep(Math.min(100, until - now()))
      if (isStopping()) return false
      if (now() >= deadline) throw error
      delay = Math.min(delay * 2, 2_000)
    }
  }
  return false
}

function isTransientInitialConnectionError(error: unknown): boolean {
  if (!(error instanceof Error)) return false
  const code = 'code' in error ? error.code : undefined
  // Authentication, permission and integrity failures are never retries.
  if (typeof code === 'string') return ['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'EPIPE', '57P03', '08001', '08006'].includes(code)
  return ['timeout exceeded when trying to connect', 'Connection terminated due to connection timeout'].includes(error.message)
}
