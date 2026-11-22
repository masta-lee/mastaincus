import { spawn } from 'node:child_process'
import { sanitizeTokensInString } from './log-sanitizer.js'
import { StringDecoder } from 'node:string_decoder'

// Pipe chunks are arbitrary and can split a credential or UTF-8 sequence.
// Sanitize complete bounded lines, discarding the whole oversized line.
function commandLog(emit: (text: string) => void) {
  const decoder = new StringDecoder('utf8')
  let pending = '', discarded = false
  const consume = (text: string) => {
    const lines = text.split('\n')
    for (let i = 0; i < lines.length; i++) {
      if (!discarded) {
        pending += lines[i]
        if (pending.length > 64 * 1024) { pending = ''; discarded = true }
      }
      if (i < lines.length - 1) {
        emit(discarded ? '[UPDATE_LOG_LINE_TOO_LARGE]\n' : sanitizeTokensInString(pending) + '\n')
        pending = ''; discarded = false
      }
    }
  }
  return {
    write: (data: Buffer) => consume(decoder.write(data)),
    end: () => { consume(decoder.end()); if (discarded) emit('[UPDATE_LOG_LINE_TOO_LARGE]\n'); else if (pending) emit(sanitizeTokensInString(pending)); pending = '' }
  }
}

export class SystemUpdateCommandNotStopped extends Error {}
export async function runSystemUpdateCommand(command: string, args: string[], options: {
  cwd: string; env: NodeJS.ProcessEnv; timeoutMs?: number; capture?: boolean
  label?: string
  stdout?: (data: Buffer) => void; stderr?: (data: Buffer) => void
}): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const description = sanitizeTokensInString(options.label || command)
    const grouped = process.platform !== 'win32'
    const child = spawn(command, args, { cwd: options.cwd, env: options.env, detached: grouped, stdio: ['ignore', 'pipe', 'pipe'] })
    let timedOut = false, outputLimitExceeded = false, output = '', outputBytes = 0, errors = ''
    const captureDecoder = new StringDecoder('utf8')
    let deadline: ReturnType<typeof setTimeout> | undefined, force: ReturnType<typeof setTimeout> | undefined
    const signal = (value: NodeJS.Signals) => {
      try { if (grouped && child.pid) process.kill(-child.pid, value); else child.kill(value) }
      catch { /* Exit can race signal delivery; verify quiescence below. */ }
    }
    const groupExists = () => {
      if (!grouped || !child.pid) return false
      try { process.kill(-child.pid, 0); return true }
      catch (error) { return (error as NodeJS.ErrnoException).code !== 'ESRCH' }
    }
    if (options.timeoutMs) deadline = setTimeout(() => {
      timedOut = true; signal('SIGTERM'); force = setTimeout(() => signal('SIGKILL'), 2000)
    }, options.timeoutMs)
    const stdout = commandLog(text => options.stdout?.(Buffer.from(text)))
    const stderr = commandLog(text => { if (options.capture) errors = (errors + text).slice(-4*1024*1024); options.stderr?.(Buffer.from(text)) })
    child.stdout.on('data', (data: Buffer) => {
      if (options.capture && !outputLimitExceeded) {
        outputBytes += data.length
        if (outputBytes > 4 * 1024 * 1024) { outputLimitExceeded = true; output = ''; signal('SIGKILL') }
        else output += captureDecoder.write(data)
      }
      stdout.write(data)
    })
    child.stderr.on('data', (data: Buffer) => stderr.write(data))
    child.once('error', error => { clearTimeout(deadline); clearTimeout(force); reject(error) })
    child.once('close', async code => {
      stdout.end(); stderr.end()
      if (options.capture && !outputLimitExceeded) output += captureDecoder.end()
      clearTimeout(deadline); clearTimeout(force)
      const leftover = groupExists()
      if (timedOut || leftover) signal('SIGKILL')
      const stopDeadline = Date.now() + 5000
      while (groupExists() && Date.now() < stopDeadline) await new Promise(done => setTimeout(done, 50))
      if (groupExists()) { reject(new SystemUpdateCommandNotStopped('Update command children have not stopped; automatic rollback is unsafe')); return }
      if (outputLimitExceeded) reject(new Error(`Command output exceeds capture limit: ${description}`))
      else if (timedOut) reject(new Error(`Command timed out: ${description}`))
      else if (leftover) reject(new Error(`Command exited with unfinished child processes: ${command}`))
      else if (code !== 0) reject(new Error(`Command failed with exit code ${code}: ${description}${errors ? '\n' + errors : ''}`))
      else resolve(output)
    })
  })
}
