import { createTask, type TaskFn, type TaskOptions, type ScheduledTask } from 'node-cron'
import { WorkerActivity } from '../workers/worker-activity.js'

const tasks = new Set<ScheduledTask>()
const intervals = new Set<ReturnType<typeof setInterval>>()
const activity = new WorkerActivity()
let stopping = false

export function schedule(expression: string, work: TaskFn, options?: TaskOptions): ScheduledTask {
  const task = createTask(expression, context => {
    if (stopping) return
    return activity.run(() => Promise.resolve(work(context)))
  }, options)
  tasks.add(task)
  if (!stopping) task.start()
  return task
}

// Also track work whose existing scheduler uses a timer or whose timeout only
// stops waiting. Nested work admitted by an already-running task must drain.
export function trackScheduledWork<T>(work: () => Promise<T>): Promise<T> {
  return activity.run(work)
}

/** Timers use the same admission and drain rules as cron jobs. */
export function scheduleInterval(work: () => Promise<unknown>, milliseconds: number, runImmediately = false): void {
  if (stopping) return
  const tick = () => {
    if (stopping) return
    void activity.run(work).catch(() => console.error('[Scheduler] Interval pass failed; the next scheduled pass will retry'))
  }
  const timer = setInterval(tick, milliseconds)
  intervals.add(timer)
  if (runImmediately) tick()
}

export async function stopManagedSchedules(): Promise<void> {
  stopping = true
  for (const timer of intervals) clearInterval(timer)
  intervals.clear()
  const results = await Promise.allSettled([...tasks].map(task => task.stop()))
  await activity.drain()
  const failed = results.find(result => result.status === 'rejected')
  if (failed?.status === 'rejected') throw failed.reason
}
