import { createTask, type TaskFn, type TaskOptions, type ScheduledTask } from 'node-cron'
import { WorkerActivity } from '../workers/worker-activity.js'

const tasks = new Set<ScheduledTask>()
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

export async function stopManagedSchedules(): Promise<void> {
  stopping = true
  const results = await Promise.allSettled([...tasks].map(task => task.stop()))
  await activity.drain()
  const failed = results.find(result => result.status === 'rejected')
  if (failed?.status === 'rejected') throw failed.reason
}
