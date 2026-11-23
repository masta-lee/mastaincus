// Keep queue claims and their detached executions visible to shutdown. An
// in-flight claim can register its work while drain is already waiting.
export class WorkerActivity {
  private readonly active = new Set<Promise<unknown>>()

  run<T>(work: () => Promise<T>): Promise<T> {
    let promise: Promise<T>
    try { promise = work() } catch (error) { promise = Promise.reject(error) }
    this.active.add(promise)
    void promise.then(() => this.active.delete(promise), () => this.active.delete(promise))
    return promise
  }

  async drain(): Promise<void> {
    while (this.active.size) await Promise.allSettled([...this.active])
  }
}
