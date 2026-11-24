import { createApp } from 'vue'
import { createPinia } from 'pinia'
import axios from 'axios'
const pending = [], refreshes = []
const token = (id = 1, sid = 'refresh-session', role = 'user', expires = 7 * 86400, marker = '') =>
  'fixture.' + btoa(JSON.stringify({ id, sid, role, exp: Math.floor(Date.now() / 1000) + expires, marker })) + '.fixture'
const identity = () => {
  try { const { id, sid, role } = JSON.parse(atob(localStorage.getItem('token').split('.')[1])); return JSON.stringify({ id, sid, role }) } catch { return null }
}
localStorage.removeItem('token')
axios.defaults.adapter = config => new Promise((resolve, reject) => pending.push({ config,
  resolve: data => resolve({ data, status: 200, statusText: 'OK', headers: {}, config }),
  reject: status => reject({ config, response: { status, data: { error: 'Controlled unauthorized', code: 'UNAUTHORIZED' } } }) }))
window.fetch = (url, options) => new Promise((resolve, reject) => {
  const row = { url, options, identity: identity(), settled: false,
    resolve: (value, status = 200) => { row.settled = true; resolve(new Response(JSON.stringify(value), { status })) },
    reject: error => { row.settled = true; reject(error) } }
  refreshes.push(row); options?.signal?.addEventListener('abort', () => row.reject(new DOMException('Aborted', 'AbortError')))
})
const { default: userApi } = await import('@/api')
const { default: adminApi } = await import('@/api/admin')
const { useAuthStore } = await import('@/stores/auth')
createApp({ setup() {
  const auth = useAuthStore()
  const session = (id = 1, sid = 'refresh-session', role = 'user', expires = 7 * 86400, marker = '') => {
    localStorage.setItem('token', token(id, sid, role, expires, marker)); auth.syncToken()
    auth.user = { id, username: 'fixture-account', email: 'fixture@example.test', role }; auth.quota = { hostLimit: id }
  }
  session()
  window.refreshHarness = { auth, userApi, adminApi, pending, refreshes, session, token, results: [], errors: [],
    start(client = 'user') {
      const requests = pending.length + refreshes.length, previousRefreshes = refreshes.length
      const sessionIdentity = identity(), sourceToken = localStorage.getItem('token')
      let proactiveRefresh = false
      try { proactiveRefresh = JSON.parse(atob(sourceToken.split('.')[1])).exp - Math.floor(Date.now() / 1000) < 300 } catch {}
      let settled = false
      void (client === 'user' ? userApi : adminApi).instances.start(1).then(value => this.results.push(value)).catch(error => this.errors.push(error.code || error.message || 'failure')).finally(() => { settled = true })
      // Actual axios adapters run asynchronously. Observe request admission
      // before a test switches session or consumes the synthetic response.
      return new Promise((resolve, reject) => {
        const deadline = performance.now() + 3000
        const check = () => {
          // A second operation can join the same unresolved refresh without
          // sending another fetch. Observe that gate instead of waiting for
          // transport, which cannot proceed until the test releases refresh.
          if ((proactiveRefresh ? refreshes.length > previousRefreshes : pending.length + refreshes.length > requests) || settled ||
            refreshes.some(row => !row.settled && row.identity === sessionIdentity)) return resolve()
          if (performance.now() > deadline) return reject(Error('refresh request admission timed out'))
          setTimeout(check, 0)
        }
        check()
      })
    } }
}, template: '<p>刷新隔离测试</p>' }).use(createPinia()).mount('#app')
