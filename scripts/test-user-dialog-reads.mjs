import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { mkdirSync } from 'node:fs'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve } from 'node:path'
import { Browser, sleep } from '../.agents/skills/design-taste-frontend/scripts/lib/cdp.mjs'
const root = fileURLToPath(new URL('..', import.meta.url)).replaceAll('\\', '/')
const require = createRequire(new URL('../client/package.json', import.meta.url))
const { createServer } = await import(pathToFileURL(require.resolve('vite')).href)
const { default: vue } = await import(pathToFileURL(require.resolve('@vitejs/plugin-vue')).href)
const output = resolve(root, 'logs/user-dialog-reads'); mkdirSync(output, { recursive: true }); process.env.TASTE_SKILL_TMP = output
const tailwind = require('tailwindcss/loadConfig')(root + '/client/tailwind.config.js')
tailwind.content = [root + '/client/src/**/*.{vue,js,ts}', root + '/scripts/fixtures/user-dialogs/*.js']
const server = await createServer({ configFile: false, cacheDir: resolve(output, 'vite-cache'), root: root + '/scripts/fixtures/user-dialogs', publicDir: root + '/client/public', plugins: [vue()],
  resolve: { alias: [{ find: /^@\/api\/admin$/, replacement: root + '/scripts/fixtures/user-dialogs/api.js' }, { find: '@', replacement: root + '/client/src' },
    ...['vue', 'pinia', 'vue-i18n', 'vue-router'].map(name => ({ find: name, replacement: require.resolve(name === 'vue' ? 'vue/dist/vue.esm-bundler.js' : name) }))], dedupe: ['vue', 'pinia', 'vue-i18n', 'vue-router'] },
  css: { postcss: { plugins: [require('tailwindcss')(tailwind), require('autoprefixer')()] } },
  server: { host: '127.0.0.1', port: 19707, strictPort: true, fs: { allow: [root] } },
})
let browser
try {
  await server.listen(); browser = await Browser.launch(); const page = await browser.newPage({ reducedMotion: true })
  await page.goto('http://127.0.0.1:19707', { settleMs: 1400 })
  for (let attempt = 0; attempt < 200; attempt++) {
    if (await page.eval(() => !!window.userDialogsHarness?.pending.length)) break
    if (attempt === 199) throw Error('user fixture did not mount: ' + page.consoleErrors.join('\n'))
    await sleep(150)
  }
  const run = async (fn, arg) => { const value = await page.eval(fn, arg); await sleep(70); return value }
  const last = kind => page.eval(kind => window.userDialogsHarness.pending.findLastIndex(item => item.kind === kind), kind)
  const accept = (index, data) => run(({ index, data }) => window.userDialogsHarness.pending[index].resolve(data), { index, data })
  const reject = index => run(index => window.userDialogsHarness.pending[index].reject(new Error('fixture read unavailable')), index)
  const read = key => page.eval(key => JSON.parse(JSON.stringify(window.userDialogsHarness.view()[key])), key)
  const user = id => ({ id, username: `Account ${id}`, balance: 10 * id, role: 'user', status: 'active', createdAt: '2026-10-01T00:00:00Z' })
  const response = (kind, id = 1, value = 10) => kind === 'balance' ? { userId: id, username: `Account ${id}`, balance: value, totalRecharge: 0, totalConsume: 0, totalRefund: 0 } :
    { [kind === 'logs' ? 'logs' : 'records']: [{ id, userId: id, ip: `192.0.2.${id}`, amount: value, balanceBefore: 0, balanceAfter: value, type: 'recharge', status: 'completed', orderNo: `fixture-${id}`, createdAt: '2026-10-01T00:00:00Z' }], total: 150, totalPages: 3, page: 1, pageSize: 50 }
  await accept(await last('users'), { users: [user(1), user(2)], total: 2, totalPages: 1 })
  await run(() => { const v = window.userDialogsHarness.view(); v.users.push({ id: 3, username: 'Admin', role: 'admin', status: 'active', balance: 0, createdAt: '2026-10-01T00:00:00Z' }) })
  for (const locale of ['zh-CN', 'zh-TW', 'en']) for (const dark of [false, true]) for (const width of [1440, 768, 390]) {
    await page.setViewport({ width, height: 1000, mobile: width < 500 })
    await run(({ locale, dark }) => { const h = window.userDialogsHarness; h.setLocale(locale); h.theme.setTheme(dark ? 'dark' : 'light') }, { locale, dark })
    const controls = await page.eval(() => [...document.querySelectorAll('.user-delete-action')].filter(button => button.getBoundingClientRect().width).map(button => {
      const icon = button.querySelector('svg'), rect = button.getBoundingClientRect(), svg = icon.getBoundingClientRect(), neighbor = button.previousElementSibling.querySelector('svg').getBoundingClientRect()
      return { label: button.getAttribute('aria-label'), title: button.title, text: button.innerText.trim(), ariaHidden: icon.getAttribute('aria-hidden'), fill: icon.getAttribute('fill'), stroke: icon.getAttribute('stroke'), strokeWidth: icon.querySelector('path').getAttribute('stroke-width'),
        width: svg.width, height: svg.height, neighborWidth: neighbor.width, neighborHeight: neighbor.height, hitWidth: rect.width, hitHeight: rect.height, right: rect.right }
    }))
    assert.equal(controls.length, 2, 'administrator rows have no delete control')
    for (const control of controls) {
      assert.equal(control.label, { 'zh-CN': '删除用户', 'zh-TW': '刪除使用者', en: 'Delete user' }[locale])
      assert.equal(control.title, control.label, 'native hover tooltip names the action')
      assert.equal(control.text, '', 'the action is an icon without a visible text label')
      assert.deepEqual([control.width, control.height, control.neighborWidth, control.neighborHeight], [16, 16, 16, 16])
      assert.deepEqual([control.ariaHidden, control.fill, control.stroke, control.strokeWidth], ['true', 'none', 'currentColor', '2'])
      if (width < 1024) assert.ok(control.hitWidth >= 44 && control.hitHeight >= 44 && control.right <= width, 'mobile icon remains a 44px tap target and fits')
    }
    await page.eval(() => { const button = [...document.querySelectorAll('.user-delete-action')].find(button => button.getBoundingClientRect().width); button.previousElementSibling.focus() })
    await page.send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 })
    await page.send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 })
    assert.equal(await page.eval(() => document.activeElement.classList.contains('user-delete-action') && document.activeElement.matches(':focus-visible') && getComputedStyle(document.activeElement).boxShadow !== 'none'), true, 'keyboard focus reaches the named icon and remains visible')
    if (locale === 'zh-CN') await page.screenshot({ path: resolve(output, `delete-icon-${dark ? 'dark' : 'light'}-${width}.png`), format: 'png' })
    await run(() => {
      const buttons = [...document.querySelectorAll('.user-delete-action')].filter(button => button.getBoundingClientRect().width)
      window.deleteListProbe = { survivor: buttons[1], top: buttons[1].getBoundingClientRect().top, scroll: scrollY }
      void window.userDialogsHarness.view().loadUsers(() => true, { background: true })
    })
    assert.equal(await read('usersLoading'), false, 'background deletion refresh never switches the loaded list to a skeleton')
    await sleep(180)
    assert.equal(await page.eval(() => window.deleteListProbe.survivor.isConnected && window.deleteListProbe.top === window.deleteListProbe.survivor.getBoundingClientRect().top && scrollY === window.deleteListProbe.scroll), true, 'delayed refresh retains rows, layout and scroll')
    const admin = { id: 3, username: 'Admin', role: 'admin', status: 'active', balance: 0, createdAt: '2026-10-01T00:00:00Z' }
    await accept(await last('users'), { users: [user(1), user(2), admin], total: 3, totalPages: 1 })
    assert.equal(await page.eval(() => window.deleteListProbe.survivor.isConnected), true, 'the same keyed row survives refresh completion')
  }
  await run(() => { const h = window.userDialogsHarness; h.view().users.pop(); h.setLocale('zh-CN'); h.theme.setTheme('light') })
  await page.setViewport({ width: 1440, height: 1000 })
  console.log('PASS delete user icons: matching 16px outline style, native hover name, keyboard focus, 44px mobile target, both themes and three languages')
  await run(() => { const v = window.userDialogsHarness.view(); v.userPage = 2; void v.loadUsers(() => true, { background: true }) })
  await accept(await last('users'), { users: [], total: 1, totalPages: 1 })
  assert.equal(await read('userPage'), 1, 'deleting the final item on the final page returns to a valid page')
  assert.equal(await read('usersLoading'), false)
  await accept(await last('users'), { users: [user(1), user(2)], total: 2, totalPages: 1 })
  await run(() => { void window.userDialogsHarness.view().loadUsers(() => true, { background: true }) })
  const failedRefresh = await last('users')
  await reject(failedRefresh)
  assert.deepEqual((await read('users')).map(row => row.id), [1, 2], 'a failed background read retains the existing list')
  await run(() => { void window.userDialogsHarness.view().loadUsers(() => true, { background: true }) })
  const oldRefresh = await last('users')
  await run(() => { void window.userDialogsHarness.view().loadUsers(() => true, { background: true }) })
  await accept(await last('users'), { users: [user(1), user(2)], total: 2, totalPages: 1 })
  await accept(oldRefresh, { users: [], total: 0, totalPages: 1 })
  assert.deepEqual((await read('users')).map(row => row.id), [1, 2], 'old refresh receipts cannot erase the newer list')
  console.log('PASS deletion list edge cases: last page correction, failed refresh retention and stale response rejection')
  if (!process.argv.includes('--delete-icon-only')) {
  await run(() => { void window.userDialogsHarness.view().openBalanceModal(window.userDialogsHarness.view().users[0]) })
  const oldBalance = await last('balance')
  await run(() => { void window.userDialogsHarness.view().openBalanceModal(window.userDialogsHarness.view().users[1]) })
  await accept(await last('balance'), response('balance', 2, 20)); await accept(oldBalance, response('balance', 1, 10))
  assert.equal((await read('balanceInfo')).balance, 20, 'old balance cannot replace the newly selected user')
  for (const kind of ['balance', 'logs', 'recharge', 'login']) {
    const list = { balance: 'balanceInfo', logs: 'balanceLogs', recharge: 'rechargeRecords', login: 'loginRecords' }[kind]
    const loading = { balance: 'balanceInfoLoading', logs: 'balanceLogsLoading', recharge: 'rechargeRecordsLoading', login: 'loginRecordsLoading' }[kind]
    const error = { balance: 'balanceInfoError', logs: 'balanceLogsError', recharge: 'rechargeRecordsError', login: 'loginRecordsError' }[kind]
    const load = { balance: 'loadBalanceInfo', logs: 'loadBalanceLogs', recharge: 'loadRechargeRecords', login: 'loadLoginRecords' }[kind]
    const open = async (id = 1) => {
      await run(kind => {
        const h = window.userDialogsHarness, v = h.view(); h.auth.user = { id: 1, role: 'admin', username: 'fixture' }; h.session('a'); v.activeTab = 'users'
        v.showBalanceModal = false; v.showLoginRecordsModal = false
        if (kind === 'login') void v.openLoginRecordsModal(v.users[0])
        else { void v.openBalanceModal(v.users[0]); if (kind !== 'balance') v.switchBalanceTab(kind) }
      }, kind)
      if (id !== 1) await run(({ kind, id }) => {
        const v = window.userDialogsHarness.view()
        if (kind === 'login') void v.openLoginRecordsModal(v.users[id - 1]); else { void v.openBalanceModal(v.users[id - 1]); if (kind !== 'balance') v.switchBalanceTab(kind) }
      }, { kind, id })
      return last(kind)
    }
    let old = await open(), fresh = await open(2)
    await accept(fresh, response(kind, 2, 20)); await accept(old, response(kind))
    assert.equal(kind === 'balance' ? (await read(list)).balance : (await read(list))[0].id, kind === 'balance' ? 20 : 2)
    for (const change of ['target-aba', 'session', 'session-aba', 'account', 'role', 'logout', 'close', 'tab', 'cache', 'pagination', 'filter']) {
      old = await open()
      const before = await page.eval(() => window.userDialogsHarness.toasts.length)
      await run(async ({ change, kind }) => {
        const h = window.userDialogsHarness, v = h.view(), modal = kind === 'login' ? 'showLoginRecordsModal' : 'showBalanceModal'
        if (change === 'target-aba') { if (kind === 'login') { void v.openLoginRecordsModal(v.users[1]); void v.openLoginRecordsModal(v.users[0]) } else { void v.openBalanceModal(v.users[1]); void v.openBalanceModal(v.users[0]); if (kind !== 'balance') v.switchBalanceTab(kind) } }
        if (change === 'session') h.session('b')
        if (change === 'session-aba') { h.session('b'); h.session('a') }
        if (change === 'account') h.auth.user = { ...h.auth.user, id: 2 }
        if (change === 'role') h.auth.user = { ...h.auth.user, role: 'user' }
        if (change === 'logout') h.session(null)
        if (change === 'close') { v[modal] = false; v[modal] = true }
        if (change === 'tab') v.activeTab = 'invites'
        if (change === 'cache') { await h.router.push('/other'); await h.router.push('/admin/users') }
        if (change === 'pagination') { if (kind === 'login') v.loginRecordsPage = 2; else if (kind === 'logs') v.balanceLogsPage = 2; else if (kind === 'recharge') v.rechargeRecordsPage = 2; else v.balanceTab = 'logs' }
        if (change === 'filter') { if (kind === 'logs') v.balanceLogsShowLotteryGiftOnly = true; else if (kind === 'login') v.loginRecordsPageSize = 20; else if (kind === 'recharge') v.rechargeRecordsPageSize = 20; else v.balanceTab = 'adjust' }
      }, { change, kind })
      await reject(old)
      assert.equal(await page.eval(() => window.userDialogsHarness.toasts.length), before, `${kind}/${change} old failure stays quiet`)
      assert.equal(await read(error), '', `${kind}/${change} old failure cannot set current error`)
    }
    old = await open(); await run(load => { void window.userDialogsHarness.view()[load]() }, load); fresh = await last(kind)
    await reject(old); assert.equal(await read(loading), true, 'old finally cannot stop newer loading')
    await reject(fresh); assert.match(await read(error), /fixture read unavailable/)
    await run(load => { void window.userDialogsHarness.view()[load]() }, load)
    await accept(await last(kind), response(kind, 1, 0)); assert.equal(await read(error), '')
    assert.equal(await read(loading), false)
    if (kind === 'balance') assert.equal((await read(list)).balance, 0)
    old = await open(); await run(() => { window.userDialogsHarness.session('a', 2) }); await accept(old, response(kind))
    assert.equal(await read(loading), false, 'same sid refresh retains the current read')
    old = await open(); await accept(old, { error: 'invalid response' }); assert.ok(await read(error), 'invalid response is not a successful empty result')
    if (kind === 'balance' || kind === 'recharge') {
      old = await open(); await accept(old, response(kind, 2, 50))
      assert.ok(await read(error), 'a receipt with another user identity is rejected')
    }
    old = await open()
    const bad = response(kind)
    if (kind === 'balance') bad.balance = '10'
    else if (kind === 'logs') bad.logs[0].amount = '10'
    else if (kind === 'recharge') bad.records[0].amount = '10'
    else bad.records[0].id = 0
    await accept(old, bad); assert.ok(await read(error), 'invalid numeric row data is not displayed as valid')
    if (kind !== 'balance') {
      old = await open(); await accept(old, { [kind === 'logs' ? 'logs' : 'records']: [], total: 0, page: 1, pageSize: 50 })
      assert.equal(await read(error), ''); assert.deepEqual(await read(list), [], 'successful empty list has no error')
    }
    old = await open(); await reject(old)
    for (const [locale, width, dark, mobile] of [['zh-CN', 1440, false, false], ['zh-CN', 768, false, false], ['en', 390, true, true]]) {
      await page.setViewport({ width, height: 1000, mobile })
      await run(({ locale, dark }) => { const h = window.userDialogsHarness; h.setLocale(locale); h.theme.setTheme(dark ? 'dark' : 'light') }, { locale, dark })
      assert.equal(await page.eval(() => document.documentElement.scrollWidth <= innerWidth), true)
      await page.screenshot({ path: resolve(output, `${kind}-${locale}-${width}.png`), format: 'png' })
      if (kind !== 'login') assert.equal(await page.eval(() => [...document.querySelectorAll('[data-user-dialog="balance"] button')].every(button => {
        const rect = button.getBoundingClientRect(); return rect.left >= 0 && rect.right <= innerWidth
      })), true, 'all four balance tabs and actions fit the phone')
    }
    await run(load => { void window.userDialogsHarness.view()[load]() }, load)
    await accept(await last(kind), response(kind, 1, 0))
    await page.screenshot({ path: resolve(output, `${kind}-success-en-390.png`), format: 'png' })
  }
  }
  await run(() => { const v = window.userDialogsHarness.view(); void v.openBalanceModal(v.users[0]) })
  const index = await last('balance')
  await run(() => {const v=window.userDialogsHarness.view();v.showBalanceModal=false;v.showLoginRecordsModal=false;window.userDialogsHarness.session('a');window.userDialogsHarness.auth.user={id:1,role:'admin'};v.activeTab='users'})
  const beforeDelete = await page.eval(()=>window.userDialogsHarness.pending.filter(r=>r.kind==='cleanup').length)
  await page.setViewport({ width: 1440, height: 1000 })
  await page.send('Page.bringToFront')
  let dialogOpened = false
  browser.listeners.get(page.sessionId+'|Page.javascriptDialogOpening')?.clear()
  const nativeDialog = browser.on(page.sessionId,'Page.javascriptDialogOpening',()=>{dialogOpened=true;void page.send('Page.handleJavaScriptDialog',{accept:false})})
  await page.eval(() => [...document.querySelectorAll('.user-delete-action')].find(button => button.getBoundingClientRect().width).focus())
  await page.send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: '\r', unmodifiedText: '\r' })
  await page.send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 })
  for(let attempt=0;attempt<100&&!dialogOpened;attempt++)await sleep(30)
  assert.ok(dialogOpened,'native browser confirmation opened')
  assert.equal(await page.eval(()=>window.userDialogsHarness.pending.filter(r=>r.kind==='cleanup').length),beforeDelete,'cancel sends no deletion request')
  nativeDialog()
  const approveDialog = browser.on(page.sessionId,'Page.javascriptDialogOpening',()=>{void page.send('Page.handleJavaScriptDialog',{accept:true})})
  await page.eval(() => {
    const buttons = [...document.querySelectorAll('.user-delete-action')].filter(button => button.getBoundingClientRect().width)
    window.deleteListProbe = { survivor: buttons[1], detached: false }
    window.deleteListProbe.observer = new MutationObserver(() => { if (!window.deleteListProbe.survivor.isConnected) window.deleteListProbe.detached = true })
    window.deleteListProbe.observer.observe(document.querySelector('#app'), { childList: true, subtree: true })
  })
  await page.eval(() => [...document.querySelectorAll('.user-delete-action')].find(button => button.getBoundingClientRect().width).scrollIntoView({ block: 'center', behavior: 'instant' }))
  await sleep(150)
  const deletePoint = await page.eval(() => { const r = [...document.querySelectorAll('.user-delete-action')].find(button => button.getBoundingClientRect().width).getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 } })
  await page.send('Input.dispatchMouseEvent', { type: 'mousePressed', button: 'left', clickCount: 1, ...deletePoint })
  await page.send('Input.dispatchMouseEvent', { type: 'mouseReleased', button: 'left', clickCount: 1, ...deletePoint })
  for(let attempt=0;attempt<100&&await last('cleanup')<0;attempt++)await sleep(30)
  const deleteIndex=await last('cleanup');assert.ok(deleteIndex>=0)
  assert.equal(await page.eval(index=>window.userDialogsHarness.pending[index].data.id,deleteIndex),1)
  assert.equal(await page.eval(() => [...document.querySelectorAll('.user-delete-action')].find(button => button.getBoundingClientRect().width).disabled), true)
  assert.equal(await page.eval(() => [...document.querySelectorAll('.user-delete-action')].find(button => button.getBoundingClientRect().width).getAttribute('aria-busy')), 'true')
  assert.equal(await page.eval(() => [...document.querySelectorAll('.user-delete-action')].find(button => button.getBoundingClientRect().width).querySelector('[role="status"]').textContent.trim()), process.argv.includes('--delete-icon-only') ? '正在删除' : 'Deleting')
  await run(()=>{void window.userDialogsHarness.view().deleteUserAccount(window.userDialogsHarness.view().users[0])})
  assert.equal(await page.eval(()=>window.userDialogsHarness.pending.filter(r=>r.kind==='cleanup').length),beforeDelete+1,'duplicate click suppressed')
  await accept(deleteIndex,{accepted:true,pending:true})
  assert.equal(await read('usersLoading'), false, 'admitted deletion refresh keeps the existing list on screen')
  assert.equal(await page.eval(() => window.deleteListProbe.detached), false)
  await accept(await last('users'),{users:[{...user(1),deleting:true},user(2)],total:2,totalPages:1})
  const statusIndex=await last('cleanup-status');await accept(statusIndex,{status:'pending',error:'USER_CLEANUP_RETRY'})
  for (let attempt = 0; attempt < 100 && await last('cleanup-status') === statusIndex; attempt++) await sleep(30)
  const pollIndex = await last('cleanup-status'); assert.ok(pollIndex > statusIndex, 'the normal cleanup watcher polls after initial admission')
  await accept(pollIndex, { status: 'pending', error: 'USER_CLEANUP_RETRY' })
  assert.equal(await page.eval(() => [...document.querySelectorAll('.user-delete-action')].find(button => button.getBoundingClientRect().width).disabled), false, 'cleanup error allows retry using the same named icon')
  assert.equal(await page.eval(() => [...document.querySelectorAll('.user-delete-action')].find(button => button.getBoundingClientRect().width).getAttribute('aria-busy')), 'false')
  for (let attempt = 0; attempt < 150 && await last('cleanup-status') === pollIndex; attempt++) await sleep(40)
  const completedPoll = await last('cleanup-status'); assert.ok(completedPoll > pollIndex)
  await accept(completedPoll, { status: 'done' })
  assert.equal(await read('usersLoading'), false, 'completed cleanup also refreshes without a skeleton')
  await accept(await last('users'), { users: [user(2)], total: 1, totalPages: 1 })
  assert.deepEqual((await read('users')).map(row => row.id), [2], 'the confirmed deleted row is removed')
  assert.equal(await page.eval(() => !window.deleteListProbe.detached && window.deleteListProbe.survivor.isConnected), true, 'unrelated user row stays mounted through admission, polling and final deletion')
  await page.eval(() => window.deleteListProbe.observer.disconnect())
  approveDialog()
  console.log('PASS administrator account removal: actual native cancel/confirm, exact target, duplicate-click suppression and asynchronous cleanup status')
  console.log('PASS deletion refresh: delayed list updates preserve rows/layout/scroll in 18 view combinations; admission, retries and confirmed removal never unmount the other user')
  await run(() => { window.userDialogsHarness.state.mounted = false }); await accept(index, response('balance', 1, 99))
  assert.equal(page.consoleErrors.length, 0, page.consoleErrors.join('\n'))
  if (!process.argv.includes('--delete-icon-only')) console.log('PASS user balance/login dialogs current target/session/cache, latest reads, pages/filters, zero, persistent errors and retry')
} finally { if (browser) await browser.close(); await server.close() }
process.exit(0)
