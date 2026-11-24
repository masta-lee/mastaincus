// Run the actual worker sections with isolated filesystem/OS/DB boundaries.
// These are failure-ordering checks, not a live database or systemd drill.
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { isIP } from 'node:net'
import { randomUUID } from 'node:crypto'
import ts from 'typescript'
import { BackupError, ensure, statePath } from '../src/services/platform-backup-core.js'
import { validateRestoreJournal, rollbackDatabasePlan } from '../src/services/platform-recovery-restore-journal.js'
import { verifyRecoveryOneshotExit } from './fixtures/recovery-oneshot.js'

await verifyRecoveryOneshotExit()

// Finance identity participates in the same precise restore/rollback journal.
{
  const id=randomUUID(),directory=statePath('private',id)
  const record={taskId:id,database:'fixture',staging:`incudal_restore_${id.replaceAll('-','')}`,rollback:`incudal_before_${id.replaceAll('-','')}`,
    stage:'prepared',config:{} as any,files:[{target:'/var/lib/incudal-finance/baseline.json',saved:join(directory,'before-0'),mode:0o640}]}
  validateRestoreJournal(record,directory)
  for(const target of ['/var/lib/incudal-finance/other.json','/var/lib/incudal-finance/../baseline.json']) assert.throws(()=>validateRestoreJournal({...record,files:[{...record.files[0],target}]},directory),/OSS_RECOVERY_STATE_INVALID/)
}

const source = await readFile(new URL('../src/services/platform-backup-worker.ts', import.meta.url), 'utf8')
const gatewaySource = await readFile(new URL('../src/services/platform-backup-gateway.ts', import.meta.url), 'utf8')
function section(startText: string, endText: string) {
  const start = source.indexOf(startText), end = source.indexOf(endText, start)
  assert.ok(start >= 0 && end > start, `worker section must exist: ${startText}`)
  return source.slice(start, end)
}
function load<T>(code: string, bindings: Record<string, unknown>): T {
  const compiled = ts.transpileModule(code, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }).outputText
  return new Function(...Object.keys(bindings), compiled)(...Object.values(bindings)) as T
}

// A timeout must not make valid signed enrollment look like a different
// identity. Execute the actual worker boundary with the original fixed helper;
// invalid enrollment, missing helper and an exhausted budget still fail once.
for (const scenario of ['verified', 'invalid', 'missing', 'timeout']) {
  let checks = 0
  const verify = load<() => Promise<void>>(
    section('async function verifyControllerEnrollment(', 'interface RestorePlan ') + '\nreturn verifyControllerEnrollment', {
      INSTALL: '/opt/incudal', process: { env: { INCUDAL_APP_DIR: '/opt/incudal/releases/verified-fixture' } },
      existsSync: () => true, join, BackupError,
      exec: async (program: string, args: string[], options: { timeout: number }) => {
        checks++
        assert.equal(program, '/usr/bin/python3')
        assert.deepEqual(args, ['-I', '-B', join('/opt/incudal/releases/verified-fixture', 'scripts/enroll-gateway-controller.py'), '--verify'])
        assert.equal(options.timeout, 120000, 'original dual signed-catalog verification can exceed 30 seconds on a low-resource machine')
        if (scenario !== 'verified') throw Object.assign(new Error('discarded private verification details'), {
          code: scenario === 'missing' ? 'ENOENT' : 1, killed: scenario === 'timeout'
        })
        return { stdout: '{}' }
      }
    })
  if (scenario === 'verified') await verify()
  else await assert.rejects(verify(), error => error instanceof BackupError && error.code === 'OSS_CONTROLLER_IDENTITY_INVALID')
  assert.equal(checks, 1, 'verification failure never retries, regenerates identity or bypasses the original helper')
}
console.log('PASS backup controller verification: low-resource budget, original sealed helper and bounded trust failures')

// Exercise the real CI launcher boundary. A four-minute valid restore must
// retain the same worker; errors expose only its fixed recovery classifications.
{
  const smoke=await readFile(new URL('../../scripts/smoke-platform-backup.mjs',import.meta.url),'utf8')
  const start=smoke.indexOf('const recoveryObservationTimeout='),end=smoke.indexOf('async function health(',start)
  assert.ok(start>=0&&end>start,'the original worker observation boundary must exist')
  const code=smoke.slice(start,end).replace("await (await import('/opt/incudal/server/dist/lib/authentication-integrity.js')).verifyRecoveryAuthenticationActor",
    'await verifyRecoveryAuthenticationActor')
  for(const scenario of ['completed','terminated','terminated-unreadable','failed-result']){
    let calls=0,request:any
    const messages:string[]=[],secret='PRIVATE_RECOVERY_TRACE_MUST_NOT_LEAVE_VM'
    const task=load<(kind:string)=>Promise<unknown>>('let config={};'+code+'\nreturn task',{
      assert,randomUUID,join,Date,process:{env:{}},
      require:()=>({parse:()=>({})}),readFile:async()=>'',verifyRecoveryAuthenticationActor:async()=>{},
      runPlatformBackupTask:async()=>{throw Error('launcher must use the original root worker')},
      pgQuery:async()=>[{id:1}],
      console:{log:()=>{},error:(...args:unknown[])=>messages.push(args.join(' '))},
      core:{readBackupConfig:async()=>({}),recoveryHeld:()=>false,backupRoot:()=>'/fixture',
        statePath:(...args:string[])=>join('/fixture',...args),validateId:(id:string)=>id,
        writeJson:async(_path:string,value:unknown)=>{request=value},
        readJson:async(path:string)=>{if(scenario==='terminated-unreadable')throw Error(secret);return path.endsWith('recovery-hold.json')?{taskId:request.id}:
          path.endsWith('journal.json')?{stage:'protected_start',privateTrace:secret}:
          {status:scenario==='completed'?'success':scenario==='terminated'?'running':'failed',stage:'protected_start',error:'OSS_PROTECTED_START_FAILED',privateTrace:secret}},
      },
      exec:async(program:string,args:string[],options:{timeout:number})=>{
        calls++;assert.equal(program,'/usr/local/libexec/incudal/incudal-online-task')
        assert.deepEqual(args,['platform-backup',request.id])
        assert.ok(options.timeout>=4*60*1000&&options.timeout<=15*60*1000,'valid restore duration and a bounded CI observation are both preserved')
        if(scenario.startsWith('terminated'))throw Object.assign(Error(secret),{stderr:secret,stdout:secret,signal:'SIGTERM',killed:true})
        return {stdout:''}
      }
    })
    if(scenario==='completed')await task('restore')
    else await assert.rejects(task('restore'),error=>!String(error).includes(secret)&&/BACKUP_DRILL_(WORKER|RESULT)_FAILED/.test(String(error)))
    assert.equal(calls,1,'the observer never retries the original task')
    assert.ok(messages.every(message=>!message.includes(secret)),'private OS and journal text remain inside the isolated machine')
    if(scenario==='terminated-unreadable')assert.ok(messages.some(message=>message.includes('"held":"unknown"')&&message.includes('"readError":true')))
    else if(scenario!=='completed')assert.ok(messages.some(message=>message.includes('protected_start')&&message.includes('OSS_PROTECTED_START_FAILED')))
  }
  assert.ok(smoke.includes('const until = Date.now() + recoveryObservationTimeout'),'automatic root continuation uses the same bounded observation')
}
console.log('PASS original restore observer: slow completion, one worker, fixed timeout/result diagnostics and no private trace output')

// Root proof of an empty-target rollback must survive a lost DB/write/unlink
// response. It never clears another hold or accepts a missing rollback batch.
for(const point of ['database','receipt','unlink','missing-batch','occupied','wrong-hold','none']) {
  const id=randomUUID(),batch=randomUUID(),directory=statePath('private',id),holdFile='fixture-hold',resultFile=statePath('results',id+'.json')
  const journal={taskId:id,snapshotAt:'2026-11-03T00:00:00Z',emptyTarget:true,stage:'rolled_back_review',rollbackBatchId:batch}
  const disk=new Map<string,any>([[join(directory,'journal.json'),journal],[holdFile,{taskId:point==='wrong-hold'?randomUUID():id,batchId:batch,mode:'rollback'}],
    [resultFile,{id,kind:'restore',status:'failed',error:'OSS_DATABASE_UNAVAILABLE'}]])
  let fail=true,dbComplete=false,proofChecks=0
  const finish=load<(directory:string)=>Promise<void>>(section('export async function finishEmptyRecoveryRollback(', 'export async function readWorkerRequest(').replace('export ','')+'\nreturn finishEmptyRecoveryRollback',{
    join,statePath,ensure,readJson:async(path:string)=>structuredClone(disk.get(path)),holdPath:()=>holdFile,
    validateRestoreJournal:()=>{},assertRestoreStartIdentity:async()=>{proofChecks++},emptyRecoveryTarget:async()=>point!=='occupied',protectedHealth:async()=>{},
    pgQuery:async(_sql:string,args:string[])=>{assert.deepEqual(args,[batch,id]);dbComplete=true;if(fail&&point==='database')throw Error('injected');return point==='missing-batch'?[]:[{id:batch}]},
    writeJson:async(path:string,value:unknown)=>{disk.set(path,value);if(fail&&point==='receipt')throw Error('injected')},
    durableUnlink:async(path:string)=>{disk.delete(path);if(fail&&point==='unlink')throw Error('injected')}
  })
  if(point==='none')await finish(directory)
  else await assert.rejects(finish(directory))
  if(['missing-batch','occupied','wrong-hold'].includes(point)) {
    assert.ok(disk.has(holdFile));assert.equal(disk.get(resultFile).rollbackVerified,undefined)
    if(point!=='missing-batch')assert.equal(dbComplete,false)
  }else {
    if(disk.has(holdFile)){fail=false;await finish(directory)}
    assert.equal(disk.has(holdFile),false)
    assert.equal(disk.get(resultFile).rollbackVerified,true);assert.ok(dbComplete);assert.ok(proofChecks>0)
    // If unlink succeeded but its reply was lost, the durable proof still
    // exists for the normal dispatcher; no import or refund is repeated.
    assert.equal(disk.get(resultFile).error,'OSS_DATABASE_UNAVAILABLE')
  }
}
console.log('PASS empty-target rollback root proof, lost responses, missing batch and protected hold identity')

// Root acceptance precedes request consumption. Only this receipt proves that
// the business worker has not crossed its first write boundary.
for(const point of ['receipt-before','receipt-after','consume','none']) {
  const id=randomUUID(),request={id,kind:'restore',createdBy:1,createdAt:new Date().toISOString()}
  const inbox=statePath('inbox',`${id}.json`),resultPath=statePath('results',`${id}.json`)
  const disk=new Map<string,any>([[inbox,request]])
  const accept=load<(id:string)=>Promise<unknown>>(source.slice(source.indexOf('export async function readWorkerRequest(')).replace('export ','')+'\nreturn readWorkerRequest',{
    statePath,validateId:(value:string)=>value,ensure,existsSync:(path:string)=>disk.has(path),
    readJson:async(path:string)=>disk.get(path),
    writeJson:async(path:string,value:unknown)=>{if(point==='receipt-before')throw new Error('injected');disk.set(path,value);if(point==='receipt-after')throw new Error('injected')},
    unlink:async(path:string)=>{if(point==='consume')throw new Error('injected');disk.delete(path)}
  })
  if(point==='none')assert.deepEqual(await accept(id),request);else await assert.rejects(accept(id),/injected/)
  assert.ok(disk.has(inbox) || disk.get(resultPath)?.restoreNotStarted===true)
  if(disk.has(resultPath)) {
    assert.equal(disk.get(resultPath).stage,'accepted')
    await assert.rejects(accept(id),/TASK_(ID_CONFLICT|INVALID)/,'an accepted task is not executed twice')
  }
}
console.log('PASS root acceptance/consumption interruptions preserve non-start proof and reject duplicate execution')

const armCode = section('      // Persistent across application', "      await update('stopping')")
for (const failure of process.argv.includes('--rollback-only') ? [] : ['journal-before', 'journal-after', 'hold-before', 'hold-after', 'none']) {
  const disk = new Map<string, unknown>()
  const arm = load<() => Promise<void>>(`return async () => { let preserve = false; ${armCode} }`, {
    directory: 'fixture-task', id: 'fixture-task', join, files:new Map(), request:{restorePolicy:'snapshot-v1'}, backupGatewayBaseline:async()=>null,
    journal: { stage: 'prepared', files: [] }, plan: { manifest: { createdAt: '2026-10-01', version: '1.7.1' } },
    holdPath: () => 'hold', writeJson: async (path: string, value: unknown) => {
      const kind = path === 'hold' ? 'hold' : 'journal'
      if (failure === kind + '-before') throw new Error('injected write failure')
      disk.set(path, structuredClone(value))
      if (failure === kind + '-after') throw new Error('injected directory sync failure after rename')
    }
  })
  if (failure === 'none') await arm(); else await assert.rejects(arm(), /injected/)
  assert.ok(!disk.has('hold') || disk.has(join('fixture-task', 'journal.json')),
    `${failure}: a durable recovery hold must always have a durable rollback journal`)
  if(disk.has('hold'))assert.equal((disk.get('hold') as any).restorePolicy,'snapshot-v1')
}
if (!process.argv.includes('--rollback-only')) console.log('PASS hold/journal failures before and after rename retain a usable recovery journal')

const rollbackSource = section('async function rollbackJournal(', 'export async function runPlatformBackupTask(')
const restoreId = randomUUID(), rollbackBatchId = randomUUID()
const directory = statePath('private', restoreId), journalPath = join(directory, 'journal.json')
const gateway = '/etc/wireguard/incudal-mgmt.conf'
for (const interruption of ['files', 'gateway', 'health', 'legacy-interrupted', 'fresh-b']) {
  const disk = new Map<string, any>([[journalPath, {
    version:2, workerPid:123, rollbackBatchId, originalOid:10, restoredOid:20,
    taskId: restoreId, database: 'fixture_db', staging:`incudal_restore_${restoreId.replace(/-/g,'')}`,
    rollback: `incudal_before_${restoreId.replace(/-/g,'')}`, stage: 'files_switched', config: {},
    files: [{ target: gateway, saved: interruption==='fresh-b'?null:join(directory,'before-0'), mode: 0o600 }]
  }], ['hold', { taskId: restoreId, batchId:restoreId }]])
  let file = interruption === 'legacy-interrupted' ? '[Interface]\nAddress = 10.253.240.1/20\nPrivateKey = original-identity' : '[Interface]\nAddress = 10.253.240.1/20\nPrivateKey = restored-identity'
  let live = 'restored-identity', liveNetwork = 'restored-network', fired = false, lastStage = ''
  const calls: string[] = []
  const refreshGateway = load<(previous: string, reconcileNetwork?: boolean) => Promise<void>>(
    gatewaySource.slice(gatewaySource.indexOf('const configPath =')).replace(/^export /gm, '') + '\nreturn refreshRestoredGateway', {
      join, ensure, isIP, readFile: async () => file,
      mkdtemp: async () => 'fixture-gateway', writeFile: async () => {}, rm: async () => {},
      exec: async (_program: string, args: string[]) => {
        if (args[0] === 'restart') liveNetwork = 'original-network'
        if (args[0] === 'syncconf') {
          if (interruption === 'gateway' && !fired) { fired = true; throw new Error('injected gateway sync failure') }
          live = file
        }
        return { stdout: args[0] === '-j' ? '[]' : args[0] === 'is-active' ? 'active' : '' }
      }
    })
  const rollback = load<(directory: string) => Promise<boolean>>(rollbackSource + '\nreturn rollbackJournal', {
    randomUUID, validateRestoreJournal, rollbackDatabasePlan, ensure, existsSync:()=>true, hashFile:async()=>'a'.repeat(64),
    lstat:async()=>({isFile:()=>true,isSymbolicLink:()=>false}),
    installRecoveryOperator: async () => {}, backupRoot: () => 'fixture-root',
    join, readJson: async (path: string) => structuredClone(disk.get(path) ?? null),
    writeJson: async (path: string, value: any) => { disk.set(path, structuredClone(value)); if (path === journalPath) lastStage = value.stage },
    service: async (action: string) => { calls.push(action) }, quoteIdentifier: (name: string) => name,
    localDatabaseAdmin: async () => JSON.stringify([{name:'fixture_db',oid:10}]), exec: async (_program:string,args:string[]) => {
      if(args[0]==='stop'){calls.push('stop-created-gateway');live='';liveNetwork=''}
      return {stdout:args[0]==='-j'?'[]':'1000'}
    },
    readFile: async (path: string) => path === gateway ? file : 'ENCRYPTION_KEY=original',
    atomicFileCopy: async () => {
      file = '[Interface]\nAddress = 10.253.240.1/20\nPrivateKey = original-identity'
      if (interruption === 'files' && !fired) { fired = true; throw new Error('injected file-directory-sync failure') }
    }, chmod: async () => {}, chown: async () => {}, unlink: async (path:string) => {if(path===gateway){assert.ok(calls.includes('stop-created-gateway'));file=''}},
    refreshRestoredGateway: refreshGateway, verifyControllerEnrollment: async () => {}, CONTROLLER_ROOT: '/controller',
    writeBackupConfig: async () => {}, statePath: (...parts: string[]) => join(...parts),
    process: { env: {} }, parseEnv: () => ({ ENCRYPTION_KEY: 'original' }), INSTALL: '/opt/incudal', holdPath: () => 'hold',
    protectedHealth: async () => {
      if (interruption === 'health' && !fired) { fired = true; throw new Error('injected protected start failure') }
    }
  })
  if (!['legacy-interrupted','fresh-b'].includes(interruption)) {
    await assert.rejects(rollback(directory), /injected/)
    assert.ok(fired && disk.has('hold'))
  }
  assert.equal(await rollback(directory), true)
  if(interruption==='fresh-b'){
    assert.equal(file,'');assert.equal(live,'');assert.equal(liveNetwork,'')
    assert.equal(await rollback(directory),true,'replaying fresh-B rollback must not recreate a gateway')
  } else {
  assert.ok(file.endsWith('original-identity'))
  assert.equal(live, file, `${interruption}: retry must reconcile kernel state even when the old file was already restored`)
  assert.equal(liveNetwork, 'original-network', `${interruption}: address/MTU must be reconciled as well as WireGuard peers`)
  }
  assert.equal(lastStage, 'rolled_back_review')
  assert.ok(calls.includes('start') && disk.has('hold'), 'rollback restarts protected, never resumes business')
}
console.log('PASS interrupted file/gateway/health rollback retries converge the original identity and retain the recovery hold')

// Ubuntu confines both wg-quick and wg config reads to /etc/wireguard.
// Exercise the actual helper through that filesystem boundary, including a
// parser failure before the live interface may be restarted.
for (const parseFailure of [false, true]) {
  const events: string[] = []
  const files = new Map<string, string>()
  const conf = '[Interface]\nPrivateKey = fixture\nAddress = 10.253.240.1/20\nListenPort = 51820\n'
  const refresh = load<(previous: string, reconcileNetwork: boolean) => Promise<void>>(
    gatewaySource.slice(gatewaySource.indexOf('const configPath =')).replace(/^export /gm, '') + '\nreturn refreshRestoredGateway', {
      join, ensure, isIP, readFile: async () => conf,
      mkdtemp: async (prefix: string) => prefix + 'fixture',
      writeFile: async (path: string, content: string, options: { mode: number }) => {
        assert.equal(options.mode, 0o600, 'temporary identities must remain private')
        files.set(path, content)
      },
      rm: async () => { events.push('cleanup') },
      exec: async (program: string, args: string[]) => {
        events.push(args[0])
        if (args[0] === 'strip' || args[0] === 'syncconf') {
          const path = args[args.length - 1]
          assert.ok(path.replaceAll('\\', '/').startsWith('/etc/wireguard/.incudal-restore-'), `${program}: configuration must stay inside the confined WireGuard directory`)
          assert.ok(files.has(path))
          if (args[0] === 'strip' && parseFailure) throw new Error('injected parser refusal')
        }
        return { stdout: args[0] === '-j' ? '[]' : args[0] === 'is-active' ? 'active' : args[0] === 'strip' ? '[Interface]\nPrivateKey = fixture\n' : '' }
      }
    })
  if (parseFailure) {
    await assert.rejects(refresh(conf, true), /injected parser refusal/)
    assert.ok(!events.includes('restart') && !events.includes('syncconf'), 'a parser refusal must precede any live network changes')
  } else {
    await refresh(conf, true)
    assert.ok(events.indexOf('strip') < events.indexOf('restart') && events.includes('syncconf'))
  }
  assert.equal(events.at(-1), 'cleanup')
}
console.log('PASS confined private gateway files, parser-before-restart ordering and cleanup')
