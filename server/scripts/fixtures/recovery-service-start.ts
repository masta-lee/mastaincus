import assert from 'node:assert/strict'
import { controlRecoveryBackend } from '../../src/services/platform-backup-health.js'

export async function verifyRecoveryServiceStart() {
  for (const scenario of ['normal','stop','restart','limited','restart-limited','startup-error','stop-error','read-error','reset-error','retry-error']) {
    const actions: string[] = []
    const action = scenario.startsWith('stop') ? 'stop' : scenario.startsWith('restart') ? 'restart' : 'start'
    const execute = async (program: string, args: string[], options: {timeout:number}) => {
      assert.equal(program, '/usr/bin/systemctl'); assert.equal(args[1], 'incudal-backend.service')
      const actionTimeout = { stop:36*60*1000, start:11*60*1000, restart:46*60*1000 }[action]
      assert.equal(options.timeout, ['show','reset-failed'].includes(args[0]) ? 10000 : actionTimeout,
        'recovery and its one permitted retry must cover the shipped drain/start budgets; diagnostics stay short')
      actions.push(args[0])
      if (actions.length === 1 && !['normal','stop','restart'].includes(scenario)) throw new Error('private diagnostic')
      if (args[0] === 'show') {
        assert.deepEqual(args, ['show','incudal-backend.service','--property=Result','--value'])
        if (scenario === 'read-error') throw new Error('private diagnostic')
        return {stdout: scenario === 'startup-error' ? 'exit-code\n' : 'start-limit-hit\n'}
      }
      if (args[0] === 'reset-failed' && scenario === 'reset-error' || actions.length === 4 && scenario === 'retry-error') throw new Error('private diagnostic')
      return {stdout:''}
    }
    if (scenario.endsWith('error')) await assert.rejects(controlRecoveryBackend(action,execute), error =>
      (error as Error).message === 'OSS_BACKEND_SERVICE_FAILED')
    else await controlRecoveryBackend(action,execute)
    const expected = ['normal','stop','restart','stop-error'].includes(scenario) ? [action] :
      ['startup-error','read-error'].includes(scenario) ? [action,'show'] :
      scenario === 'reset-error' ? [action,'show','reset-failed'] : [action,'show','reset-failed',action]
    assert.deepEqual(actions,expected,scenario)
  }
  console.log('PASS recovery service start: only start-limit-hit resets the fixed backend once; stop, real startup, reset and retry failures stay bounded')
}
