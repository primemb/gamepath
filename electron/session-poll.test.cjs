const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')
const vm = require('node:vm')

// Run the actual main-process poll without launching Electron or its service.
const main = fs.readFileSync(path.join(__dirname, 'main.cjs'), 'utf8')
const start = main.indexOf('async function pollSessionStatus()')
const source = main.slice(start, main.indexOf('\n/**', start))

function fixture(request) {
  const effects = []
  const context = vm.createContext({
    state: { session: { status: 'connected' } },
    serviceBridge: { status: { status: 'ready' }, request },
    sessionPollInFlight: false,
    sessionPollFailures: 0,
    SESSION_POLL_MAX_FAILURES: 3,
    lastRuntimeState: null,
    updateSessionMetrics: () => effects.push('metrics'),
    recordUsage: () => effects.push('usage'),
    relayFailover: { observe: () => effects.push('observe'), end: () => effects.push('end') },
    stopSessionKeepAlive: () => effects.push('stop-polling'),
    logger: { warn() {}, info() {}, error() {} },
    sessionExclusive: async (work) => work(),
  })
  vm.runInContext(source, context)
  return { context, effects, poll: () => context.pollSessionStatus() }
}

function deferred() {
  let resolve, reject
  const promise = new Promise((yes, no) => {
    resolve = yes
    reject = no
  })
  return { promise, resolve, reject }
}

test('a status reply for a replaced session does not change metrics or failover', async () => {
  const reply = deferred()
  const f = fixture(() => reply.promise)
  const pending = f.poll()
  const replacement = { status: 'connected', relayId: 'standby' }
  f.context.state.session = replacement
  reply.resolve({ state: 'degraded', mode: 'relay' })
  await pending
  assert.equal(f.context.state.session, replacement)
  assert.deepEqual(f.effects, [])
  assert.equal(f.context.sessionPollInFlight, false)
})

test('a late status failure cannot stop a replacement session', async () => {
  const reply = deferred()
  const commands = []
  const f = fixture((command) => {
    commands.push(command)
    return reply.promise
  })
  f.context.sessionPollFailures = 2
  const pending = f.poll()
  const replacement = { status: 'starting' }
  f.context.state.session = replacement
  reply.reject(new Error('old engine stopped'))
  await pending
  assert.equal(f.context.state.session, replacement)
  assert.deepEqual(commands, ['session-status'])
  assert.deepEqual(f.effects, [])
})

test('failed-session cleanup checks again after queued Start or Stop finishes', async () => {
  const commands = []
  const queued = deferred()
  const f = fixture(async (command) => {
    commands.push(command)
    throw new Error('old service request failed')
  })
  f.context.sessionPollFailures = 2
  let cleanup
  f.context.sessionExclusive = (work) => {
    cleanup = work
    return queued.promise
  }
  const pending = f.poll()
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(typeof cleanup, 'function')
  const replacement = { status: 'connected' }
  f.context.state.session = replacement
  await cleanup()
  queued.resolve()
  await pending
  assert.equal(f.context.state.session, replacement)
  assert.deepEqual(commands, ['session-status'])
  assert.deepEqual(f.effects, [])
})

test('three failed polls still clean up the session they belong to', async () => {
  const commands = []
  const f = fixture(async (command) => {
    commands.push(command)
    if (command === 'session-status') throw new Error('service unavailable')
  })
  await f.poll()
  await f.poll()
  assert.equal(f.context.state.session.status, 'connected')
  await f.poll()
  assert.equal(f.context.state.session.status, 'error')
  assert.deepEqual(commands, ['session-status', 'session-status', 'session-status', 'stop-session'])
  assert.deepEqual(f.effects, ['stop-polling', 'end'])
})
