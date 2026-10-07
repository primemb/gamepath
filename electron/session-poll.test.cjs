const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')
const vm = require('node:vm')
const { SessionLease, SERVICE_LEASE_MS } = require('./session-lease.cjs')

// Run the actual main-process poll without launching Electron or its service.
const main = fs.readFileSync(path.join(__dirname, 'main.cjs'), 'utf8')
const start = main.indexOf('async function pollSessionStatus()')
const source = main.slice(start, main.indexOf('\n/**', start))

function fixture(request) {
  const effects = []
  const clock = { now: 1_000 }
  const context = vm.createContext({
    state: { session: { status: 'connected' } },
    serviceBridge: { status: { status: 'ready' }, request },
    sessionPollInFlight: false,
    sessionLease: new SessionLease(() => clock.now),
    lastRuntimeState: null,
    updateSessionMetrics: () => effects.push('metrics'),
    recordUsage: () => effects.push('usage'),
    relayFailover: { observe: () => effects.push('observe'), end: () => effects.push('end') },
    stopSessionKeepAlive: () => effects.push('stop-polling'),
    logger: { warn() {}, info() {}, error() {} },
    sessionExclusive: async (work) => work(),
  })
  vm.runInContext(source, context)
  return { context, effects, clock, poll: () => context.pollSessionStatus() }
}

/** Two answered errors: the next one gives the session up. */
function failTwice(lease) {
  lease.failed(new Error('engine error'))
  lease.failed(new Error('engine error'))
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
  failTwice(f.context.sessionLease)
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
  failTwice(f.context.sessionLease)
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

const timedOut = () => Object.assign(new Error('Network service request timed out'), { transient: true })

test('a service that does not answer keeps the session until its lease has run out', async () => {
  const commands = []
  const f = fixture(async (command) => {
    commands.push(command)
    if (command === 'session-status') throw timedOut()
  })
  // Observed live: about 35 s of silence while every path kept carrying the game.
  for (let elapsed = 6000; elapsed < SERVICE_LEASE_MS; elapsed += 6000) {
    f.clock.now += 6000
    await f.poll()
    assert.equal(f.context.state.session.status, 'connected')
  }
  assert.ok(!commands.includes('stop-session'))
  f.clock.now += 6000
  await f.poll()
  assert.equal(f.context.state.session.status, 'error')
  assert.equal(commands.at(-1), 'stop-session')
})

test('an answer after a silence restarts the lease window', async () => {
  let fail = true
  const f = fixture(async () => {
    if (fail) throw timedOut()
    return { state: 'connected', mode: 'relay' }
  })
  f.clock.now += SERVICE_LEASE_MS - 1000
  await f.poll()
  fail = false
  await f.poll()
  fail = true
  f.clock.now += SERVICE_LEASE_MS - 1000
  await f.poll()
  assert.equal(f.context.state.session.status, 'connected')
})

test('a service that refuses the connection is given up on quickly', async () => {
  const f = fixture(async () => {
    throw Object.assign(new Error('Network service unavailable: connect ECONNREFUSED'), {
      transient: true,
      code: 'ECONNREFUSED',
    })
  })
  await f.poll()
  await f.poll()
  assert.equal(f.context.state.session.status, 'connected')
  await f.poll()
  assert.equal(f.context.state.session.status, 'error')
})
