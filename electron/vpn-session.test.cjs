const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')
const {
  VpnSessionController,
  VpnConfigError,
  VPN_POLL_MS,
  RECONNECT_DELAYS_MS,
  DEGRADED_RESTART_MS,
} = require('./vpn-session.cjs')
const { SERVICE_LEASE_MS, MAX_ANSWERED_FAILURES } = require('./session-lease.cjs')

const node = { id: 'vpn-node', name: 'Home', kind: 'wireguard' }
const request = {
  mode: 'direct',
  trafficMode: 'split',
  rules: [{ kind: 'application', value: 'C:\\Apps\\chat.exe' }],
  remoteDns: true,
  killSwitch: false,
  nodes: [{ kind: 'wireguard', config: '[Interface]', label: 'Home' }],
}
const connectedPaths = {
  paths: [{ route: 1, latencyMs: 42, lossPercent: 0, bytesSent: 10, bytesReceived: 20 }],
  userBytesSent: 10,
  userBytesReceived: 20,
}

function silentLogger() {
  const lines = []
  const sink = (prefix) => ({
    info: (message) => lines.push(`${prefix} info ${message}`),
    warn: (message) => lines.push(`${prefix} warn ${message}`),
    error: (message) => lines.push(`${prefix} error ${message}`),
    debug: () => {},
  })
  return { lines, scope: sink }
}

function fakeTimers() {
  const timeouts = []
  const intervals = []
  return {
    timeouts,
    intervals,
    setTimeout: (callback, delay) => {
      const timer = { callback, delay, cleared: false }
      timeouts.push(timer)
      return timer
    },
    clearTimeout: (timer) => {
      if (timer) timer.cleared = true
    },
    setInterval: (callback, delay) => {
      const timer = { callback, delay, cleared: false }
      intervals.push(timer)
      return timer
    },
    clearInterval: (timer) => {
      if (timer) timer.cleared = true
    },
    pendingTimeout: () => timeouts.find((timer) => !timer.cleared),
    /** Runs the pending timeout the way the clock would, once. */
    fire() {
      const timer = this.pendingTimeout()
      timer.cleared = true
      timer.callback()
    },
  }
}

/** A service that answers each command from a script, recording every call. */
function fakeService(script = {}) {
  const calls = []
  return {
    calls,
    ready: () => script.ready !== false,
    request: async (command, payload, timeout) => {
      calls.push({ command, payload, timeout })
      const answer = script[command]
      const value = typeof answer === 'function' ? answer(payload, calls) : answer
      if (value instanceof Error) throw value
      return value ?? {}
    },
  }
}

function harness({ script, pauseReason = () => null, buildRequest } = {}) {
  let clock = 1_000
  const timers = fakeTimers()
  const service = fakeService({
    'start-session': {
      paths: connectedPaths,
      capture: { backend: 'windivert', effectiveMtu: 1420, dnsServers: ['8.8.8.8'] },
    },
    'session-status': { ...connectedPaths, state: 'connected' },
    ...script,
  })
  const logger = silentLogger()
  const usage = {
    started: [],
    recorded: 0,
    start: (id, nodes) => usage.started.push([id, nodes]),
    record: () => (usage.recorded += 1),
  }
  const controller = new VpnSessionController({
    service,
    logger,
    buildRequest: buildRequest ?? (() => ({ request, node })),
    pauseReason,
    usage,
    timers,
    now: () => clock,
    randomId: () => 'abc123',
  })
  return { controller, service, timers, logger, usage, advance: (ms) => (clock += ms) }
}

test('connecting validates, starts in the vpn slot and begins renewing the lease', async () => {
  const { controller, service, timers, usage } = harness()
  await controller.connect()
  assert.deepEqual(
    service.calls.map((call) => call.command),
    ['validate-runtime', 'start-session'],
  )
  for (const call of service.calls) assert.equal(call.payload.slot, 'vpn')
  assert.equal(service.calls[1].payload.sessionId, 'vpn-abc123')
  const session = controller.snapshot()
  assert.equal(session.status, 'connected')
  assert.equal(session.metrics.latencyMs, 42)
  assert.equal(timers.intervals[0].delay, VPN_POLL_MS)
  assert.deepEqual(usage.started[0][0], 'vpn-abc123')
})

test('the lease poll leaves the service lease plenty of headroom', () => {
  const slot = fs.readFileSync(path.join(__dirname, '..', 'service', 'src', 'slot.rs'), 'utf8')
  const leaseSeconds = Number(slot.match(/const SESSION_LEASE: Duration = Duration::from_secs\((\d+)\)/)[1])
  // The client waits out exactly the lease the service enforces.
  assert.equal(SERVICE_LEASE_MS, leaseSeconds * 1000)
  assert.ok(VPN_POLL_MS * (MAX_ANSWERED_FAILURES + 2) <= SERVICE_LEASE_MS)
})

test('a configuration problem is reported and not retried', async () => {
  const { controller, timers } = harness({
    buildRequest: () => {
      throw new VpnConfigError('Add a VPN node first.')
    },
  })
  await controller.connect()
  assert.equal(controller.snapshot().status, 'error')
  assert.equal(controller.wanted, false)
  assert.equal(timers.pendingTimeout(), undefined)
})

test('a refused request is not retried either', async () => {
  const { controller, timers } = harness({ script: { 'validate-runtime': new Error('route 1: bad config') } })
  await controller.connect()
  assert.equal(controller.snapshot().message, 'route 1: bad config')
  assert.equal(timers.pendingTimeout(), undefined)
})

test('a check the busy service never answered is retried, not taken as a refusal', async () => {
  const timedOut = Object.assign(new Error('Network service request timed out'), { transient: true })
  const { controller, timers } = harness({ script: { 'validate-runtime': timedOut } })
  await controller.connect()
  assert.equal(controller.wanted, true)
  assert.equal(timers.pendingTimeout().delay, RECONNECT_DELAYS_MS[0])
})

test('a node that does not answer is retried with growing waits, then connects', async () => {
  let failures = 2
  const { controller, timers, service } = harness({
    script: {
      'start-session': () =>
        failures-- > 0
          ? new Error('no WireGuard handshake reply within 3 s')
          : { paths: connectedPaths, capture: { dnsServers: ['8.8.8.8'] } },
    },
  })
  await controller.connect()
  assert.equal(controller.snapshot().status, 'reconnecting')
  assert.equal(timers.pendingTimeout().delay, RECONNECT_DELAYS_MS[0])
  // A failed start is cleaned up, so the slot never keeps half a session.
  assert.equal(service.calls.at(-1).command, 'stop-session')

  timers.fire()
  await controller.queue
  assert.equal(timers.pendingTimeout().delay, RECONNECT_DELAYS_MS[1])

  timers.fire()
  await controller.queue
  assert.equal(controller.snapshot().status, 'connected')
  assert.equal(controller.reconnectAttempt, 0)
})

test('turning the VPN off stops it and cancels a pending retry', async () => {
  const { controller, timers, service } = harness({ script: { 'start-session': new Error('timeout') } })
  await controller.connect()
  const retry = timers.pendingTimeout()
  await controller.disconnect()
  assert.equal(retry.cleared, true)
  assert.equal(controller.snapshot().status, 'idle')
  assert.equal(controller.wanted, false)
  assert.equal(service.calls.filter((call) => call.command === 'start-session').length, 1)
})

test('the game taking all traffic pauses the VPN, and it resumes afterwards', async () => {
  let reason = null
  const { controller, service } = harness({ pauseReason: () => reason })
  await controller.connect()
  reason = 'game-all-traffic'
  await controller.reconsider()
  assert.equal(controller.snapshot().status, 'paused')
  assert.equal(controller.snapshot().pauseReason, 'game-all-traffic')
  assert.equal(service.calls.at(-1).command, 'stop-session')

  reason = null
  await controller.reconsider()
  assert.equal(controller.snapshot().status, 'connected')
  assert.equal(service.calls.filter((call) => call.command === 'start-session').length, 2)
})

test('a VPN asked for while the game holds all traffic waits instead of failing', async () => {
  const { controller, service } = harness({ pauseReason: () => 'game-all-traffic' })
  await controller.connect()
  assert.equal(controller.snapshot().status, 'paused')
  assert.equal(service.calls.length, 0)
})

test('the service pausing the slot itself is recognised from the status poll', async () => {
  const { controller } = harness({
    script: { 'session-status': new Error('no active network session (game-all-traffic)') },
  })
  await controller.connect()
  await controller.poll()
  assert.equal(controller.snapshot().status, 'paused')
})

test('an unanswered status keeps the VPN until the lease has run out, then reconnects', async () => {
  let fail = true
  const { controller, timers, advance, service } = harness({
    script: {
      'session-status': () =>
        fail
          ? Object.assign(new Error('Network service request timed out'), { transient: true })
          : { ...connectedPaths, state: 'connected' },
    },
  })
  await controller.connect()
  for (let elapsed = 6000; elapsed < SERVICE_LEASE_MS; elapsed += 6000) {
    advance(6000)
    await controller.poll()
    assert.equal(controller.snapshot().status, 'connected')
  }
  assert.equal(service.calls.filter((call) => call.command === 'stop-session').length, 0)
  advance(6000)
  await controller.poll()
  await controller.queue
  assert.equal(controller.snapshot().status, 'reconnecting')
  fail = false
  timers.fire()
  await controller.queue
  assert.equal(controller.snapshot().status, 'connected')
})

test('errors the service answers with are given up on after a few in a row', async () => {
  const { controller } = harness({ script: { 'session-status': new Error('native engine stopped unexpectedly') } })
  await controller.connect()
  for (let index = 1; index < MAX_ANSWERED_FAILURES; index += 1) {
    await controller.poll()
    assert.equal(controller.snapshot().status, 'connected')
  }
  await controller.poll()
  await controller.queue
  assert.equal(controller.snapshot().status, 'reconnecting')
})

test('a node degraded for too long is restarted; a brief drop is not', async () => {
  let healthy = false
  const { controller, advance, service } = harness({
    script: { 'session-status': () => ({ ...connectedPaths, state: healthy ? 'connected' : 'degraded' }) },
  })
  await controller.connect()
  await controller.poll()
  assert.equal(controller.snapshot().status, 'degraded')
  healthy = true
  await controller.poll()
  assert.equal(controller.snapshot().status, 'connected')

  healthy = false
  await controller.poll()
  advance(DEGRADED_RESTART_MS)
  await controller.poll()
  await controller.queue
  assert.equal(controller.snapshot().status, 'reconnecting')
  assert.equal(service.calls.filter((call) => call.command === 'stop-session').length, 1)
})

test('live rules go to the running vpn slot only in split mode', async () => {
  const { controller, service } = harness({ script: { 'update-session-rules': { targetCount: 2 } } })
  assert.equal(await controller.applyRules([], 'split'), null)
  await controller.connect()
  assert.equal(await controller.applyRules([{ kind: 'ip', value: '203.0.113.1' }], 'all'), null)
  const capture = await controller.applyRules([{ kind: 'ip', value: '203.0.113.1' }], 'split')
  assert.equal(capture.targetCount, 2)
  const update = service.calls.find((call) => call.command === 'update-session-rules')
  assert.equal(update.payload.slot, 'vpn')
})

test('waking from sleep retries a dropped VPN at once', async () => {
  const { controller, timers } = harness({ script: { 'start-session': new Error('unreachable') } })
  await controller.connect()
  const retry = timers.pendingTimeout()
  await controller.onResume()
  assert.equal(retry.cleared, true)
  assert.equal(controller.snapshot().status, 'reconnecting')
})

test('quitting stops the slot but keeps the wish to be connected', async () => {
  const { controller, service } = harness()
  await controller.connect()
  await controller.shutdown()
  assert.equal(service.calls.at(-1).command, 'stop-session')
  assert.equal(controller.wanted, true)
})

test('every log line carries the session id', async () => {
  const { controller, logger } = harness()
  await controller.connect()
  assert.ok(logger.lines.some((line) => line.startsWith('vpn vpn-abc123 info connected in')))
})

test('remote DNS setup failure stops the session before reporting connected or renewing it', async () => {
  const withoutDns = harness({ script: { 'start-session': { paths: connectedPaths, capture: {} } } })
  await withoutDns.controller.connect()
  assert.equal(withoutDns.controller.snapshot().status, 'reconnecting')
  assert.equal(withoutDns.service.calls.at(-1).command, 'stop-session')
  assert.ok(withoutDns.logger.lines.some((line) => line.includes('prevent local DNS fallback')))
  assert.deepEqual(withoutDns.usage.started, [])
  assert.equal(withoutDns.timers.intervals.length, 0)

  const withDns = harness({
    script: {
      'start-session': { paths: connectedPaths, capture: { backend: 'windivert', dnsServers: ['8.8.8.8'] } },
    },
  })
  await withDns.controller.connect()
  assert.equal(withDns.controller.snapshot().status, 'connected')
  const localDns = harness({
    script: { 'start-session': { paths: connectedPaths, capture: {} } },
    buildRequest: () => ({ request: { ...request, remoteDns: false }, node }),
  })
  await localDns.controller.connect()
  assert.equal(localDns.controller.snapshot().status, 'connected')
})

test('a poll answered after the VPN was turned off does not bring it back', async () => {
  let answer
  const { controller } = harness({
    script: { 'session-status': () => new Promise((resolve) => (answer = resolve)) },
  })
  await controller.connect()
  const polling = controller.poll()
  await controller.disconnect()
  answer({ ...connectedPaths, state: 'connected' })
  await polling
  assert.equal(controller.snapshot().status, 'idle')
  assert.equal(controller.snapshot().metrics, undefined)
})
