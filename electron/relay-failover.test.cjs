const test = require('node:test')
const assert = require('node:assert/strict')
const {
  DIRECT_FAILURES_REQUIRED,
  DIRECT_PROBE_INTERVAL_MS,
  OUTAGE_WITHOUT_WITNESS_MS,
  OUTAGE_WITH_WITNESS_MS,
  RELAY_ALIVE_HOLD_MS,
  RelayFailoverController,
  RelayFailoverWatch,
  normalizeRelayFailover,
  standbyRelayFor,
} = require('./relay-failover.cjs')

const POLL_MS = 3000

/** A watch that saw a healthy session and, if asked, a direct probe answered. */
function healthyWatch({ directWitness }) {
  const watch = new RelayFailoverWatch()
  const first = watch.observe({ connected: true, uplink: 'up', now: 0 })
  assert.equal(first.action, 'probe-baseline')
  watch.noteBaseline(directWitness)
  return watch
}

/** Polls an outage every POLL_MS from `from` for `duration`, answering direct probes with `reachable`. */
function runOutage(watch, { from = POLL_MS, duration, uplink = 'up', reachable = false }) {
  const actions = []
  for (let now = from; now <= from + duration; now += POLL_MS) {
    const { action, epoch } = watch.observe({ connected: false, uplink, now })
    actions.push(action)
    if (action === 'probe-outage') watch.noteOutageProbe(reachable, epoch, now)
    if (action === 'failover') return { actions, failedOverAt: now - from }
  }
  return { actions, failedOverAt: null }
}

test('a freeze the relay comes back from never moves the session', () => {
  const watch = healthyWatch({ directWitness: true })
  // The longest freeze measured on a real overloaded host was 21 s.
  const { failedOverAt } = runOutage(watch, { duration: 21_000 })
  assert.equal(failedOverAt, null)
  assert.equal(watch.observe({ connected: true, uplink: 'up', now: 30_000 }).action, 'none')
  assert.equal(runOutage(watch, { from: 33_000, duration: 21_000 }).failedOverAt, null)
})

test('a relay that stays silent everywhere is moved away from once the witnesses agree', () => {
  const watch = healthyWatch({ directWitness: true })
  const { actions, failedOverAt } = runOutage(watch, { duration: 60_000 })
  assert.ok(failedOverAt >= OUTAGE_WITH_WITNESS_MS, `moved after ${failedOverAt} ms`)
  assert.ok(failedOverAt < OUTAGE_WITH_WITNESS_MS + DIRECT_PROBE_INTERVAL_MS)
  assert.ok(actions.filter((action) => action === 'probe-outage').length >= DIRECT_FAILURES_REQUIRED)
})

test('one direct answer proves the relay is alive and starts the clock again', () => {
  const watch = healthyWatch({ directWitness: true })
  const { failedOverAt } = runOutage(watch, { duration: 120_000, reachable: true })
  assert.equal(failedOverAt, null)
})

test('once the relay answers directly, it is left alone for a while', () => {
  const watch = healthyWatch({ directWitness: true })
  const { actions } = runOutage(watch, { duration: RELAY_ALIVE_HOLD_MS + 10_000, reachable: true })
  const probes = actions.filter((action) => action === 'probe-outage').length
  // One probe found it alive; the next waits out the hold.
  assert.equal(probes, 2)
})

test('a local connection in doubt is never blamed on the relay', () => {
  for (const uplink of ['down', 'unknown']) {
    const watch = healthyWatch({ directWitness: true })
    assert.equal(runOutage(watch, { duration: 120_000, uplink }).failedOverAt, null)
  }
})

test('the uplink wavering partway through restarts the outage', () => {
  const watch = healthyWatch({ directWitness: true })
  runOutage(watch, { duration: 24_000 })
  assert.equal(watch.observe({ connected: false, uplink: 'unknown', now: 30_000 }).action, 'none')
  const { failedOverAt } = runOutage(watch, { from: 33_000, duration: 60_000 })
  assert.ok(failedOverAt >= OUTAGE_WITH_WITNESS_MS)
})

test('without a direct path to the relay, silence has to last twice as long', () => {
  const watch = healthyWatch({ directWitness: false })
  const { actions, failedOverAt } = runOutage(watch, { duration: 120_000 })
  assert.ok(failedOverAt >= OUTAGE_WITHOUT_WITNESS_MS, `moved after ${failedOverAt} ms`)
  // Probing a relay this machine has never reached directly proves nothing.
  assert.ok(!actions.includes('probe-outage'))
})

test('a session that never carried traffic is still starting, not failed', () => {
  const watch = new RelayFailoverWatch()
  for (let now = 0; now <= 120_000; now += POLL_MS) {
    assert.equal(watch.observe({ connected: false, uplink: 'up', now }).action, 'none')
  }
})

test('a probe answer from an earlier outage does not count toward this one', () => {
  const watch = healthyWatch({ directWitness: true })
  const stale = watch.observe({ connected: false, uplink: 'up', now: 3000 })
  assert.equal(stale.action, 'probe-outage')
  watch.observe({ connected: true, uplink: 'up', now: 6000 })
  watch.noteOutageProbe(false, stale.epoch, 6000)
  assert.equal(watch.directFailures, 0)
})

test('a finished watch never asks for a second move', () => {
  const watch = healthyWatch({ directWitness: true })
  watch.finish()
  assert.equal(runOutage(watch, { duration: 120_000 }).failedOverAt, null)
})

test('the standby is the chosen relay, or the first other one that is set up', () => {
  const relays = [
    { id: 'main', address: '1.1.1.1' },
    { id: 'same-host', address: '1.1.1.1' },
    { id: 'unenrolled', address: '2.2.2.2' },
    { id: 'first', address: '3.3.3.3' },
    { id: 'second', address: '4.4.4.4' },
  ]
  const hasToken = (id) => id !== 'unenrolled'
  assert.equal(standbyRelayFor(relays, hasToken, 'main', null).id, 'first')
  assert.equal(standbyRelayFor(relays, hasToken, 'main', 'second').id, 'second')
  assert.equal(standbyRelayFor(relays, hasToken, 'main', 'unenrolled'), null)
  assert.equal(standbyRelayFor(relays, hasToken, 'main', 'main'), null)
  assert.equal(standbyRelayFor([relays[0]], hasToken, 'main', null), null)
})

test('the setting is off unless it was explicitly turned on', () => {
  assert.deepEqual(normalizeRelayFailover(undefined), { enabled: false, standbyRelayId: null })
  assert.deepEqual(normalizeRelayFailover({ enabled: 'yes', standbyRelayId: '' }), {
    enabled: false,
    standbyRelayId: null,
  })
  assert.deepEqual(normalizeRelayFailover({ enabled: true, standbyRelayId: 'b' }), {
    enabled: true,
    standbyRelayId: 'b',
  })
})

const settle = () => new Promise((resolve) => setImmediate(resolve))

function controllerHarness({ mainAnswers, moveOutcome = 'moved' }) {
  let clock = 0
  const moves = []
  let probes = 0
  const controller = new RelayFailoverController({
    probeMainRelay: async () => {
      probes += 1
      return mainAnswers(clock)
    },
    moveToStandby: async (details) => {
      moves.push(details)
      return typeof moveOutcome === 'function' ? moveOutcome(moves.length) : moveOutcome
    },
    logger: { error() {} },
    now: () => clock,
  })
  const poll = async (state, uplink = 'up') => {
    controller.observe({ state, uplink })
    await settle()
    clock += POLL_MS
  }
  return { controller, moves, probeCount: () => probes, poll, advance: (ms) => (clock += ms) }
}

test('the controller moves a gone relay exactly once and reports why', async () => {
  const harness = controllerHarness({ mainAnswers: (now) => now === 0 })
  harness.controller.begin(true)
  await harness.poll('connected')
  for (let step = 0; step < 40; step += 1) await harness.poll('connecting')
  assert.equal(harness.moves.length, 1)
  assert.equal(harness.moves[0].directWitness, true)
  assert.ok(harness.moves[0].silentMs >= OUTAGE_WITH_WITNESS_MS)
})

test('a dead standby is retried only after a whole new outage has been measured', async () => {
  const harness = controllerHarness({
    mainAnswers: (now) => now === 0,
    moveOutcome: (attempt) => (attempt === 1 ? 'standby-down' : 'moved'),
  })
  harness.controller.begin(true)
  await harness.poll('connected')
  for (let step = 0; step < 12; step += 1) await harness.poll('connecting')
  assert.equal(harness.moves.length, 1)
  // The next attempt needs the full wait again, not the next poll.
  for (let step = 0; step < 5; step += 1) await harness.poll('connecting')
  assert.equal(harness.moves.length, 1)
  for (let step = 0; step < 12; step += 1) await harness.poll('connecting')
  assert.equal(harness.moves.length, 2)
})

test('a session started with the setting off is never moved', async () => {
  const harness = controllerHarness({ mainAnswers: () => false })
  harness.controller.begin(false)
  await harness.poll('connected')
  for (let step = 0; step < 40; step += 1) await harness.poll('connecting')
  assert.equal(harness.moves.length, 0)
  assert.equal(harness.probeCount(), 0)
})

test('a relay that still answers directly keeps its session through any outage', async () => {
  const harness = controllerHarness({ mainAnswers: () => true })
  harness.controller.begin(true)
  await harness.poll('connected')
  for (let step = 0; step < 60; step += 1) await harness.poll('connecting')
  assert.equal(harness.moves.length, 0)
})
