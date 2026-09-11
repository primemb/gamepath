const assert = require('node:assert/strict')
const test = require('node:test')

const { deriveJourney } = require('./journey.cjs')

function route(overrides = {}) {
  return {
    route: 1,
    label: 'X2150294_TURKY1',
    pathKind: 'wireguard',
    reachable: true,
    latencyMs: 69,
    handshakeMs: 5_082,
    handshakeRoundTrips: 1,
    ...overrides,
  }
}

test('uses the GamePath probe RTT, never a transport setup time', () => {
  const journey = deriveJourney({ paths: [route()], selectedRoutes: [1] })
  assert.equal(journey.route, 1)
  assert.equal(journey.probeRttMs, 69)
  assert.equal(journey.probeRttMs, route().latencyMs)
  assert.notEqual(journey.probeRttMs, route().handshakeMs)
})

test('the journey stays on the carrying route when another is faster', () => {
  const carrying = route({ route: 1, latencyMs: 69 })
  const faster = route({ route: 2, label: 'backup', latencyMs: 41 })
  const journey = deriveJourney({ paths: [carrying, faster], selectedRoutes: [1] })
  assert.equal(journey.route, 1)
  assert.equal(journey.probeRttMs, 69)
})

test('falls back to a measurable route before the scheduler has picked one', () => {
  const journey = deriveJourney({ paths: [route()], selectedRoutes: [] })
  assert.equal(journey.route, 1)
  assert.equal(journey.probeRttMs, 69)
})

test('an unreachable or unmeasured route is not described', () => {
  for (const paths of [[], [route({ reachable: false })], [route({ latencyMs: null })]]) {
    const journey = deriveJourney({ paths, selectedRoutes: [1] })
    assert.equal(journey.route, null)
    assert.equal(journey.probeRttMs, null)
  }
})
