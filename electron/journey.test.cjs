const assert = require('node:assert/strict')
const test = require('node:test')

const { deriveJourney } = require('./journey.cjs')

/** The two routes from a real session: WireGuard and OpenVPN-over-TCP. */
function wireguard(overrides = {}) {
  return {
    route: 1,
    label: 'X2150294_TURKY1',
    pathKind: 'wireguard',
    reachable: true,
    latencyMs: 69,
    handshakeMs: 51,
    handshakeRoundTrips: 1,
    ...overrides,
  }
}

function openvpn(overrides = {}) {
  return {
    route: 2,
    label: 'tr2.e-mix.ir',
    pathKind: 'openvpn',
    reachable: true,
    latencyMs: 66,
    // Five round trips of TCP connect, TLS and PUSH_REPLY.
    handshakeMs: 329,
    handshakeRoundTrips: null,
    ...overrides,
  }
}

test('a one-round-trip handshake estimates the hop out to the node', () => {
  const journey = deriveJourney({ paths: [wireguard()], selectedRoutes: [1] })
  assert.equal(journey.estimable, true)
  assert.equal(journey.userToNodeMs, 51)
  assert.equal(journey.nodeToRelayMs, 18)
})

test('a SOCKS5 handshake is divided by its three round trips', () => {
  const socks = {
    route: 1,
    label: 'proxy',
    pathKind: 'socks5',
    reachable: true,
    latencyMs: 80,
    handshakeMs: 90,
    handshakeRoundTrips: 3,
  }
  const journey = deriveJourney({ paths: [socks], selectedRoutes: [1] })
  assert.equal(journey.userToNodeMs, 30)
  assert.equal(journey.nodeToRelayMs, 50)
})

test('an OpenVPN handshake yields no hop estimate at all', () => {
  const journey = deriveJourney({ paths: [openvpn()], selectedRoutes: [2] })
  // Reporting 329 ms as a hop is what made a healthy 66 ms path look broken.
  assert.equal(journey.estimable, false)
  assert.equal(journey.userToNodeMs, null)
  assert.equal(journey.nodeToRelayMs, null)
  assert.equal(journey.kind, 'openvpn')
})

test('the breakdown stays on the carrying route when another is faster', () => {
  // The OpenVPN route has the lower latency, so "fastest" would pick it and the
  // panel would swap subject every time jitter moved the two past each other.
  const paths = [wireguard(), openvpn()]
  const journey = deriveJourney({ paths, selectedRoutes: [1] })
  assert.equal(journey.route, 1)
  assert.equal(journey.label, 'X2150294_TURKY1')
  assert.equal(journey.userToNodeMs, 51)
})

test('jitter between two close routes does not change which one is described', () => {
  const described = []
  for (const [wireguardMs, openvpnMs] of [
    [69, 66],
    [66, 69],
    [67, 67],
    [71, 64],
  ]) {
    const journey = deriveJourney({
      paths: [wireguard({ latencyMs: wireguardMs }), openvpn({ latencyMs: openvpnMs })],
      selectedRoutes: [1],
    })
    described.push(journey.route)
  }
  assert.deepEqual(described, [1, 1, 1, 1])
})

test('a remainder that would be negative is reported as unavailable, not zero', () => {
  // A handshake longer than the measured round trip means the two numbers are
  // not comparable. Clamping showed the node as sitting on top of the relay.
  const slowHandshake = wireguard({ latencyMs: 40, handshakeMs: 120, handshakeRoundTrips: 1 })
  const journey = deriveJourney({ paths: [slowHandshake], selectedRoutes: [1] })
  assert.equal(journey.nodeToRelayMs, null, 'a negative remainder is not a measurement')
})

test('a direct session has no relay leg to report', () => {
  const journey = deriveJourney({ paths: [wireguard()], selectedRoutes: [1], direct: true })
  assert.equal(journey.userToNodeMs, 51)
  assert.equal(journey.nodeToRelayMs, null)
})

test('an unreachable route is never described', () => {
  const journey = deriveJourney({
    paths: [wireguard({ reachable: false }), openvpn()],
    selectedRoutes: [1],
  })
  assert.equal(journey.route, 2)
})

test('before the scheduler has picked, any reachable route is described', () => {
  const journey = deriveJourney({ paths: [wireguard(), openvpn()], selectedRoutes: [] })
  assert.equal(journey.route, 1)
})

test('no reachable route yields nulls rather than throwing', () => {
  for (const paths of [[], [wireguard({ reachable: false })], [wireguard({ latencyMs: null })]]) {
    const journey = deriveJourney({ paths, selectedRoutes: [1] })
    assert.equal(journey.route, null)
    assert.equal(journey.userToNodeMs, null)
    assert.equal(journey.nodeToRelayMs, null)
    assert.equal(journey.estimable, false)
  }
  assert.doesNotThrow(() => deriveJourney())
})
