'use strict'

/**
 * Splits a session's measured round trip into the legs the UI shows.
 *
 * Two rules keep this honest, and both exist because breaking them produced
 * numbers that looked like network faults and were not:
 *
 * - **A handshake is only a hop estimate when its round-trip count is fixed.**
 *   WireGuard's handshake is one round trip, so it doubles as the hop out to
 *   the node. SOCKS5 costs three. OpenVPN negotiates TLS and its count depends
 *   on the server, so nothing is derived from it — reporting a five-round-trip
 *   negotiation as one hop is how a healthy 66 ms path reads as 329 ms.
 * - **The breakdown names one route and stays on it.** Following whichever
 *   route is fastest right now makes the panel swap subject whenever two routes
 *   are within their own jitter, which reads as a spike that never happened.
 */

/**
 * @param {object} input
 * @param {Array<object>} input.paths per-route status from the engine
 * @param {Array<number>} input.selectedRoutes routes currently carrying traffic
 * @param {boolean} input.direct a direct session has no relay leg
 */
function deriveJourney({ paths = [], selectedRoutes = [], direct = false } = {}) {
  const usable = paths.filter((path) => path.reachable && path.latencyMs != null)
  // The route carrying traffic, falling back to any reachable one before the
  // scheduler has picked.
  const route = usable.find((path) => selectedRoutes.includes(path.route)) ?? usable[0] ?? null
  if (!route) {
    return { route: null, label: null, kind: null, estimable: false, userToNodeMs: null, nodeToRelayMs: null }
  }

  const estimable = route.handshakeMs != null && Boolean(route.handshakeRoundTrips)
  const userToNodeMs = estimable ? route.handshakeMs / route.handshakeRoundTrips : null
  // Only a positive remainder is a measurement. A negative one means the two
  // numbers are not comparable, and clamping it to zero would show the node as
  // sitting on top of the relay.
  const remainder = !direct && userToNodeMs != null ? route.latencyMs - userToNodeMs : null
  const nodeToRelayMs = remainder != null && remainder > 0 ? remainder : null

  return {
    route: route.route,
    label: route.label ?? null,
    kind: route.pathKind ?? null,
    estimable,
    userToNodeMs,
    nodeToRelayMs,
  }
}

module.exports = { deriveJourney }
