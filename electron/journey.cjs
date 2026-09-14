'use strict'

/**
 * Chooses the route described by the journey panel.
 *
 * `latencyMs` is an RTT measured by a GamePath probe that travels through the
 * selected VPN/proxy path and reaches our relay. A transport setup time is
 * deliberately not used here: WireGuard, OpenVPN, L2TP/IPsec, and SOCKS negotiation can
 * take seconds because of retries and server work, and is not a live latency
 * measurement. We also cannot honestly split this RTT into user-to-node and
 * node-to-relay without an agent running on the user's VPN node.
 *
 * @param {object} input
 * @param {Array<object>} input.paths per-route status from the engine
 * @param {Array<number>} input.selectedRoutes routes currently carrying traffic
 */
function deriveJourney({ paths = [], selectedRoutes = [] } = {}) {
  const usable = paths.filter((path) => path.reachable && path.latencyMs != null)
  // Prefer the route carrying traffic. Falling back to a reachable route is
  // useful during startup before the scheduler has made its first choice.
  const route = usable.find((path) => selectedRoutes.includes(path.route)) ?? usable[0] ?? null
  if (!route) {
    return { route: null, label: null, kind: null, probeRttMs: null }
  }

  return {
    route: route.route,
    label: route.label ?? null,
    kind: route.pathKind ?? null,
    probeRttMs: route.latencyMs,
  }
}

module.exports = { deriveJourney }
