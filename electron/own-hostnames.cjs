const net = require('node:net')

const HOSTNAME = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/

/** The hostname in `host`, `host:port`; null for an address or anything else. */
function hostOf(value) {
  if (typeof value !== 'string') return null
  const match = value
    .trim()
    .toLowerCase()
    .match(/^([^:\s[\]]+?)\.?(?::\d+)?$/)
  if (!match || net.isIP(match[1])) return null
  return HOSTNAME.test(match[1]) ? match[1] : null
}

/**
 * Every hostname GamePath itself connects to: game nodes, relays and the VPN's
 * nodes. Neither session redirects lookups for these, so each tunnel resolves
 * its own servers exactly as it would with the other session off. Without it,
 * a game node resolved while the VPN was on got the VPN proxy's fake-IP answer,
 * and the game's route then ran through the VPN.
 */
function ownHostnames(state) {
  const candidates = [
    ...(state.tunnels ?? []).flatMap((tunnel) => [tunnel.endpoint, tunnel.host]),
    ...(state.relays ?? []).map((relay) => relay.address),
    ...(state.vpn?.nodes ?? [state.vpn?.node]).flatMap((node) => [node?.endpoint, node?.host]),
  ]
  return [...new Set(candidates.map(hostOf).filter(Boolean))].sort()
}

module.exports = { ownHostnames, hostOf }
