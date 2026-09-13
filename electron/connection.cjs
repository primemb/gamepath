/**
 * Rules about what a connection mode can be started with.
 *
 * These live apart from the Electron main process so they can be exercised
 * directly, and so the renderer and the main process agree on one answer.
 */

/**
 * The only node a direct session can use, or null with the reason why not.
 *
 * Direct mode has no relay to combine paths at or to reach a proxy through, so
 * both limits are checked in one place and each answer names the way out
 * rather than only stating what is wrong.
 *
 * @param {{ name: string, kind: string }[]} enabledTunnels
 * @returns {{ node: object | null, error: string | null }}
 */
function directNodeSelection(enabledTunnels) {
  if (!enabledTunnels.length) {
    return { node: null, error: 'Choose the WireGuard or OpenVPN node that will carry your traffic.' }
  }
  if (enabledTunnels.length > 1) {
    return {
      node: null,
      error: `Direct mode sends traffic through one node, but ${enabledTunnels.length} are selected. Choose a single WireGuard or OpenVPN node, or switch to relay mode to combine them.`,
    }
  }
  const [node] = enabledTunnels
  if (node.kind === 'socks5') {
    return {
      node: null,
      error: `${node.name} is a SOCKS5 proxy, which needs a relay to forward to. Choose a WireGuard or OpenVPN node for direct mode, or set up a relay.`,
    }
  }
  return { node, error: null }
}

/**
 * The node a session should keep selected after switching into direct mode.
 *
 * Switching modes changes what a selected node means, so an already enabled
 * tunnelling node is kept if there is one, and otherwise the first that could
 * work is offered — leaving the user with a usable starting point instead of
 * an empty selection.
 *
 * @param {{ id: string, kind: string, enabled: boolean }[]} tunnels
 * @returns {string | null}
 */
function directSelectionAfterSwitch(tunnels) {
  const usable = (tunnel) => tunnel.kind === 'wireguard' || tunnel.kind === 'openvpn'
  const chosen = tunnels.find((tunnel) => tunnel.enabled && usable(tunnel)) ?? tunnels.find(usable)
  return chosen?.id ?? null
}

module.exports = { directNodeSelection, directSelectionAfterSwitch }
