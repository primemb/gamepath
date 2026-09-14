/**
 * Rules about what a connection mode can be started with.
 *
 * These live apart from the Electron main process so they can be exercised
 * directly, and so the renderer and the main process agree on one answer.
 */

/**
 * The nodes that will actually carry traffic.
 *
 * A node is only carrying when it is switched on itself *and* its group is,
 * which is what lets one group switch stand in for every node inside it. An
 * ungrouped node answers to its own switch alone.
 *
 * @param {{ enabled: boolean, groupId?: string | null }[]} tunnels
 * @param {{ id: string, enabled: boolean }[]} groups
 */
function activeTunnels(tunnels, groups = []) {
  const enabledGroupIds = new Set(groups.filter((group) => group.enabled).map((group) => group.id))
  return tunnels.filter((tunnel) => tunnel.enabled && (!tunnel.groupId || enabledGroupIds.has(tunnel.groupId)))
}

/**
 * Restores direct mode's one-node rule after a change that could have broken it.
 *
 * Switching a group on can wake several nodes at once, which direct mode
 * cannot start with. Rather than refusing the switch, the selection is
 * narrowed to a single node — `preferredId` when it is among them, so a node
 * the user just chose is the one that survives.
 *
 * @param {{ id: string, enabled: boolean, groupId?: string | null }[]} tunnels
 * @param {{ id: string, enabled: boolean }[]} groups
 * @param {string | null} preferredId
 */
function enforceDirectSelection(tunnels, groups = [], preferredId = null) {
  const active = activeTunnels(tunnels, groups)
  if (active.length <= 1) return
  const keep = active.find((tunnel) => tunnel.id === preferredId) ?? active[0]
  for (const tunnel of active) if (tunnel.id !== keep.id) tunnel.enabled = false
}

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
    return { node: null, error: 'Choose the WireGuard, OpenVPN or L2TP node that will carry your traffic.' }
  }
  if (enabledTunnels.length > 1) {
    return {
      node: null,
      error: `Direct mode sends traffic through one node, but ${enabledTunnels.length} are selected. Choose a single tunnelling node, or switch to relay mode to combine them.`,
    }
  }
  const [node] = enabledTunnels
  if (node.kind === 'socks5') {
    return {
      node: null,
      error: `${node.name} is a SOCKS5 proxy, which needs a relay to forward to. Choose a WireGuard, OpenVPN or L2TP node for direct mode, or set up a relay.`,
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
 * an empty selection. A node inside a switched-off group is the last resort,
 * since choosing it would land the user on a selection that cannot start.
 *
 * @param {{ id: string, kind: string, enabled: boolean, groupId?: string | null }[]} tunnels
 * @param {{ id: string, enabled: boolean }[]} groups
 * @returns {string | null}
 */
function directSelectionAfterSwitch(tunnels, groups = []) {
  const enabledGroupIds = new Set(groups.filter((group) => group.enabled).map((group) => group.id))
  const usable = (tunnel) => tunnel.kind !== 'socks5'
  const reachable = (tunnel) => !tunnel.groupId || enabledGroupIds.has(tunnel.groupId)
  const chosen =
    tunnels.find((tunnel) => tunnel.enabled && usable(tunnel) && reachable(tunnel)) ??
    tunnels.find((tunnel) => usable(tunnel) && reachable(tunnel)) ??
    tunnels.find((tunnel) => tunnel.enabled && usable(tunnel)) ??
    tunnels.find(usable)
  return chosen?.id ?? null
}

module.exports = { activeTunnels, enforceDirectSelection, directNodeSelection, directSelectionAfterSwitch }
