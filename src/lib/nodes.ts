import type { NodeGroup, NodeKind, Tunnel } from '../types'

export const nodeKindLabels: Record<NodeKind, string> = {
  wireguard: 'WireGuard',
  openvpn: 'OpenVPN',
  l2tp: 'L2TP/IPsec',
  socks5: 'SOCKS5',
}

/**
 * Whether a node is currently carrying traffic.
 *
 * This is the same rule the main process applies when a session starts: the
 * node's own switch and its group's switch both have to be on. Keeping it in
 * one place is what stops a card from reading "Enabled" while the engine has
 * quietly left it out.
 */
export const isNodeActive = (tunnel: Tunnel, groups: NodeGroup[]) =>
  tunnel.enabled && (!tunnel.groupId || groups.some((group) => group.id === tunnel.groupId && group.enabled))

export const activeNodes = (tunnels: Tunnel[], groups: NodeGroup[]) =>
  tunnels.filter((tunnel) => isNodeActive(tunnel, groups))

/** A group's nodes are those pointed at it; `null` collects the ungrouped ones. */
export const nodesInGroup = (tunnels: Tunnel[], groupId: string | null) =>
  tunnels.filter((tunnel) => (tunnel.groupId ?? null) === groupId)

export type NodeSection = {
  /** Null for the ungrouped section, which has no switch and cannot be removed. */
  group: NodeGroup | null
  nodes: Tunnel[]
  activeCount: number
}

/**
 * The node list as the Routes screen shows it: one section per group, with
 * whatever is left over gathered under a final ungrouped section.
 *
 * Empty groups are kept — a group the user just created has nothing in it yet,
 * and a section that disappears until it is filled is a confusing place to
 * drop the first node into.
 */
export function nodeSections(tunnels: Tunnel[], groups: NodeGroup[]): NodeSection[] {
  const sections: NodeSection[] = groups.map((group) => {
    const nodes = nodesInGroup(tunnels, group.id)
    return { group, nodes, activeCount: nodes.filter((node) => isNodeActive(node, groups)).length }
  })
  const ungrouped = nodesInGroup(tunnels, null)
  if (ungrouped.length) {
    sections.push({
      group: null,
      nodes: ungrouped,
      activeCount: ungrouped.filter((node) => node.enabled).length,
    })
  }
  return sections
}
