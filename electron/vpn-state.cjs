'use strict'

/**
 * The VPN's saved settings: saved nodes, its own split rules, and whether the
 * user wants it on. Pure functions over plain objects, so every rule here is
 * tested without Electron.
 *
 * Node secrets live separately in `state.encryptedVpnConfigs`,
 * which `publicState()` strips with every other `encrypted*` field.
 */

const RULE_KINDS = ['application', 'folder', 'hostname', 'ip']
const NODE_KINDS = ['wireguard', 'openvpn', 'l2tp', 'socks5']

function defaultVpn() {
  return {
    nodes: [],
    selectedNodeId: null,
    trafficMode: 'split',
    // On for the same reason as the game's: a filtered resolver poisons the
    // names of exactly the sites the VPN is for.
    remoteDns: true,
    killSwitch: false,
    rules: [],
    wantConnected: false,
  }
}

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)

function normalizeRule(rule) {
  if (!isObject(rule) || !RULE_KINDS.includes(rule.kind)) return null
  const value = typeof rule.value === 'string' ? rule.value.trim() : ''
  if (!value || typeof rule.id !== 'string' || !rule.id) return null
  return {
    id: rule.id,
    kind: rule.kind,
    value,
    label: typeof rule.label === 'string' && rule.label ? rule.label : value,
    enabled: rule.enabled !== false,
  }
}

/** Whatever was saved, a usable VPN state. Never throws. */
function normalizeVpn(saved) {
  const vpn = defaultVpn()
  if (!isObject(saved)) return vpn
  const candidates = Array.isArray(saved.nodes) ? saved.nodes : [saved.node]
  const nodeIds = new Set()
  for (const node of candidates) {
    if (
      !isObject(node) ||
      !NODE_KINDS.includes(node.kind) ||
      typeof node.id !== 'string' ||
      !node.id ||
      nodeIds.has(node.id)
    )
      continue
    nodeIds.add(node.id)
    vpn.nodes.push({ ...node })
  }
  vpn.selectedNodeId = nodeIds.has(saved.selectedNodeId)
    ? saved.selectedNodeId
    : (vpn.nodes.find((node) => node.enabled !== false)?.id ?? vpn.nodes[0]?.id ?? null)
  vpn.nodes = vpn.nodes.map((node) => ({ ...node, enabled: node.id === vpn.selectedNodeId }))
  if (saved.trafficMode === 'all') vpn.trafficMode = 'all'
  if (saved.remoteDns === false) vpn.remoteDns = false
  if (saved.killSwitch === true) vpn.killSwitch = true
  if (Array.isArray(saved.rules)) {
    const seen = new Set()
    for (const rule of saved.rules.map(normalizeRule)) {
      if (rule && !seen.has(rule.id)) {
        seen.add(rule.id)
        vpn.rules.push(rule)
      }
    }
  }
  vpn.wantConnected = saved.wantConnected === true && vpn.selectedNodeId !== null
  return vpn
}

function selectedVpnNode(vpn) {
  return vpn.nodes.find((node) => node.id === vpn.selectedNodeId) ?? null
}

/** Move the original single-node save without decrypting or exposing it. */
function migrateVpnState(state) {
  const legacyId = state.vpn?.node?.id
  state.vpn = normalizeVpn(state.vpn)
  const stored = isObject(state.encryptedVpnConfigs) ? state.encryptedVpnConfigs : {}
  state.encryptedVpnConfigs = Object.fromEntries(
    state.vpn.nodes.filter((node) => typeof stored[node.id] === 'string').map((node) => [node.id, stored[node.id]]),
  )
  if (state.vpn.nodes.some((node) => node.id === legacyId) && typeof state.encryptedVpnConfig === 'string') {
    state.encryptedVpnConfigs[legacyId] ??= state.encryptedVpnConfig
  }
  delete state.encryptedVpnConfig
}

/** The rule list the service compiles. */
function vpnRuleSpecs(vpn) {
  return vpn.rules.filter((rule) => rule.enabled).map(({ kind, value }) => ({ kind, value }))
}

/**
 * Why `kind`/`value` cannot be routed by `node` in `trafficMode`, or null.
 *
 * L2TP/IPsec is routed by Windows itself, and Windows routes cannot tell one
 * application from another or follow a wildcard name. Saying so when the rule
 * is added beats a session that fails to start.
 */
function ruleLimitation(node, trafficMode, kind, value) {
  if (node?.kind !== 'l2tp' || trafficMode !== 'split') return null
  if (kind === 'application' || kind === 'folder') {
    return 'An L2TP/IPsec VPN routes by address, so it cannot select applications or folders. Use a website or IP target, all-traffic mode, or a WireGuard/OpenVPN node.'
  }
  if (kind === 'hostname' && value.startsWith('*.')) {
    return 'An L2TP/IPsec VPN cannot follow wildcard names. Use an exact hostname or an IP range.'
  }
  return null
}

/** Rules of the saved set that the current node cannot route. */
function unroutableRules(vpn) {
  return vpn.rules.filter(
    (rule) => rule.enabled && ruleLimitation(selectedVpnNode(vpn), vpn.trafficMode, rule.kind, rule.value),
  )
}

function createRule(input, id) {
  const kind = input?.kind
  if (!RULE_KINDS.includes(kind)) throw new Error('Choose what kind of target this is')
  const value = String(input?.value ?? '').trim()
  if (!value) throw new Error('A target is required')
  const label = String(input?.label ?? '').trim()
  return { id, kind, value, label: label || value.split(/[\\/]/).pop() || value, enabled: true }
}

const sameTarget = (left, right) =>
  left.kind === right.kind && left.value.toLocaleLowerCase() === right.value.toLocaleLowerCase()

const insideFolder = (application, folder) => {
  const prefix = folder.value.toLocaleLowerCase().replace(/[\\/]+$/, '')
  return application.value.toLocaleLowerCase().startsWith(`${prefix}\\`)
}

/**
 * VPN rules the game would take first. The game's capture sees every packet
 * before the VPN's, so a target selected by both always goes through the game.
 */
function ruleConflicts(vpnRules, gameRules) {
  const active = gameRules.filter((rule) => rule.enabled)
  return vpnRules
    .filter((rule) =>
      active.some(
        (game) =>
          sameTarget(rule, game) || (rule.kind === 'application' && game.kind === 'folder' && insideFolder(rule, game)),
      ),
    )
    .map((rule) => rule.id)
}

/** The game rules that are actually live: on, and in a group that is on. */
function activeGameRules(rules, ruleGroups) {
  const enabledGroups = new Set(ruleGroups.filter((group) => group.enabled).map((group) => group.id))
  return rules.filter((rule) => rule.enabled && (!rule.groupId || enabledGroups.has(rule.groupId)))
}

module.exports = {
  RULE_KINDS,
  defaultVpn,
  normalizeVpn,
  selectedVpnNode,
  migrateVpnState,
  vpnRuleSpecs,
  ruleLimitation,
  unroutableRules,
  createRule,
  ruleConflicts,
  activeGameRules,
}
