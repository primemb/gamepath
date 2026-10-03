const assert = require('node:assert/strict')
const test = require('node:test')
const {
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
} = require('./vpn-state.cjs')

const wireguard = { id: 'vpn-node', kind: 'wireguard', name: 'Home', endpoint: 'vpn.example:51820' }
const l2tp = { id: 'vpn-node', kind: 'l2tp', name: 'Office', endpoint: 'office.example' }

test('anything saved becomes a usable VPN state without throwing', () => {
  for (const saved of [undefined, null, 42, 'vpn', [], { rules: null }, { node: 'x', rules: [null, 7] }]) {
    assert.deepEqual(normalizeVpn(saved), defaultVpn())
  }
})

test('a saved VPN keeps what is valid and drops what is not', () => {
  const vpn = normalizeVpn({
    node: wireguard,
    trafficMode: 'all',
    remoteDns: false,
    killSwitch: true,
    wantConnected: true,
    rules: [
      { id: 'a', kind: 'application', value: ' C:\\Apps\\chat.exe ', enabled: false },
      { id: 'a', kind: 'ip', value: '203.0.113.0/24' },
      { id: 'b', kind: 'teleport', value: 'x' },
      { id: 'c', kind: 'hostname', value: '' },
      { id: 'd', kind: 'hostname', value: 'news.example' },
    ],
  })
  assert.equal(selectedVpnNode(vpn).kind, 'wireguard')
  assert.equal(vpn.trafficMode, 'all')
  assert.equal(vpn.remoteDns, false)
  assert.equal(vpn.killSwitch, true)
  assert.equal(vpn.wantConnected, true)
  assert.deepEqual(
    vpn.rules.map((rule) => [rule.id, rule.value, rule.enabled]),
    [
      ['a', 'C:\\Apps\\chat.exe', false],
      ['d', 'news.example', true],
    ],
  )
  assert.deepEqual(vpnRuleSpecs(vpn), [{ kind: 'hostname', value: 'news.example' }])
})

test('a VPN without a node never wants to be connected', () => {
  assert.equal(normalizeVpn({ wantConnected: true }).wantConnected, false)
})

test('an L2TP split VPN refuses selectors Windows routes cannot express', () => {
  assert.match(ruleLimitation(l2tp, 'split', 'application', 'C:\\a.exe'), /cannot select applications/)
  assert.match(ruleLimitation(l2tp, 'split', 'hostname', '*.example.com'), /wildcard/)
  assert.equal(ruleLimitation(l2tp, 'split', 'hostname', 'example.com'), null)
  assert.equal(ruleLimitation(l2tp, 'all', 'application', 'C:\\a.exe'), null)
  assert.equal(ruleLimitation(wireguard, 'split', 'application', 'C:\\a.exe'), null)

  const vpn = {
    ...defaultVpn(),
    nodes: [l2tp],
    selectedNodeId: l2tp.id,
    rules: [createRule({ kind: 'folder', value: 'C:\\Apps' }, 'f')],
  }
  assert.deepEqual(
    unroutableRules(vpn).map((rule) => rule.id),
    ['f'],
  )
})

test('legacy VPN saves keep their node, selection and encrypted secret', () => {
  const state = { vpn: { node: wireguard, wantConnected: true }, encryptedVpnConfig: 'sealed:legacy' }
  migrateVpnState(state)
  assert.equal(state.vpn.nodes.length, 1)
  assert.equal(state.vpn.selectedNodeId, wireguard.id)
  assert.equal(selectedVpnNode(state.vpn).enabled, true)
  assert.equal(state.vpn.wantConnected, true)
  assert.deepEqual(state.encryptedVpnConfigs, { [wireguard.id]: 'sealed:legacy' })
  assert.equal(state.encryptedVpnConfig, undefined)
  const before = structuredClone(state)
  migrateVpnState(state)
  assert.deepEqual(state, before)
})

test('saved VPN lists discard duplicates and keep exactly one selected node', () => {
  const other = { ...l2tp, id: 'other' }
  const vpn = normalizeVpn({
    nodes: [wireguard, other, wireguard, null],
    selectedNodeId: other.id,
    wantConnected: true,
  })
  assert.deepEqual(
    vpn.nodes.map((node) => [node.id, node.enabled]),
    [
      [wireguard.id, false],
      [other.id, true],
    ],
  )
  assert.equal(selectedVpnNode(vpn).id, other.id)
  const restored = normalizeVpn({ ...vpn, selectedNodeId: 'removed' })
  assert.equal(restored.selectedNodeId, other.id)
  assert.equal(normalizeVpn({ nodes: [], node: wireguard, wantConnected: true }).wantConnected, false)
})

test('migration preserves each nodes secret and removes orphaned secrets', () => {
  const other = { ...l2tp, id: 'other' }
  const state = {
    vpn: { nodes: [wireguard, other], selectedNodeId: other.id },
    encryptedVpnConfigs: { [wireguard.id]: 'sealed:first', [other.id]: 'sealed:second', orphan: 'sealed:gone' },
  }
  migrateVpnState(state)
  assert.deepEqual(state.encryptedVpnConfigs, { [wireguard.id]: 'sealed:first', [other.id]: 'sealed:second' })
})

test('a new rule needs a known kind and a target, and labels itself', () => {
  assert.throws(() => createRule({ kind: 'nope', value: 'x' }, 'id'), /kind of target/)
  assert.throws(() => createRule({ kind: 'ip', value: '  ' }, 'id'), /target is required/)
  assert.equal(createRule({ kind: 'application', value: 'C:\\Apps\\chat.exe' }, 'id').label, 'chat.exe')
  assert.equal(createRule({ kind: 'hostname', value: 'news.example', label: 'News' }, 'id').label, 'News')
})

test('a VPN rule the game also selects is reported, because the game takes it first', () => {
  const vpnRules = [
    createRule({ kind: 'application', value: 'C:\\Games\\Shooter\\game.exe' }, 'inside-folder'),
    createRule({ kind: 'hostname', value: 'MATCH.example' }, 'same-host'),
    createRule({ kind: 'application', value: 'C:\\Apps\\chat.exe' }, 'free'),
  ]
  const gameRules = [
    { id: 'g1', kind: 'folder', value: 'C:\\Games\\Shooter\\', enabled: true, groupId: null },
    { id: 'g2', kind: 'hostname', value: 'match.example', enabled: true, groupId: 'paused' },
    { id: 'g3', kind: 'application', value: 'C:\\Apps\\chat.exe', enabled: false, groupId: null },
  ]
  const groups = [{ id: 'paused', name: 'Paused', enabled: true }]
  assert.deepEqual(ruleConflicts(vpnRules, activeGameRules(gameRules, groups)), ['inside-folder', 'same-host'])
  // A rule in a switched-off group is not live, so it takes nothing.
  groups[0].enabled = false
  assert.deepEqual(ruleConflicts(vpnRules, activeGameRules(gameRules, groups)), ['inside-folder'])
})
