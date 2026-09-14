const assert = require('node:assert/strict')
const test = require('node:test')
const {
  activeTunnels,
  enforceDirectSelection,
  directNodeSelection,
  directSelectionAfterSwitch,
} = require('./connection.cjs')

const wireguard = (id, enabled = true, groupId = null) => ({
  id,
  kind: 'wireguard',
  name: `WG ${id}`,
  enabled,
  groupId,
})
const openvpn = (id, enabled = true, groupId = null) => ({
  id,
  kind: 'openvpn',
  name: `OVPN ${id}`,
  enabled,
  groupId,
})
const proxy = (id, enabled = true, groupId = null) => ({
  id,
  kind: 'socks5',
  name: `Proxy ${id}`,
  enabled,
  groupId,
})
const group = (id, enabled = true) => ({ id, name: `Group ${id}`, enabled })

test('a single tunnelling node is what direct mode wants', () => {
  const { node, error } = directNodeSelection([wireguard('a')])
  assert.equal(error, null)
  assert.equal(node.id, 'a')

  const openVpnSelection = directNodeSelection([openvpn('b')])
  assert.equal(openVpnSelection.error, null)
  assert.equal(openVpnSelection.node.id, 'b')
})

test('an empty selection asks for a node rather than reporting a fault', () => {
  const { node, error } = directNodeSelection([])
  assert.equal(node, null)
  assert.match(error, /Choose the WireGuard, OpenVPN or L2TP node/)
})

test('several selected nodes name both ways out', () => {
  const { node, error } = directNodeSelection([wireguard('a'), wireguard('b'), wireguard('c')])
  assert.equal(node, null)
  assert.match(error, /3 are selected/)
  assert.match(error, /single tunnelling node/)
  assert.match(error, /relay mode/)
})

test('a proxy is refused with the reason and the alternative', () => {
  const { node, error } = directNodeSelection([proxy('p')])
  assert.equal(node, null)
  // Naming the node matters when several are added and only one is selected.
  assert.match(error, /^Proxy p is a SOCKS5 proxy/)
  assert.match(error, /needs a relay/)
  assert.match(error, /Choose a WireGuard, OpenVPN or L2TP node/)
})

test('switching to direct mode keeps an already enabled tunnelling node', () => {
  const tunnels = [proxy('p', true), wireguard('a', false), wireguard('b', true)]
  assert.equal(directSelectionAfterSwitch(tunnels), 'b')

  assert.equal(directSelectionAfterSwitch([proxy('p', true), openvpn('a', true), wireguard('b', false)]), 'a')
})

test('switching offers the first usable node when none was enabled', () => {
  const tunnels = [proxy('p', true), openvpn('a', false), wireguard('b', false)]
  assert.equal(directSelectionAfterSwitch(tunnels), 'a')
})

test('switching with nothing usable leaves the selection empty', () => {
  assert.equal(directSelectionAfterSwitch([proxy('p', true)]), null)
  assert.equal(directSelectionAfterSwitch([]), null)
})

test('a node carries traffic only when its own switch and its group are both on', () => {
  const tunnels = [wireguard('a', true, 'g1'), wireguard('b', false, 'g1'), wireguard('c', true, 'g2'), wireguard('d')]
  const groups = [group('g1', true), group('g2', false)]
  assert.deepEqual(
    activeTunnels(tunnels, groups).map((tunnel) => tunnel.id),
    ['a', 'd'],
  )
})

test('an ungrouped node answers to its own switch alone', () => {
  assert.deepEqual(
    activeTunnels([wireguard('a'), wireguard('b', false)], []).map((tunnel) => tunnel.id),
    ['a'],
  )
})

test('switching a group on in direct mode leaves exactly one node carrying', () => {
  const tunnels = [wireguard('a', true, 'g1'), wireguard('b', true, 'g1'), wireguard('c', true)]
  enforceDirectSelection(tunnels, [group('g1', true)])
  assert.deepEqual(
    activeTunnels(tunnels, [group('g1', true)]).map((tunnel) => tunnel.id),
    ['a'],
  )
  // The nodes that lost the contest are switched off, not silently hidden.
  assert.deepEqual(
    tunnels.filter((tunnel) => tunnel.enabled).map((tunnel) => tunnel.id),
    ['a'],
  )
})

test('a node the user just chose is the one direct mode keeps', () => {
  const tunnels = [wireguard('a', true, 'g1'), wireguard('b', true, 'g1')]
  enforceDirectSelection(tunnels, [group('g1', true)], 'b')
  assert.deepEqual(
    tunnels.filter((tunnel) => tunnel.enabled).map((tunnel) => tunnel.id),
    ['b'],
  )
})

test('direct mode is left alone when only one node was carrying', () => {
  const tunnels = [wireguard('a', true, 'g1'), wireguard('b', true, 'g2')]
  const groups = [group('g1', true), group('g2', false)]
  enforceDirectSelection(tunnels, groups)
  // 'b' stays switched on so switching its group back on restores the choice.
  assert.deepEqual(
    tunnels.filter((tunnel) => tunnel.enabled).map((tunnel) => tunnel.id),
    ['a', 'b'],
  )
})

test('switching to direct mode passes over a node in a switched-off group', () => {
  const tunnels = [wireguard('a', true, 'g1'), wireguard('b', false, 'g2')]
  assert.equal(directSelectionAfterSwitch(tunnels, [group('g1', false), group('g2', true)]), 'b')
})

test('switching falls back to a grouped node when nothing else can carry', () => {
  const tunnels = [proxy('p'), wireguard('a', true, 'g1')]
  assert.equal(directSelectionAfterSwitch(tunnels, [group('g1', false)]), 'a')
})
