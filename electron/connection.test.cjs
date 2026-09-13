const assert = require('node:assert/strict')
const test = require('node:test')
const { directNodeSelection, directSelectionAfterSwitch } = require('./connection.cjs')

const wireguard = (id, enabled = true) => ({ id, kind: 'wireguard', name: `WG ${id}`, enabled })
const openvpn = (id, enabled = true) => ({ id, kind: 'openvpn', name: `OVPN ${id}`, enabled })
const proxy = (id, enabled = true) => ({ id, kind: 'socks5', name: `Proxy ${id}`, enabled })

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
  assert.match(error, /Choose the WireGuard or OpenVPN node/)
})

test('several selected nodes name both ways out', () => {
  const { node, error } = directNodeSelection([wireguard('a'), wireguard('b'), wireguard('c')])
  assert.equal(node, null)
  assert.match(error, /3 are selected/)
  assert.match(error, /single WireGuard or OpenVPN node/)
  assert.match(error, /relay mode/)
})

test('a proxy is refused with the reason and the alternative', () => {
  const { node, error } = directNodeSelection([proxy('p')])
  assert.equal(node, null)
  // Naming the node matters when several are added and only one is selected.
  assert.match(error, /^Proxy p is a SOCKS5 proxy/)
  assert.match(error, /needs a relay/)
  assert.match(error, /Choose a WireGuard or OpenVPN node/)
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
