const assert = require('node:assert/strict')
const test = require('node:test')
const { parseAdapterNode } = require('./adapter.cjs')

test('an adapter node is kept by name, with nothing secret', () => {
  const { node, secret } = parseAdapterNode({ adapter: ' Windscribe ' }, 'node-1', '2026-11-01T00:00:00.000Z')
  assert.equal(node.kind, 'adapter')
  assert.equal(node.adapter, 'Windscribe')
  assert.equal(node.endpoint, 'Windscribe')
  assert.equal(node.name, 'Windscribe')
  assert.equal(node.hasCredentials, false)
  assert.equal(secret, '{}')
})

test('a label names the node without changing the adapter it uses', () => {
  const { node } = parseAdapterNode({ adapter: 'WindscribeOpenVPN', label: 'Windscribe UDP' }, 'node-2')
  assert.equal(node.name, 'Windscribe UDP')
  assert.equal(node.adapter, 'WindscribeOpenVPN')
})

test('a missing adapter, or one of GamePath’s own, is refused', () => {
  assert.throws(() => parseAdapterNode({ adapter: '  ' }, 'n'), /Choose or type the network adapter/)
  assert.throws(() => parseAdapterNode({ adapter: 'GamePath VPN' }, 'n'), /GamePath adapter/)
})
