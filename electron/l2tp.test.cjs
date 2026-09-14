const test = require('node:test')
const assert = require('node:assert/strict')
const { parseL2tpNode } = require('./l2tp.cjs')

test('keeps every L2TP secret out of public node metadata', () => {
  const { node, credentials } = parseL2tpNode(
    { server: 'vpn.example', username: 'player', password: 'secret', preSharedKey: 'shared', label: 'Legacy' },
    'node-1',
    '2026-09-14T00:00:00.000Z',
  )
  assert.equal(node.kind, 'l2tp')
  assert.equal(node.endpoint, 'vpn.example')
  assert.equal(node.name, 'Legacy')
  assert.equal(JSON.stringify(node).includes('secret'), false)
  assert.equal(JSON.stringify(node).includes('shared'), false)
  assert.deepEqual(credentials, {
    server: 'vpn.example',
    username: 'player',
    password: 'secret',
    preSharedKey: 'shared',
  })
})

test('requires complete L2TP/IPsec authentication', () => {
  const base = { server: 'vpn.example', username: 'player', password: 'secret', preSharedKey: 'shared' }
  for (const missing of ['server', 'username', 'password', 'preSharedKey']) {
    assert.throws(() => parseL2tpNode({ ...base, [missing]: '' }, 'node'), /Enter/)
  }
  assert.throws(() => parseL2tpNode({ ...base, server: 'https://vpn.example:1701' }, 'node'), /without a URL or port/)
  assert.throws(() => parseL2tpNode({ ...base, server: '2001:db8::1' }, 'node'), /IPv4/)
  assert.throws(() => parseL2tpNode({ ...base, server: 'bad_host.example' }, 'node'), /without a URL or port/)
})
