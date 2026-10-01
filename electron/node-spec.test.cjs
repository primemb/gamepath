const assert = require('node:assert/strict')
const test = require('node:test')
const { nodeSpec } = require('./node-spec.cjs')

test('each node kind becomes the tagged node the engine expects', () => {
  assert.deepEqual(nodeSpec({ kind: 'wireguard', name: 'WG' }, '[Interface]'), {
    kind: 'wireguard',
    config: '[Interface]',
    label: 'WG',
  })
  assert.deepEqual(
    nodeSpec({ kind: 'socks5', name: 'Proxy', host: 'proxy.example', port: 1080 }, JSON.stringify({ username: '' })),
    { kind: 'socks5', host: 'proxy.example', port: 1080, username: null, password: null, label: 'Proxy' },
  )
  assert.deepEqual(
    nodeSpec({ kind: 'openvpn', name: 'OVPN' }, JSON.stringify({ config: 'client', username: 'me', password: 'pw' })),
    { kind: 'openvpn', config: 'client', username: 'me', password: 'pw', label: 'OVPN' },
  )
  const l2tp = { server: 'vpn.example', username: 'me', password: 'pw', preSharedKey: 'psk' }
  assert.deepEqual(nodeSpec({ kind: 'l2tp', name: 'L2TP' }, JSON.stringify(l2tp)), {
    kind: 'l2tp',
    ...l2tp,
    label: 'L2TP',
  })
})
