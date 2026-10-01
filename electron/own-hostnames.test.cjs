const assert = require('node:assert/strict')
const test = require('node:test')
const { ownHostnames, hostOf } = require('./own-hostnames.cjs')

test('a hostname is taken from every endpoint form, an address never', () => {
  assert.equal(hostOf('Turkey1.Pingkhor.xyz:903'), 'turkey1.pingkhor.xyz')
  assert.equal(hostOf('relay.example.com.'), 'relay.example.com')
  assert.equal(hostOf('88.218.16.70'), null)
  assert.equal(hostOf('88.218.16.70:51820'), null)
  assert.equal(hostOf('[2001:db8::1]:51820'), null)
  assert.equal(hostOf('Assigned by the server'), null)
  assert.equal(hostOf('localhost'), null)
  assert.equal(hostOf(undefined), null)
})

test('game nodes, relays and the VPN node are all collected once', () => {
  const state = {
    tunnels: [
      { endpoint: 'turkey1.pingkhor.xyz:903' },
      { endpoint: 'german2.pingkhor.xyz:904' },
      { endpoint: 'german2.pingkhor.xyz:904' },
      { endpoint: '37.152.174.246', host: '37.152.174.246' },
      { endpoint: 'tr2.e-mix.ir:1403', address: 'Assigned by the server' },
    ],
    relays: [{ address: '191.101.113.26' }, { address: 'relay.example.net' }],
    vpn: { node: { kind: 'socks5', endpoint: '127.0.0.1:2080', host: 'proxy.example.org' } },
  }
  assert.deepEqual(ownHostnames(state), [
    'german2.pingkhor.xyz',
    'proxy.example.org',
    'relay.example.net',
    'tr2.e-mix.ir',
    'turkey1.pingkhor.xyz',
  ])
  assert.deepEqual(ownHostnames({}), [])
})
