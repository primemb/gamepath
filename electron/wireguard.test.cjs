const assert = require('node:assert/strict')
const test = require('node:test')
const { parseWireGuardConfig, valueFromSection } = require('./wireguard.cjs')

const sample = `[Interface]
PrivateKey = secret-client-key
Address = 10.10.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = server-public-key
AllowedIPs = 0.0.0.0/0
Endpoint = 203.0.113.8:51820
PersistentKeepalive = 25
`

test('parses safe WireGuard metadata without returning keys', () => {
  const parsed = parseWireGuardConfig(sample, 'C:\\vpn\\turkey-one.conf', 'route-1', '2026-09-06T00:00:00.000Z')
  assert.equal(parsed.name, 'turkey-one')
  assert.equal(parsed.endpoint, '203.0.113.8:51820')
  assert.equal(parsed.address, '10.10.0.2/32')
  assert.equal(parsed.hasPrivateKey, true)
  assert.equal(JSON.stringify(parsed).includes('secret-client-key'), false)
  assert.equal(JSON.stringify(parsed).includes('server-public-key'), false)
})

test('reads values case-insensitively', () => {
  assert.equal(valueFromSection('[interface]\naddress=10.0.0.2/32', 'Interface', 'Address'), '10.0.0.2/32')
})

test('rejects an incomplete configuration', () => {
  assert.throws(() => parseWireGuardConfig('[Interface]\nAddress=10.0.0.2', 'bad.conf', 'bad'), /Missing/)
})
