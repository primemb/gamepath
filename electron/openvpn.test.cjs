const test = require('node:test')
const assert = require('node:assert/strict')
const { parseOpenVpnConfig, normaliseProtocol } = require('./openvpn.cjs')

const CA = [
  '<ca>',
  '-----BEGIN CERTIFICATE-----',
  'MIIBIjCByaADAgECAgEBMAo=',
  '-----END CERTIFICATE-----',
  '</ca>',
].join('\n')

const config = (body) => `${body}\n${CA}\n`

test('reads the server, protocol and name from a provider file', () => {
  const node = parseOpenVpnConfig(
    config('client\ndev tun\nremote tr2.example.ir 1403 tcp\nauth-user-pass'),
    'C:/downloads/tr2.example.ir.ovpn',
    'node-1',
    '2026-09-07T00:00:00.000Z',
  )
  assert.equal(node.kind, 'openvpn')
  assert.equal(node.name, 'tr2.example.ir')
  assert.equal(node.endpoint, 'tr2.example.ir:1403')
  assert.equal(node.protocol, 'tcp')
  assert.equal(node.wantsCredentials, true)
  assert.equal(node.enabled, true)
})

test('a protocol on the remote line wins over a separate proto line', () => {
  const node = parseOpenVpnConfig(config('remote vpn.example 443 tcp\nproto udp\nauth-user-pass'), 'x.ovpn', 'node-2')
  assert.equal(node.protocol, 'tcp')
})

test('a proto line applies when the remote line names none', () => {
  const node = parseOpenVpnConfig(config('remote vpn.example 1194\nproto tcp\nauth-user-pass'), 'x.ovpn', 'node-3')
  assert.equal(node.protocol, 'tcp')
})

test('a port line overrides the port on the remote line', () => {
  const node = parseOpenVpnConfig(config('remote vpn.example 1194\nport 443\nauth-user-pass'), 'x.ovpn', 'node-4')
  assert.equal(node.endpoint, 'vpn.example:443')
})

test('the address and DNS are described as the server’s to decide', () => {
  const node = parseOpenVpnConfig(config('remote vpn.example 1194\nauth-user-pass'), 'x.ovpn', 'node-5')
  assert.match(node.address, /server/i)
  assert.match(node.dns, /server/i)
})

test('a certificate-only configuration needs no credentials', () => {
  const source = `remote vpn.example 1194\n${CA}\n<cert>\ncert\n</cert>\n<key>\nkey\n</key>\n`
  const node = parseOpenVpnConfig(source, 'x.ovpn', 'node-6')
  assert.equal(node.wantsCredentials, false)
})

test('a file with no way to authenticate is refused', () => {
  assert.throws(
    () => parseOpenVpnConfig(config('remote vpn.example 1194'), 'x.ovpn', 'node-7'),
    /no way to authenticate/,
  )
})

test('a file with no remote is refused', () => {
  assert.throws(() => parseOpenVpnConfig(config('auth-user-pass'), 'x.ovpn', 'node-8'), /`remote` line/)
})

test('a file with no certificate authority is refused', () => {
  assert.throws(
    () => parseOpenVpnConfig('remote vpn.example 1194\nauth-user-pass\n', 'x.ovpn', 'node-9'),
    /`<ca>` block/,
  )
})

test('a tap configuration is refused because it carries frames not packets', () => {
  assert.throws(
    () => parseOpenVpnConfig(config('dev tap\nremote vpn.example 1194\nauth-user-pass'), 'x.ovpn', 'node-10'),
    /`tun` configuration/,
  )
})

test('a key kept in a separate file is refused by name', () => {
  assert.throws(
    () =>
      parseOpenVpnConfig(
        config('remote vpn.example 1194\ntls-crypt /etc/openvpn/tc.key\nauth-user-pass'),
        'x.ovpn',
        'node-11',
      ),
    /self-contained file/,
  )
})

test('compression is refused but a stub is allowed', () => {
  assert.throws(
    () => parseOpenVpnConfig(config('remote vpn.example 1194\ncomp-lzo yes\nauth-user-pass'), 'x.ovpn', 'node-12'),
    /does not compress/,
  )
  const node = parseOpenVpnConfig(config('remote vpn.example 1194\ncomp-lzo no\nauth-user-pass'), 'x.ovpn', 'node-13')
  assert.equal(node.kind, 'openvpn')
})

test('credentials read from a file are refused so they can be entered here', () => {
  assert.throws(
    () => parseOpenVpnConfig(config('remote vpn.example 1194\nauth-user-pass creds.txt'), 'x.ovpn', 'node-14'),
    /enter the credentials in GamePath/,
  )
})

test('a certificate body is not mistaken for a directive', () => {
  // A base64 line beginning with a word that happens to match a directive name
  // must not be read as one, which is why block contents are skipped.
  const source = ['remote vpn.example 1194', 'auth-user-pass', '<ca>', 'secret abc', 'dev tap', '</ca>'].join('\n')
  const node = parseOpenVpnConfig(source, 'x.ovpn', 'node-15')
  assert.equal(node.endpoint, 'vpn.example:1194')
})

test('protocol names are normalised to udp or tcp', () => {
  assert.equal(normaliseProtocol('tcp-client'), 'tcp')
  assert.equal(normaliseProtocol('TCP4'), 'tcp')
  assert.equal(normaliseProtocol('udp6'), 'udp')
})
