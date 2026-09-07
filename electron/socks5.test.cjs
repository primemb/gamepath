const assert = require('node:assert/strict')
const test = require('node:test')
const { parseSocks5Node, parseAddress } = require('./socks5.cjs')

test('parses a bare host and port', () => {
  const { node, credentials } = parseSocks5Node({ address: '127.0.0.1:2080' }, 'node-1', '2026-09-07T00:00:00.000Z')
  assert.equal(node.kind, 'socks5')
  assert.equal(node.host, '127.0.0.1')
  assert.equal(node.port, 2080)
  assert.equal(node.endpoint, '127.0.0.1:2080')
  assert.equal(node.name, '127.0.0.1:2080')
  assert.equal(node.enabled, true)
  assert.equal(node.hasPrivateKey, false)
  assert.equal(node.hasCredentials, false)
  assert.deepEqual(credentials, { username: '', password: '' })
})

test('parses a socks5 URI with credentials and keeps them out of the node', () => {
  const { node, credentials } = parseSocks5Node({ address: 'socks5://player:s3cr3t@proxy.example:1080' }, 'node-2')
  assert.equal(node.host, 'proxy.example')
  assert.equal(node.port, 1080)
  assert.equal(node.hasCredentials, true)
  assert.deepEqual(credentials, { username: 'player', password: 's3cr3t' })
  assert.equal(JSON.stringify(node).includes('s3cr3t'), false)
})

test('accepts socks5h and percent-encoded secrets', () => {
  const { credentials } = parseSocks5Node({ address: 'socks5h://user%40mail:p%40ss%3Aword@proxy.example:1080' }, 'n')
  assert.deepEqual(credentials, { username: 'user@mail', password: 'p@ss:word' })
})

test('defaults the port to 1080 when the address omits one', () => {
  assert.equal(parseSocks5Node({ address: 'proxy.example' }, 'n').node.port, 1080)
})

test('brackets a literal IPv6 host so host:port stays unambiguous', () => {
  assert.equal(parseSocks5Node({ address: 'socks5://[::1]:2080' }, 'n').node.endpoint, '[::1]:2080')
  assert.equal(parseSocks5Node({ host: '::1', port: 2080 }, 'n').node.endpoint, '[::1]:2080')
})

test('explicit fields override what the address carried', () => {
  const { node, credentials } = parseSocks5Node(
    { address: 'socks5://old:old@127.0.0.1:2080', port: 9050, username: 'new', password: 'newpass' },
    'n',
  )
  assert.equal(node.port, 9050)
  assert.deepEqual(credentials, { username: 'new', password: 'newpass' })
})

test('uses a given label and falls back to the endpoint', () => {
  assert.equal(parseSocks5Node({ address: '127.0.0.1:2080', label: 'Local sing-box' }, 'n').node.name, 'Local sing-box')
  assert.equal(parseSocks5Node({ address: '127.0.0.1:2080', label: '   ' }, 'n').node.name, '127.0.0.1:2080')
})

test('rejects unusable input', () => {
  assert.throws(() => parseSocks5Node({ address: '' }, 'n'), /Enter the proxy address/)
  assert.throws(() => parseSocks5Node({ address: 'http://proxy.example:8080' }, 'n'), /SOCKS5/)
  assert.throws(() => parseSocks5Node({ address: '127.0.0.1:70000' }, 'n'), /between 1 and 65535/)
  assert.throws(() => parseSocks5Node({ address: '127.0.0.1:2080', username: 'player' }, 'n'), /both a username/)
  assert.throws(() => parseSocks5Node({ address: '127.0.0.1:2080', password: 'secret' }, 'n'), /both a username/)
  assert.throws(
    () => parseSocks5Node({ address: '127.0.0.1:2080', username: 'a'.repeat(256), password: 'b' }, 'n'),
    /255 bytes/,
  )
})

test('parseAddress leaves credentials empty when the URI has none', () => {
  assert.deepEqual(parseAddress('proxy.example:1080'), {
    host: 'proxy.example',
    port: 1080,
    username: '',
    password: '',
  })
})
