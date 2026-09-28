const assert = require('node:assert/strict')
const test = require('node:test')
const {
  defaultLanProxy,
  normalizeLanProxy,
  parseLanProxySettings,
  lanProxySessionPayload,
  publicLanProxy,
} = require('./lan-proxy.cjs')

test('the proxy is off with no login until the user turns it on', () => {
  assert.deepEqual(defaultLanProxy(), { enabled: false, port: 1080, username: '' })
  assert.deepEqual(normalizeLanProxy(undefined), defaultLanProxy())
  assert.deepEqual(normalizeLanProxy({ enabled: true, port: 47983, username: 'ps5' }), {
    enabled: true,
    port: 1080,
    username: 'ps5',
  })
})

test('ports are validated and the service port is refused', () => {
  const current = defaultLanProxy()
  assert.equal(parseLanProxySettings({ port: '1081' }, current, false).settings.port, 1081)
  assert.throws(() => parseLanProxySettings({ port: 0 }, current, false), /1 to 65535/)
  assert.throws(() => parseLanProxySettings({ port: 47983 }, current, false), /GamePath service/)
})

test('a login needs a password, and clearing the username clears it', () => {
  const current = defaultLanProxy()
  assert.throws(() => parseLanProxySettings({ username: 'console' }, current, false), /Enter a password/)
  const withLogin = parseLanProxySettings({ username: ' console ', password: 'pw' }, current, false)
  assert.equal(withLogin.settings.username, 'console')
  assert.equal(withLogin.password, 'pw')
  // Renaming keeps the stored password.
  const renamed = parseLanProxySettings({ username: 'ps5' }, withLogin.settings, true)
  assert.equal(renamed.password, undefined)
  const cleared = parseLanProxySettings({ username: '' }, renamed.settings, true)
  assert.equal(cleared.settings.username, '')
  assert.equal(cleared.password, null)
  assert.throws(() => parseLanProxySettings({ username: 'a:b', password: 'x' }, current, false), /colon/)
})

test('the session payload carries a login only when both halves exist', () => {
  const settings = { enabled: true, port: 1080, username: 'console' }
  assert.deepEqual(lanProxySessionPayload(settings, 'pw'), {
    enabled: true,
    port: 1080,
    username: 'console',
    password: 'pw',
  })
  assert.equal(lanProxySessionPayload(settings, null).username, null)
  assert.equal(publicLanProxy(settings, true).hasPassword, true)
  assert.equal('password' in publicLanProxy(settings, true), false)
})
