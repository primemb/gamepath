const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')

const { withoutSecrets } = require('./public-state.cjs')

test('every encrypted field is removed, whatever it is called', () => {
  const safe = withoutSecrets({
    tunnels: [],
    encryptedConfigs: { a: 'x' },
    encryptedRelayTokens: {},
    encryptedLanProxyPassword: 'x',
    encryptedVpnConfig: 'x',
    vpn: { node: null },
  })
  assert.deepEqual(Object.keys(safe).sort(), ['tunnels', 'vpn'])
})

test('main.cjs builds the renderer state through withoutSecrets', () => {
  const source = fs.readFileSync(path.join(__dirname, 'main.cjs'), 'utf8')
  const body = source.slice(source.indexOf('function publicState()'), source.indexOf('function loadState()'))
  assert.match(body, /withoutSecrets\(state\)/)
})
