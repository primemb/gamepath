const assert = require('node:assert/strict')
const test = require('node:test')
const {
  defaultDirect,
  normalizeDirect,
  parseDirectTarget,
  createDirectEntry,
  directLimitation,
  directSpec,
} = require('./vpn-direct-state.cjs')

test('a typed site, link or address becomes one direct target', () => {
  assert.deepEqual(parseDirectTarget(' Digikala.com '), { kind: 'domain', value: 'digikala.com' })
  assert.deepEqual(parseDirectTarget('https://www.aparat.com:443/v/abc?x=1'), {
    kind: 'domain',
    value: 'aparat.com',
  })
  assert.deepEqual(parseDirectTarget('*.shaparak.ir'), { kind: 'domain', value: 'shaparak.ir' })
  assert.deepEqual(parseDirectTarget('185.143.232.0/22'), { kind: 'ip', value: '185.143.232.0/22' })
  assert.deepEqual(parseDirectTarget('5.200.1.9'), { kind: 'ip', value: '5.200.1.9' })
  for (const bad of ['', 'localhost', '0.0.0.0/1', '300.1.1.1', 'bad host.ir', '2a01::/32']) {
    assert.equal(parseDirectTarget(bad), null, bad)
  }
  assert.throws(() => createDirectEntry('nonsense'), /Enter a website/)
})

test('a saved direct list keeps what is valid and drops what is not', () => {
  assert.deepEqual(normalizeDirect(undefined), defaultDirect())
  const direct = normalizeDirect({
    enabled: true,
    lists: ['ir-ip', 'gone', 'ir-ip'],
    entries: [
      { id: 'a', kind: 'domain', value: 'digikala.com', enabled: false },
      { id: 'a', kind: 'domain', value: 'twice.ir' },
      { id: 'b', kind: 'ip', value: 'digikala.com' },
      { id: 'c', kind: 'ip', value: '5.200.1.9' },
    ],
  })
  assert.equal(direct.enabled, true)
  assert.deepEqual(direct.lists, ['ir-ip'])
  assert.deepEqual(
    direct.entries.map((entry) => [entry.id, entry.value, entry.enabled]),
    [
      ['a', 'digikala.com', false],
      ['c', '5.200.1.9', true],
    ],
  )
})

test('the engine is sent every listed range and site, typed sites with their subdomains', () => {
  const lists = { 'ir-ip': ['2.144.0.0/14'], 'ir-sites': ['*.ir', 'time.example'] }
  const direct = {
    enabled: true,
    lists: ['ir-ip', 'ir-sites'],
    entries: [
      { id: 'a', kind: 'domain', value: 'digikala.com', enabled: true },
      { id: 'b', kind: 'ip', value: '5.200.1.9', enabled: true },
      { id: 'c', kind: 'domain', value: 'off.example', enabled: false },
    ],
  }
  assert.deepEqual(
    directSpec(direct, (id) => lists[id]),
    {
      networks: ['2.144.0.0/14', '5.200.1.9/32'],
      domains: ['*.ir', 'time.example', '*.digikala.com'],
    },
  )
  assert.equal(
    directSpec({ ...direct, enabled: false }, (id) => lists[id]),
    null,
  )
  assert.equal(
    directSpec({ enabled: true, lists: [], entries: [] }, () => []),
    null,
  )
})

test('only an L2TP node cannot leave sites out', () => {
  assert.match(directLimitation({ kind: 'l2tp' }), /routed by Windows/)
  for (const kind of ['wireguard', 'openvpn', 'socks5']) assert.equal(directLimitation({ kind }), null)
  assert.equal(directLimitation(null), null)
})
