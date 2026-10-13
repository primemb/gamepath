const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const test = require('node:test')
const { CATALOG, STALE_MS, parseList, DirectListStore } = require('./direct-lists.cjs')

const quiet = { info() {}, warn() {}, error() {}, debug() {} }
const logger = { scope: () => quiet }

const ranges = (count) => Array.from({ length: count }, (_, index) => `10.${index >> 8}.${index & 255}.0/24`)
const sites = (count) => Array.from({ length: count }, (_, index) => `+.site${index}.com`)

function response(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => String(body.length) },
    text: async () => body,
  }
}

function store({ answers, now = () => 1_000 } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gamepath-direct-'))
  const requested = []
  const fetch = async (url) => {
    requested.push(url)
    const answer = answers(url)
    if (answer instanceof Error) throw answer
    return answer
  }
  return { directory, requested, store: new DirectListStore({ directory, fetch, logger, now }) }
}

test('the catalog is the lists Throne uses to bypass Iran, from mirrors jsDelivr first', () => {
  assert.deepEqual(
    CATALOG.map((list) => [list.id, list.tag]),
    [
      ['ir-ip', 'geoip:ir'],
      ['ir-sites', 'geosite:category-ir'],
    ],
  )
  for (const list of CATALOG) {
    assert.match(list.urls[0], /^https:\/\/cdn\.jsdelivr\.net\/gh\/Chocolate4U\/Iran-clash-rules@release\//)
    assert.ok(list.urls.some((url) => url.startsWith('https://github.com/')))
  }
})

test('clash text lists become engine entries, with IPv6 and comments left out', () => {
  const ips = parseList('ip', '# header\n2.144.0.0/14\n\n2a01:5ec0::/29\n5.1.43.7\n1.2.3.0/40\n0.0.0.0/1\n')
  assert.deepEqual(ips, { entries: ['2.144.0.0/14', '5.1.43.7/32'], rejected: 2 })
  const domains = parseList('domain', '# header\n+.digikala.com\n.aparat.com\nTime.IR.\n*.bank.ir\nnot a domain\n')
  assert.deepEqual(domains, {
    entries: ['*.digikala.com', '*.aparat.com', 'time.ir', '*.bank.ir'],
    rejected: 1,
  })
})

test('a download is saved and survives a restart of the app', async () => {
  const { directory, requested, store: first } = store({ answers: () => response(ranges(600).join('\n')) })
  const saved = await first.download('ir-ip')
  assert.equal(saved.count, 600)
  assert.equal(requested.length, 1)
  assert.ok(requested[0].startsWith('https://cdn.jsdelivr.net/'))
  const again = new DirectListStore({ directory, fetch: async () => assert.fail('no fetch'), logger })
  assert.equal(again.has('ir-ip'), true)
  assert.equal(again.entries('ir-ip').length, 600)
  assert.equal(again.describe().find((list) => list.id === 'ir-ip').count, 600)
})

test('a filtered mirror or a block page falls through to the next mirror', async () => {
  const blockPage = '<html><body>This site is not accessible</body></html>'
  const { requested, store: lists } = store({
    answers: (url) => {
      if (url.includes('cdn.jsdelivr.net')) return new Error('ECONNRESET')
      if (url.includes('fastly')) return response(blockPage)
      return response(sites(1200).join('\n'))
    },
  })
  const saved = await lists.download('ir-sites')
  assert.equal(saved.count, 1200)
  assert.equal(saved.source, 'github.com')
  assert.equal(requested.length, 3)
})

test('when every mirror fails the old copy is kept and the error says what to try', async () => {
  let reachable = true
  const { store: lists } = store({
    answers: () => (reachable ? response(ranges(600).join('\n')) : response('', 503)),
  })
  await lists.download('ir-ip')
  reachable = false
  await assert.rejects(lists.download('ir-ip'), /turn the VPN on in all-traffic mode/)
  assert.equal(lists.entries('ir-ip').length, 600)
})

test('two requests for the same list share one download', async () => {
  const { requested, store: lists } = store({ answers: () => response(ranges(600).join('\n')) })
  await Promise.all([lists.download('ir-ip'), lists.download('ir-ip')])
  assert.equal(requested.length, 1)
})

test('a list goes stale after a week', async () => {
  let now = 1_000
  const { store: lists } = store({ answers: () => response(ranges(600).join('\n')), now: () => now })
  assert.equal(lists.isStale('ir-ip'), true)
  await lists.download('ir-ip')
  assert.equal(lists.isStale('ir-ip'), false)
  now += STALE_MS + 1
  assert.equal(lists.isStale('ir-ip'), true)
})
