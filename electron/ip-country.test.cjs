const test = require('node:test')
const assert = require('node:assert/strict')
const { createIpCountryLookup, isPublicIp, resolveIp, targetHost } = require('./ip-country.cjs')

test('extracts hosts from the endpoint forms displayed by the app', () => {
  assert.equal(targetHost('1.1.1.1:443'), '1.1.1.1')
  assert.equal(targetHost('10.0.0.2/32'), '10.0.0.2')
  assert.equal(targetHost('[2606:4700:4700::1111]:53'), '2606:4700:4700::1111')
  assert.equal(targetHost('relay.example.com:51821'), 'relay.example.com')
  assert.equal(targetHost('*.example.com'), null)
  assert.equal(targetHost('System default'), null)
})

test('does not send private or reserved addresses to the public API', () => {
  assert.equal(isPublicIp('10.0.0.2'), false)
  assert.equal(isPublicIp('192.168.1.20'), false)
  assert.equal(isPublicIp('::1'), false)
  assert.equal(isPublicIp('8.8.8.8'), true)
  assert.equal(isPublicIp('2606:4700:4700::1111'), true)
})

test('resolves hostnames but leaves literal IP addresses alone', async () => {
  let calls = 0
  const lookup = async () => {
    calls += 1
    return { address: '203.0.113.8', family: 4 }
  }
  assert.equal(await resolveIp('vpn.example.com:51820', lookup), '203.0.113.8')
  assert.equal(await resolveIp('8.8.8.8', lookup), '8.8.8.8')
  assert.equal(calls, 1)
})

test('returns normalized country data and caches repeated IPs', async () => {
  let calls = 0
  const fetchImpl = async () => {
    calls += 1
    return {
      ok: true,
      status: 200,
      json: async () => ({ success: true, country: 'United States', country_code: 'us' }),
    }
  }
  const findCountry = createIpCountryLookup({ fetchImpl })
  const expected = { ip: '8.8.8.8', country: 'United States', countryCode: 'US' }
  assert.deepEqual(await findCountry('8.8.8.8:53'), expected)
  assert.deepEqual(await findCountry('8.8.8.8'), expected)
  assert.equal(calls, 1)
})

test('fails quietly when a target cannot be resolved or geolocated', async () => {
  const findCountry = createIpCountryLookup({
    lookup: async () => {
      throw new Error('not found')
    },
    fetchImpl: async () => {
      throw new Error('offline')
    },
  })
  assert.equal(await findCountry('missing.example'), null)
  assert.equal(await findCountry('192.0.2.1'), null)
})
