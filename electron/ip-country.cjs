const dns = require('node:dns').promises
const net = require('node:net')

const SUCCESS_TTL_MS = 7 * 24 * 60 * 60 * 1000
const FAILURE_TTL_MS = 15 * 60 * 1000
const MAX_CACHE_ENTRIES = 512

const nonPublicAddresses = new net.BlockList()
for (const [address, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
]) {
  nonPublicAddresses.addSubnet(address, prefix, 'ipv4')
}
for (const [address, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['fc00::', 7],
  ['fe80::', 10],
  ['2001:db8::', 32],
  ['ff00::', 8],
]) {
  nonPublicAddresses.addSubnet(address, prefix, 'ipv6')
}

function isPublicIp(ip) {
  const family = net.isIP(ip)
  return family !== 0 && !nonPublicAddresses.check(ip, family === 6 ? 'ipv6' : 'ipv4')
}

function targetHost(value) {
  const target = String(value ?? '').trim()
  if (!target || target.length > 253 || /\s|:\/\//.test(target)) return null

  if (target.startsWith('[')) {
    const closing = target.indexOf(']')
    return closing > 1 ? target.slice(1, closing) : null
  }

  const withoutCidr = target.replace(/\/\d{1,3}$/, '')
  if (net.isIP(withoutCidr)) return withoutCidr

  // IPv4/hostname endpoints commonly include a port. Unbracketed IPv6 was
  // already accepted by net.isIP above and must not be split here.
  const portMatch = withoutCidr.match(/^([^:]+):(\d{1,5})$/)
  const host = (portMatch?.[1] ?? withoutCidr).replace(/\.$/, '')
  if (!host || host.includes('*') || !/^[a-z\d.-]+$/i.test(host)) return null
  return host
}

async function resolveIp(value, lookup = dns.lookup) {
  const host = targetHost(value)
  if (!host) return null
  if (net.isIP(host)) return host
  try {
    return (await lookup(host, { verbatim: true })).address
  } catch {
    return null
  }
}

function createIpCountryLookup({ fetchImpl = globalThis.fetch, lookup = dns.lookup, now = Date.now } = {}) {
  const cache = new Map()
  const pending = new Map()
  let retryAfter = 0

  async function lookupCountry(target) {
    const ip = await resolveIp(target, lookup)
    if (!ip || !isPublicIp(ip)) return null

    const cached = cache.get(ip)
    if (cached && cached.expiresAt > now()) return cached.value
    if (pending.has(ip)) return pending.get(ip)
    if (now() < retryAfter) return null

    const request = (async () => {
      let value = null
      let ttl = FAILURE_TTL_MS
      try {
        const response = await fetchImpl(
          `https://ipwho.is/${encodeURIComponent(ip)}?fields=success,message,country,country_code`,
          { signal: AbortSignal.timeout(5000) },
        )
        if (response.status === 429) {
          const seconds = Number(response.headers.get('retry-after'))
          retryAfter = now() + (Number.isFinite(seconds) ? seconds * 1000 : 60 * 60 * 1000)
        } else if (response.ok) {
          const result = await response.json()
          const code = typeof result.country_code === 'string' ? result.country_code.toUpperCase() : ''
          if (result.success === true && /^[A-Z]{2}$/.test(code) && typeof result.country === 'string') {
            value = { ip, country: result.country, countryCode: code }
            ttl = SUCCESS_TTL_MS
          }
        }
      } catch {
        // Country context is an enhancement. Network/API failures must never
        // interfere with displaying the endpoint itself.
      }

      if (cache.size >= MAX_CACHE_ENTRIES) cache.delete(cache.keys().next().value)
      cache.set(ip, { value, expiresAt: now() + ttl })
      return value
    })()

    pending.set(ip, request)
    try {
      return await request
    } finally {
      pending.delete(ip)
    }
  }

  return lookupCountry
}

module.exports = { createIpCountryLookup, isPublicIp, resolveIp, targetHost }
