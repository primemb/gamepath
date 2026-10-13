'use strict'

const { findList, parseNetwork, parseDomain } = require('./direct-lists.cjs')

/**
 * The VPN's direct sites as saved: whether the feature is on, which
 * downloaded lists it uses, and the user's own sites and addresses. Pure
 * functions, tested without Electron.
 */

function defaultDirect() {
  return { enabled: false, lists: [], entries: [] }
}

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)

function normalizeDirect(saved) {
  const direct = defaultDirect()
  if (!isObject(saved)) return direct
  direct.enabled = saved.enabled === true
  if (Array.isArray(saved.lists)) direct.lists = [...new Set(saved.lists.filter((id) => findList(id)))]
  if (Array.isArray(saved.entries)) {
    const seen = new Set()
    for (const entry of saved.entries) {
      if (!isObject(entry) || typeof entry.id !== 'string' || seen.has(entry.id)) continue
      const parsed = typeof entry.value === 'string' ? parseDirectTarget(entry.value) : null
      if (!parsed || parsed.kind !== entry.kind) continue
      seen.add(entry.id)
      direct.entries.push({ id: entry.id, ...parsed, enabled: entry.enabled !== false })
    }
  }
  return direct
}

/**
 * What the user typed, as a site or an address. A pasted link is reduced to
 * its site, so `https://www.digikala.com/cart` means `digikala.com`: `www.` is
 * one of the site's own names, and keeping it would leave the bare name out.
 */
function parseDirectTarget(input) {
  const text = String(input ?? '')
    .trim()
    .toLowerCase()
  if (!text) return null
  if (/^[\d./]+$/.test(text)) {
    const network = parseNetwork(text)
    return network && { kind: 'ip', value: network.endsWith('/32') ? network.slice(0, -3) : network }
  }
  const host = text
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
    .split(/[/?#]/)[0]
    .replace(/:\d+$/, '')
    .replace(/^(\*\.|www\.)/, '')
  const domain = parseDomain(host)
  return domain && domain.includes('.') ? { kind: 'domain', value: domain } : null
}

function createDirectEntry(input, id) {
  const parsed = parseDirectTarget(input)
  if (!parsed) {
    throw new Error('Enter a website such as digikala.com, or an IPv4 address or range such as 185.143.232.0/22.')
  }
  return { id, ...parsed, enabled: true }
}

const sameEntry = (left, right) => left.kind === right.kind && left.value === right.value

/**
 * Why `node` cannot use a direct list, or null. L2TP/IPsec is routed by
 * Windows RAS, with no capture of GamePath's to leave anything out of.
 */
function directLimitation(node) {
  if (node?.kind !== 'l2tp') return null
  return 'An L2TP/IPsec VPN is routed by Windows, so it cannot leave sites out. Use a WireGuard, OpenVPN or SOCKS5 node for direct sites.'
}

/**
 * What the engine is sent: every network and domain the direct list covers,
 * or null when nothing is direct. `entriesOf(id)` reads a downloaded list.
 */
function directSpec(direct, entriesOf) {
  if (!direct.enabled) return null
  const networks = new Set()
  const domains = new Set()
  for (const id of direct.lists) {
    const target = findList(id)?.kind === 'ip' ? networks : domains
    for (const entry of entriesOf(id)) target.add(entry)
  }
  for (const entry of direct.entries) {
    if (!entry.enabled) continue
    if (entry.kind === 'ip') networks.add(entry.value.includes('/') ? entry.value : `${entry.value}/32`)
    // A site typed by hand means the whole site, `www.` and all.
    else domains.add(`*.${entry.value}`)
  }
  if (!networks.size && !domains.size) return null
  return { networks: [...networks], domains: [...domains] }
}

module.exports = {
  defaultDirect,
  normalizeDirect,
  parseDirectTarget,
  createDirectEntry,
  sameEntry,
  directLimitation,
  directSpec,
}
