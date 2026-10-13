'use strict'

const fs = require('node:fs')
const path = require('node:path')

/**
 * Downloadable lists for the VPN's direct sites: destinations that keep the
 * normal connection while the VPN carries everything else.
 *
 * The lists are the ones Throne's "Bypass Iran" route profile uses, from
 * Chocolate4U's Iran rules. Throne fetches them as sing-box `.srs` rule-sets;
 * the same project publishes the same data as plain text, which needs no
 * binary decoder. Nothing is bundled: the user downloads a list onto their own
 * machine and updates it when they choose, or it refreshes once it is a week
 * old. jsDelivr is tried first, as Throne does, because it is usually
 * reachable where GitHub is filtered.
 */

const RELEASE = 'Chocolate4U/Iran-clash-rules'
const mirrors = (file) => [
  `https://cdn.jsdelivr.net/gh/${RELEASE}@release/${file}`,
  `https://fastly.jsdelivr.net/gh/${RELEASE}@release/${file}`,
  `https://github.com/${RELEASE}/releases/latest/download/${file}`,
  `https://raw.githubusercontent.com/${RELEASE}/release/${file}`,
]

/** Add a country by adding its lists here; nothing else needs to change. */
const CATALOG = [
  {
    id: 'ir-ip',
    country: 'IR',
    kind: 'ip',
    title: 'Iran IP ranges',
    tag: 'geoip:ir',
    description: 'Every address registered in Iran, plus Iranian messengers such as Eitaa and Rubika.',
    urls: mirrors('ircidr.txt'),
    // Far below the real size, far above an error page or a filter's notice.
    minimum: 500,
  },
  {
    id: 'ir-sites',
    country: 'IR',
    kind: 'domain',
    title: 'Iranian websites',
    tag: 'geosite:category-ir',
    description: 'Every .ir site, and Iranian sites on .com, .net and other domains.',
    urls: mirrors('ir.txt'),
    minimum: 1000,
  },
]

/** A list older than this refreshes itself in the background. */
const STALE_MS = 7 * 24 * 60 * 60 * 1000
const DOWNLOAD_TIMEOUT_MS = 20000
const MAX_DOWNLOAD_BYTES = 8 * 1024 * 1024

const findList = (id) => CATALOG.find((list) => list.id === id) ?? null

const DOMAIN = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$/
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/

/** `a.b.c.d` or `a.b.c.d/len` with a prefix the engine accepts, else null. */
function parseNetwork(value) {
  const [address, prefix, extra] = value.split('/')
  if (extra !== undefined || !IPV4.test(address)) return null
  if (prefix === undefined) return `${address}/32`
  if (!/^\d{1,2}$/.test(prefix) || Number(prefix) < 8 || Number(prefix) > 32) return null
  return `${address}/${Number(prefix)}`
}

/**
 * A domain in the engine's form: `*.name` covers the name and everything
 * under it, `name` only itself. Clash writes the first as `+.name`; its
 * `.name` and one-level `*.name` are widened to the same, which errs towards
 * direct for a site the list already calls domestic.
 */
function parseDomain(value) {
  const lower = value.toLowerCase().replace(/\.$/, '')
  const suffix = /^(\+\.|\*\.|\.)/.test(lower)
  const name = lower.replace(/^(\+\.|\*\.|\.)/, '')
  if (!DOMAIN.test(name)) return null
  return suffix ? `*.${name}` : name
}

/** The usable entries of a downloaded list, and how many lines were not. */
function parseList(kind, text) {
  const entries = []
  let rejected = 0
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    // IPv6 is not carried at all, so its ranges have nothing to bypass.
    if (kind === 'ip' && line.includes(':')) continue
    const entry = kind === 'ip' ? parseNetwork(line) : parseDomain(line)
    if (entry) entries.push(entry)
    else rejected += 1
  }
  return { entries: [...new Set(entries)], rejected }
}

/**
 * The lists on disk, under `userData/direct-lists`. Metadata is kept in
 * memory, because the window asks for it on every state change; entries are
 * read when a session needs them.
 */
class DirectListStore {
  constructor({ directory, fetch, logger, now = () => Date.now() }) {
    this.directory = directory
    this.fetch = fetch
    this.log = logger.scope('direct')
    this.now = now
    this.cache = new Map()
    this.downloads = new Map()
    this.index = this.readIndex()
  }

  readIndex() {
    try {
      const saved = JSON.parse(fs.readFileSync(path.join(this.directory, 'index.json'), 'utf8'))
      return Object.fromEntries(Object.entries(saved).filter(([id]) => findList(id)))
    } catch {
      return {}
    }
  }

  writeIndex() {
    fs.mkdirSync(this.directory, { recursive: true })
    const file = path.join(this.directory, 'index.json')
    fs.writeFileSync(`${file}.tmp`, JSON.stringify(this.index))
    fs.renameSync(`${file}.tmp`, file)
  }

  /** What the window shows for each list. */
  describe() {
    return CATALOG.map(({ id, country, kind, title, tag, description }) => ({
      id,
      country,
      kind,
      title,
      tag,
      description,
      count: this.index[id]?.count ?? 0,
      updatedAt: this.index[id]?.updatedAt ?? null,
      downloading: this.downloads.has(id),
    }))
  }

  has(id) {
    return Boolean(this.index[id])
  }

  entries(id) {
    if (!this.has(id)) return []
    const cached = this.cache.get(id)
    if (cached && cached.updatedAt === this.index[id].updatedAt) return cached.entries
    try {
      const entries = JSON.parse(fs.readFileSync(path.join(this.directory, `${id}.json`), 'utf8'))
      this.cache.set(id, { updatedAt: this.index[id].updatedAt, entries })
      return entries
    } catch (error) {
      this.log.warn(`could not read the ${id} list: ${error.message}`)
      return []
    }
  }

  isStale(id) {
    return !this.has(id) || this.now() - this.index[id].updatedAt > STALE_MS
  }

  /** One download per list at a time; a second caller shares the first. */
  download(id) {
    const running = this.downloads.get(id)
    if (running) return running
    const operation = this.fetchList(id).finally(() => this.downloads.delete(id))
    this.downloads.set(id, operation)
    return operation
  }

  async fetchList(id) {
    const list = findList(id)
    if (!list) throw new Error('That list no longer exists.')
    const failures = []
    for (const url of list.urls) {
      const host = new URL(url).host
      try {
        const text = await this.fetchText(url)
        const { entries, rejected } = parseList(list.kind, text)
        // A filter's block page or an error body parses as a handful of
        // nonsense lines; a real list is thousands of entries.
        if (entries.length < list.minimum || rejected > entries.length / 20) {
          throw new Error(`not a ${list.tag} list (${entries.length} usable lines)`)
        }
        fs.mkdirSync(this.directory, { recursive: true })
        const file = path.join(this.directory, `${id}.json`)
        fs.writeFileSync(`${file}.tmp`, JSON.stringify(entries))
        fs.renameSync(`${file}.tmp`, file)
        this.index[id] = { count: entries.length, updatedAt: this.now(), source: host }
        this.cache.set(id, { updatedAt: this.index[id].updatedAt, entries })
        this.writeIndex()
        this.log.info(`${id} downloaded from ${host}: ${entries.length} entries`)
        return this.index[id]
      } catch (error) {
        failures.push(`${host}: ${error.message}`)
      }
    }
    this.log.warn(`${id} could not be downloaded: ${failures.join('; ')}`)
    throw new Error(
      `Could not download ${list.title} from any mirror. If these sites are filtered on your connection, turn the VPN on in all-traffic mode and try again.`,
    )
  }

  async fetchText(url) {
    const response = await this.fetch(url, { signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS) })
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    const length = Number(response.headers.get('content-length'))
    if (length > MAX_DOWNLOAD_BYTES) throw new Error('the file is unexpectedly large')
    const text = await response.text()
    if (text.length > MAX_DOWNLOAD_BYTES) throw new Error('the file is unexpectedly large')
    return text
  }
}

module.exports = { CATALOG, STALE_MS, findList, parseList, parseNetwork, parseDomain, DirectListStore }
