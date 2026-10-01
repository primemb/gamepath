const path = require('node:path')
const { DatabaseSync } = require('node:sqlite')

const dayKey = (date) => {
  const local = new Date(date)
  return `${local.getFullYear()}-${String(local.getMonth() + 1).padStart(2, '0')}-${String(local.getDate()).padStart(2, '0')}`
}

/**
 * Turns one running session's cumulative counters into deltas.
 *
 * Each session keeps its own baselines, so the game and the VPN can report at
 * the same time without either reading the other's counters as a reset. The
 * prefix keeps their rows apart in the shared table: the game writes the
 * categories it always did, the VPN writes `vpn-total`, `vpn-node`, `vpn-app`.
 */
class UsageSession {
  constructor(store, prefix = '') {
    this.store = store
    this.prefix = prefix
    this.last = new Map()
    this.session = null
    this.captureId = null
    this.lanProxyStartedAt = null
  }

  start(session, nodes) {
    this.store.flush()
    this.last.clear()
    this.captureId = null
    this.lanProxyStartedAt = null
    this.session = { id: String(session), nodes }
  }

  record(runtime, at = new Date()) {
    if (!this.session) return
    const day = dayKey(at)
    this.addCounter(day, 'total', 'all', 'All traffic', runtime.userBytesSent, runtime.userBytesReceived)
    for (const route of runtime.paths ?? []) {
      const node = this.session.nodes[route.route - 1]
      if (!node) continue
      this.addCounter(day, 'node', node.id, node.name, route.bytesSent, route.bytesReceived)
    }
    const diagnostics = runtime.capture?.diagnostics
    if (diagnostics?.captureId != null && diagnostics.captureId !== this.captureId) {
      this.captureId = diagnostics.captureId
      for (const key of this.last.keys()) if (key.startsWith('app\0')) this.last.delete(key)
    }
    for (const app of diagnostics?.appUsage ?? []) {
      this.addCounter(day, 'app', app.application, app.application, app.bytesSent, app.bytesReceived)
    }
    // A proxy restarted by a settings change counts from zero again.
    const proxy = runtime.lanProxy
    if (proxy?.startedAt != null && proxy.startedAt !== this.lanProxyStartedAt) {
      this.lanProxyStartedAt = proxy.startedAt
      for (const key of this.last.keys()) if (key.startsWith('device\0')) this.last.delete(key)
    }
    for (const device of proxy?.clients ?? []) {
      this.addCounter(day, 'device', device.address, device.address, device.bytesSent, device.bytesReceived)
    }
  }

  addCounter(day, category, identity, label, sent, received) {
    if (!Number.isSafeInteger(sent) || !Number.isSafeInteger(received) || sent < 0 || received < 0) return
    const key = `${category}\0${identity}`
    const before = this.last.get(key)
    const difference = (value, old) => (old == null || value < old ? value : value - old)
    const sentDelta = difference(sent, before?.sent)
    const receivedDelta = difference(received, before?.received)
    this.last.set(key, { sent, received })
    if (!sentDelta && !receivedDelta) return
    this.store.add(day, `${this.prefix}${category}`, identity, label, sentDelta, receivedDelta)
  }
}

class UsageStore {
  constructor(directory) {
    this.db = new DatabaseSync(path.join(directory, 'usage.sqlite'))
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;
      CREATE TABLE IF NOT EXISTS usage_daily (
        day TEXT NOT NULL,
        category TEXT NOT NULL,
        identity TEXT NOT NULL,
        label TEXT NOT NULL,
        sent INTEGER NOT NULL DEFAULT 0,
        received INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (day, category, identity)
      );
    `)
    this.insert = this.db.prepare(`
      INSERT INTO usage_daily (day, category, identity, label, sent, received)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(day, category, identity) DO UPDATE SET
        label = excluded.label,
        sent = sent + excluded.sent,
        received = received + excluded.received
    `)
    this.pending = new Map()
    // The game session, under the categories every earlier release wrote.
    this.game = new UsageSession(this)
  }

  /** A separate session whose rows are kept apart by `prefix`. */
  session(prefix) {
    return new UsageSession(this, prefix)
  }

  start(session, nodes) {
    this.game.start(session, nodes)
  }

  record(runtime, at = new Date()) {
    this.game.record(runtime, at)
  }

  add(day, category, identity, label, sent, received) {
    const pendingKey = `${day}\0${category}\0${identity}`
    const entry = this.pending.get(pendingKey) ?? { day, category, identity, label, sent: 0, received: 0 }
    entry.sent += sent
    entry.received += received
    this.pending.set(pendingKey, entry)
  }

  flush() {
    if (!this.pending.size) return
    this.db.exec('BEGIN IMMEDIATE')
    try {
      for (const row of this.pending.values()) {
        this.insert.run(row.day, row.category, row.identity, row.label, row.sent, row.received)
      }
      this.db.exec('COMMIT')
      this.pending.clear()
    } catch (error) {
      this.db.exec('ROLLBACK')
      throw error
    }
  }

  query(from, to) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(from) || !/^\d{4}-\d{2}-\d{2}$/.test(to) || from > to) {
      throw new Error('Choose a valid date range')
    }
    this.flush()
    const totals = this.db
      .prepare(
        `
      SELECT category, identity, MAX(label) AS label, SUM(sent) AS sent, SUM(received) AS received
      FROM usage_daily WHERE day BETWEEN ? AND ? GROUP BY category, identity
      ORDER BY sent + received DESC
    `,
      )
      .all(from, to)
    const daily = this.db.prepare(`
      SELECT day, SUM(sent) AS sent, SUM(received) AS received
      FROM usage_daily WHERE category = ? AND day BETWEEN ? AND ? GROUP BY day ORDER BY day
    `)
    // The game's series keeps its old name; the VPN's is reported beside it.
    const days = daily.all('total', from, to)
    const vpnDays = daily.all('vpn-total', from, to)
    return { from, to, totals, days, vpnDays }
  }

  reset() {
    this.db.exec('DELETE FROM usage_daily; VACUUM; PRAGMA wal_checkpoint(TRUNCATE)')
    this.pending.clear()
    // Keep the current counters as a baseline so the next poll cannot restore deleted traffic.
  }

  close() {
    this.flush()
    this.db.close()
  }
}

module.exports = { UsageStore, UsageSession, dayKey }
