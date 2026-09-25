const path = require('node:path')
const { DatabaseSync } = require('node:sqlite')

const dayKey = (date) => {
  const local = new Date(date)
  return `${local.getFullYear()}-${String(local.getMonth() + 1).padStart(2, '0')}-${String(local.getDate()).padStart(2, '0')}`
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
    this.last = new Map()
    this.session = null
    this.captureId = null
  }

  start(session, nodes) {
    this.flush()
    this.last.clear()
    this.captureId = null
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
    const pendingKey = `${day}\0${key}`
    const entry = this.pending.get(pendingKey) ?? { day, category, identity, label, sent: 0, received: 0 }
    entry.sent += sentDelta
    entry.received += receivedDelta
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
    const days = this.db
      .prepare(
        `
      SELECT day, SUM(sent) AS sent, SUM(received) AS received
      FROM usage_daily WHERE category = 'total' AND day BETWEEN ? AND ? GROUP BY day ORDER BY day
    `,
      )
      .all(from, to)
    return { from, to, totals, days }
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

module.exports = { UsageStore, dayKey }
