const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const test = require('node:test')
const { UsageStore } = require('./usage.cjs')

test('usage deltas survive restarts and reset during a live session', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gamepath-usage-'))
  try {
    const store = new UsageStore(directory)
    const node = { id: 'node-1', name: 'North route' }
    store.start('session-1', [node])
    const snapshot = (sent, received, appSent) => ({
      userBytesSent: sent,
      userBytesReceived: received,
      paths: [{ route: 1, bytesSent: sent * 2, bytesReceived: received * 2 }],
      capture: {
        diagnostics: { captureId: 1, appUsage: [{ application: 'game.exe', bytesSent: appSent, bytesReceived: 0 }] },
      },
    })
    store.record(snapshot(100, 50, 80), new Date(2026, 8, 24, 12))
    store.record(snapshot(100, 50, 80), new Date(2026, 8, 24, 12))
    store.record(snapshot(130, 60, 110), new Date(2026, 8, 25, 12))
    assert.deepEqual(
      store.query('2026-09-24', '2026-09-25').days.map(({ sent, received }) => [sent, received]),
      [
        [100, 50],
        [30, 10],
      ],
    )
    assert.equal(store.query('2026-09-25', '2026-09-25').totals.find((row) => row.category === 'app').sent, 30)
    const renewedCapture = snapshot(140, 65, 15)
    renewedCapture.capture.diagnostics.captureId = 2
    store.record(renewedCapture, new Date(2026, 8, 25, 12))
    assert.equal(store.query('2026-09-25', '2026-09-25').totals.find((row) => row.category === 'app').sent, 45)
    store.reset()
    const afterReset = snapshot(160, 75, 35)
    afterReset.capture.diagnostics.captureId = 2
    store.record(afterReset, new Date(2026, 8, 25, 13))
    assert.equal(store.query('2026-09-24', '2026-09-25').totals.find((row) => row.category === 'total').sent, 20)
    store.start('session-2', [node])
    store.record(snapshot(10, 5, 8), new Date(2026, 8, 25, 14))
    assert.equal(store.query('2026-09-25', '2026-09-25').totals.find((row) => row.category === 'total').sent, 30)
    store.close()

    const reopened = new UsageStore(directory)
    assert.equal(reopened.query('2026-09-25', '2026-09-25').totals.find((row) => row.category === 'node').sent, 60)
    reopened.close()
  } finally {
    fs.rmSync(directory, { recursive: true, force: true })
  }
})

test('proxy devices are counted per address and survive a proxy restart', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gamepath-usage-'))
  try {
    const store = new UsageStore(directory)
    store.start('session-1', [])
    const at = new Date(2026, 8, 28, 20)
    const snapshot = (startedAt, sent) => ({
      userBytesSent: 0,
      userBytesReceived: 0,
      lanProxy: { startedAt, clients: [{ address: '192.168.1.40', bytesSent: sent, bytesReceived: sent * 10 }] },
    })
    store.record(snapshot(1, 100), at)
    store.record(snapshot(1, 150), at)
    // Restarted by a settings change: its counters begin again.
    store.record(snapshot(2, 30), at)
    const device = store.query('2026-09-28', '2026-09-28').totals.find((row) => row.category === 'device')
    assert.equal(device.identity, '192.168.1.40')
    assert.equal(device.sent, 180)
    assert.equal(device.received, 1800)
    store.close()
  } finally {
    fs.rmSync(directory, { recursive: true, force: true })
  }
})
