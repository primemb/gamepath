'use strict'

const crypto = require('node:crypto')
const { CATALOG } = require('./direct-lists.cjs')
const { createDirectEntry, sameEntry, directLimitation, directSpec } = require('./vpn-direct-state.cjs')
const { selectedVpnNode } = require('./vpn-state.cjs')

/** First check a minute and a half after launch, then twice a day. */
const REFRESH_DELAY_MS = 90 * 1000
const REFRESH_INTERVAL_MS = 12 * 60 * 60 * 1000

/**
 * The VPN's direct sites: IPC for the lists and the user's own entries, and
 * the spec each session start sends. Every change applies to a running VPN
 * live, without reconnecting it, or not at all.
 */
function createVpnDirect({ ipcMain, vpn, saveState, publicState, controller, store, logger }) {
  const log = logger.scope('direct')
  let queue = Promise.resolve()
  let refreshTimer = null

  /** What a session is sent, or null when nothing is direct. */
  const spec = () =>
    directLimitation(selectedVpnNode(vpn())) ? null : directSpec(vpn().direct, (id) => store.entries(id))

  function commit(change) {
    const operation = queue.then(async () => {
      const previous = structuredClone(vpn().direct)
      change(vpn().direct)
      try {
        await controller.applyDirect(spec())
        saveState()
        return publicState()
      } catch (error) {
        vpn().direct = previous
        try {
          await controller.applyDirect(spec())
        } catch (rollbackError) {
          log.error(`could not restore the direct list: ${rollbackError.message}`)
        }
        throw error
      }
    })
    queue = operation.catch(() => {})
    return operation
  }

  /** Downloads whichever of `ids` are not on this machine yet. */
  async function ensureDownloaded(ids) {
    for (const id of ids) if (!store.has(id)) await store.download(id)
  }

  async function setEnabled(enabled) {
    if (!enabled) return commit((direct) => (direct.enabled = false))
    const direct = vpn().direct
    // First time on: start from the lists Throne's Bypass Iran profile uses.
    const lists = direct.lists.length || direct.entries.length ? direct.lists : CATALOG.map((list) => list.id)
    await ensureDownloaded(lists)
    return commit((next) => {
      next.enabled = true
      next.lists = lists
    })
  }

  async function setList(id, on) {
    if (!CATALOG.some((list) => list.id === id)) throw new Error('That list no longer exists.')
    if (on) await ensureDownloaded([id])
    return commit((direct) => {
      direct.lists = on ? [...new Set([...direct.lists, id])] : direct.lists.filter((item) => item !== id)
    })
  }

  /** Fresh copies of `ids`; the running VPN picks them up live. */
  async function update(ids) {
    const failures = []
    for (const id of ids) {
      try {
        await store.download(id)
      } catch (error) {
        failures.push(error)
      }
    }
    const state = await commit(() => {})
    if (failures.length === ids.length) throw failures[0]
    return state
  }

  async function refreshStale() {
    const direct = vpn().direct
    const stale = direct.enabled ? direct.lists.filter((id) => store.has(id) && store.isStale(id)) : []
    if (!stale.length) return
    log.info(`refreshing ${stale.length} direct list(s) older than a week`)
    try {
      await update(stale)
    } catch (error) {
      log.warn(`direct lists not refreshed: ${error.message}`)
    }
  }

  function register() {
    ipcMain.handle('vpn:set-direct-enabled', (_event, enabled) => setEnabled(Boolean(enabled)))
    ipcMain.handle('vpn:set-direct-list', (_event, id, on) => setList(id, Boolean(on)))
    ipcMain.handle('vpn:update-direct-lists', (_event, ids) =>
      update((Array.isArray(ids) ? ids : CATALOG.map((list) => list.id)).filter((id) => typeof id === 'string')),
    )
    ipcMain.handle('vpn:add-direct-entry', (_event, value) => {
      const entry = createDirectEntry(value, crypto.randomUUID())
      if (vpn().direct.entries.some((item) => sameEntry(item, entry))) {
        throw new Error(`${entry.value} is already on the direct list.`)
      }
      return commit((direct) => direct.entries.push(entry))
    })
    ipcMain.handle('vpn:set-direct-entry-enabled', (_event, id, enabled) =>
      commit((direct) => {
        const entry = direct.entries.find((item) => item.id === id)
        if (entry) entry.enabled = Boolean(enabled)
      }),
    )
    ipcMain.handle('vpn:remove-direct-entry', (_event, id) =>
      commit((direct) => {
        direct.entries = direct.entries.filter((item) => item.id !== id)
      }),
    )
    const scheduleRefresh = (delay) => {
      refreshTimer = setTimeout(() => {
        void refreshStale().finally(() => scheduleRefresh(REFRESH_INTERVAL_MS))
      }, delay)
      refreshTimer.unref?.()
    }
    scheduleRefresh(REFRESH_DELAY_MS)
  }

  /** What the window is shown: settings, list status, and any limitation. */
  function publicDirect(node) {
    return { ...vpn().direct, catalog: store.describe(), limitation: directLimitation(node) }
  }

  return {
    register,
    spec,
    publicDirect,
    shutdown: () => clearTimeout(refreshTimer),
  }
}

module.exports = { createVpnDirect }
