'use strict'

const crypto = require('node:crypto')
const fs = require('node:fs')
const path = require('node:path')
const { parseWireGuardConfig } = require('./wireguard.cjs')
const { parseOpenVpnConfig } = require('./openvpn.cjs')
const { parseSocks5Node } = require('./socks5.cjs')
const { parseL2tpNode } = require('./l2tp.cjs')
const { nodeSpec } = require('./node-spec.cjs')
const { ownHostnames } = require('./own-hostnames.cjs')
const { vpnPauseReason } = require('./session-coordinator.cjs')
const { VpnSessionController, VpnConfigError } = require('./vpn-session.cjs')
const {
  vpnRuleSpecs,
  ruleLimitation,
  unroutableRules,
  createRule,
  ruleConflicts,
  activeGameRules,
} = require('./vpn-state.cjs')

/**
 * The VPN section of the main process: its IPC channels, its node and rules,
 * and the controller that runs its session.
 *
 * Everything the game session owns is only ever read here. The two touch at
 * exactly one point, `pauseReason`, which is how the game makes the VPN step
 * aside.
 */
function createVpnFeature({
  ipcMain,
  dialog,
  getState,
  saveState,
  publicState,
  encrypt,
  decrypt,
  service,
  engine,
  logger,
  usage,
  onChange,
}) {
  const state = () => getState()
  const vpn = () => state().vpn
  // Set between the game deciding to start in all-traffic mode and its
  // session existing, so the VPN is already out of the way when it does.
  let gameStartingAllTraffic = false
  let offeredOpenVpnFile = null
  let ruleQueue = Promise.resolve()

  // The running game keeps the traffic mode it started with; the saved
  // setting can change under it and only applies to its next start.
  const pauseReason = () => {
    const game = state().session
    const mode = game.capture?.trafficMode ?? state().trafficMode
    return vpnPauseReason(game, mode) ?? (gameStartingAllTraffic ? 'game-all-traffic' : null)
  }

  function buildRequest() {
    const settings = vpn()
    if (!settings.node) throw new VpnConfigError('Add a VPN node first.')
    const [blocked] = unroutableRules(settings)
    if (blocked)
      throw new VpnConfigError(ruleLimitation(settings.node, settings.trafficMode, blocked.kind, blocked.value))
    const rules = vpnRuleSpecs(settings)
    if (settings.trafficMode === 'split' && !rules.length) {
      throw new VpnConfigError('Add at least one app or website for the VPN, or switch it to all traffic.')
    }
    const stored = state().encryptedVpnConfig
    let secret
    try {
      secret = stored && decrypt(stored)
    } catch {
      secret = null
    }
    if (!secret) {
      throw new VpnConfigError(`${settings.node.name} is missing its stored secret. Remove it and add it again.`)
    }
    return {
      node: settings.node,
      request: {
        mode: 'direct',
        trafficMode: settings.trafficMode,
        rules,
        remoteDns: settings.remoteDns,
        ownHostnames: ownHostnames(state()),
        killSwitch: settings.killSwitch,
        nodes: [nodeSpec(settings.node, secret)],
      },
    }
  }

  const controller = new VpnSessionController({
    service,
    logger,
    buildRequest,
    pauseReason,
    usage,
    onChange,
  })

  function publicVpn() {
    const settings = vpn()
    const limitations = Object.fromEntries(
      settings.rules
        .map((rule) => [rule.id, ruleLimitation(settings.node, settings.trafficMode, rule.kind, rule.value)])
        .filter(([, limitation]) => limitation),
    )
    return {
      ...settings,
      session: controller.snapshot(),
      conflicts: ruleConflicts(settings.rules, activeGameRules(state().rules, state().ruleGroups)),
      limitations,
      canSelectApps: !(settings.node?.kind === 'l2tp' && settings.trafficMode === 'split'),
    }
  }

  /** Settings a running session cannot take live are applied by reconnecting. */
  function saveAndReconnect(why) {
    saveState()
    void controller.restart(why)
    return publicState()
  }

  function setNode(node, secret) {
    const replacing = vpn().node
    vpn().node = { ...node, enabled: true }
    state().encryptedVpnConfig = encrypt(secret)
    logger.scope('vpn').info(`${replacing ? 'node replaced' : 'node added'}: kind=${node.kind}`)
    return saveAndReconnect('the VPN node changed')
  }

  /** Same contract as the game's rule edits: live, or not at all. */
  function commitRuleChange(change) {
    const operation = ruleQueue.then(async () => {
      const previous = structuredClone(vpn().rules)
      change(vpn())
      try {
        await controller.applyRules(vpnRuleSpecs(vpn()), vpn().trafficMode)
        saveState()
        return publicState()
      } catch (error) {
        vpn().rules = previous
        try {
          await controller.applyRules(vpnRuleSpecs(vpn()), vpn().trafficMode)
        } catch (rollbackError) {
          logger.scope('vpn').error(`could not restore live targets: ${rollbackError.message}`)
        }
        throw error
      }
    })
    ruleQueue = operation.catch(() => {})
    return operation
  }

  /**
   * Turns the VPN on or off, for the window and the tray alike. The saved
   * wish follows what the controller settled on, so a VPN that cannot start
   * for a reason retrying will not fix is not retried at the next launch.
   */
  async function setWanted(on) {
    if (on && !vpn().node) throw new Error('Add a VPN node first.')
    vpn().wantConnected = on
    saveState()
    if (on) await controller.connect()
    else await controller.disconnect()
    if (vpn().wantConnected !== controller.wanted) {
      vpn().wantConnected = controller.wanted
      saveState()
    }
  }

  function readSecret() {
    const stored = state().encryptedVpnConfig
    if (!stored) throw new Error('The VPN node is missing its stored secret. Remove it and add it again.')
    return JSON.parse(decrypt(stored))
  }

  function register() {
    ipcMain.handle('vpn:import-wireguard', async () => {
      const result = await dialog.showOpenDialog({
        title: 'Choose a WireGuard configuration for the VPN',
        buttonLabel: 'Use this file',
        properties: ['openFile'],
        filters: [{ name: 'WireGuard configuration', extensions: ['conf'] }],
      })
      if (result.canceled) return { canceled: true }
      const filePath = result.filePaths[0]
      const source = fs.readFileSync(filePath, 'utf8')
      return { canceled: false, state: setNode(parseWireGuardConfig(source, filePath, crypto.randomUUID()), source) }
    })

    // Like the game's OpenVPN import: the file body stays here, the window
    // only learns what it is and whether it wants a login.
    ipcMain.handle('vpn:choose-openvpn', async () => {
      const result = await dialog.showOpenDialog({
        title: 'Choose an OpenVPN configuration for the VPN',
        buttonLabel: 'Choose file',
        properties: ['openFile'],
        filters: [{ name: 'OpenVPN configuration', extensions: ['ovpn'] }],
      })
      if (result.canceled) return { canceled: true }
      const filePath = result.filePaths[0]
      const node = parseOpenVpnConfig(fs.readFileSync(filePath, 'utf8'), filePath, 'preview')
      offeredOpenVpnFile = filePath
      return {
        canceled: false,
        file: {
          path: filePath,
          name: node.name,
          endpoint: node.endpoint,
          protocol: node.protocol,
          wantsCredentials: node.wantsCredentials,
        },
      }
    })

    ipcMain.handle('vpn:add-openvpn', (_event, input) => {
      if (!offeredOpenVpnFile || input?.filePath !== offeredOpenVpnFile) {
        throw new Error('That file is no longer the one you chose. Choose it again.')
      }
      const source = fs.readFileSync(offeredOpenVpnFile, 'utf8')
      const node = parseOpenVpnConfig(source, offeredOpenVpnFile, crypto.randomUUID())
      const username = String(input?.username ?? '').trim()
      if (node.wantsCredentials && !username) throw new Error('This file needs a username and password.')
      offeredOpenVpnFile = null
      return setNode(
        { ...node, hasCredentials: Boolean(username) },
        JSON.stringify({ config: source, username: username || null, password: input?.password || null }),
      )
    })

    ipcMain.handle('vpn:add-socks5', (_event, input) => {
      const { node, credentials } = parseSocks5Node(input ?? {}, crypto.randomUUID())
      return setNode(node, JSON.stringify(credentials))
    })

    ipcMain.handle('vpn:add-l2tp', (_event, input) => {
      const { node, credentials } = parseL2tpNode(input ?? {}, crypto.randomUUID())
      return setNode(node, JSON.stringify(credentials))
    })

    ipcMain.handle('vpn:test-l2tp', (_event, input) => {
      if (!service.ready()) throw new Error('Install and start the GamePath Network Service first')
      const credentials = input ? parseL2tpNode(input, 'probe').credentials : readSecret()
      return service.request('probe-l2tp-node', credentials, 60000)
    })

    // The proxy is tested the way the VPN uses it: a login, then a
    // connection out through it. No relay is involved.
    ipcMain.handle('vpn:test-socks5', (_event, input) => {
      if (!engine.ready()) throw new Error('The native routing engine is unavailable')
      const { node, credentials } = input
        ? parseSocks5Node(input, 'probe')
        : { node: vpn().node, credentials: readSecret() }
      if (node?.kind !== 'socks5') throw new Error('The VPN node is not a SOCKS5 proxy')
      return engine.request(
        'probe-socks5-proxy',
        {
          host: node.host,
          port: node.port,
          username: credentials.username || null,
          password: credentials.password || null,
        },
        20000,
      )
    })

    ipcMain.handle('vpn:remove-node', async () => {
      vpn().wantConnected = false
      await controller.disconnect()
      vpn().node = null
      delete state().encryptedVpnConfig
      logger.scope('vpn').info('node removed')
      saveState()
      return publicState()
    })

    ipcMain.handle('vpn:set-traffic-mode', (_event, mode) => {
      if (mode !== 'split' && mode !== 'all') throw new Error('Unknown traffic mode')
      vpn().trafficMode = mode
      return saveAndReconnect(`traffic mode changed to ${mode}`)
    })

    ipcMain.handle('vpn:set-remote-dns', (_event, enabled) => {
      vpn().remoteDns = Boolean(enabled)
      return saveAndReconnect(`remote DNS ${enabled ? 'on' : 'off'}`)
    })

    ipcMain.handle('vpn:set-kill-switch', (_event, enabled) => {
      vpn().killSwitch = Boolean(enabled)
      return saveAndReconnect(`kill switch ${enabled ? 'on' : 'off'}`)
    })

    ipcMain.handle('vpn:browse-target', async (_event, kind) => {
      if (kind !== 'application' && kind !== 'folder') return { canceled: true }
      const result = await dialog.showOpenDialog({
        title: kind === 'application' ? 'Choose an application for the VPN' : 'Choose a folder for the VPN',
        buttonLabel: 'Use this target',
        properties: kind === 'application' ? ['openFile'] : ['openDirectory'],
        filters: kind === 'application' ? [{ name: 'Windows applications', extensions: ['exe'] }] : undefined,
      })
      if (result.canceled) return { canceled: true }
      const value = result.filePaths[0]
      return { canceled: false, value, label: path.basename(value) }
    })

    ipcMain.handle('vpn:add-rule', (_event, input) => {
      const rule = createRule(input, crypto.randomUUID())
      const limitation = ruleLimitation(vpn().node, vpn().trafficMode, rule.kind, rule.value)
      if (limitation) throw new Error(limitation)
      return commitRuleChange((settings) => settings.rules.push(rule))
    })

    ipcMain.handle('vpn:set-rule-enabled', (_event, id, enabled) =>
      commitRuleChange((settings) => {
        const rule = settings.rules.find((item) => item.id === id)
        if (rule) rule.enabled = Boolean(enabled)
      }),
    )

    ipcMain.handle('vpn:remove-rule', (_event, id) =>
      commitRuleChange((settings) => {
        settings.rules = settings.rules.filter((item) => item.id !== id)
      }),
    )

    ipcMain.handle('vpn:connect', async () => {
      await setWanted(true)
      return publicState()
    })

    ipcMain.handle('vpn:disconnect', async () => {
      await setWanted(false)
      return publicState()
    })

    ipcMain.handle('vpn:status', () => publicState())
  }

  return {
    controller,
    register,
    publicVpn,
    /** Before the game starts: in all-traffic mode the VPN leaves first. */
    async beforeGameStart() {
      if (state().trafficMode !== 'all') return
      gameStartingAllTraffic = true
      await controller.reconsider()
    },
    /** After any game session transition: pause or resume to match. */
    gameChanged() {
      gameStartingAllTraffic = false
      return controller.reconsider()
    },
    /** At launch: a VPN the user left on comes back on. */
    resume() {
      if (vpn().wantConnected && vpn().node) return controller.connect()
      return Promise.resolve()
    },
    setWanted,
    onPowerResume: () => controller.onResume(),
    shutdown: () => controller.shutdown(),
  }
}

module.exports = { createVpnFeature }
