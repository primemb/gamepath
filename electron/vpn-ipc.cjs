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
const { createVpnDirect } = require('./vpn-direct-ipc.cjs')
const {
  sessionNodes,
  vpnRuleSpecs,
  nodeSetLimitation,
  assignedLimitation,
  unroutableRules,
  createRule,
  sameTarget,
  ruleConflicts,
  activeGameRules,
  selectedVpnNode,
  migrateVpnState,
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
  directLists,
}) {
  const state = () => getState()
  const vpn = () => state().vpn
  migrateVpnState(state())
  // Set between the game deciding to start in all-traffic mode and its
  // session existing, so the VPN is already out of the way when it does.
  let gameStartingAllTraffic = false
  let offeredOpenVpnFile = null
  let ruleQueue = Promise.resolve()
  let nodeQueue = Promise.resolve()
  // Assigned once the controller exists; read only when a session starts.
  let direct = null

  function changeNodes(change) {
    const operation = nodeQueue.then(change)
    nodeQueue = operation.catch(() => {})
    return operation
  }

  // The running game keeps the traffic mode it started with; the saved
  // setting can change under it and only applies to its next start.
  const pauseReason = () => {
    const game = state().session
    const mode = game.capture?.trafficMode ?? state().trafficMode
    return vpnPauseReason(game, mode) ?? (gameStartingAllTraffic ? 'game-all-traffic' : null)
  }

  function storedSecret(node) {
    const stored = state().encryptedVpnConfigs[node.id]
    let secret
    try {
      secret = stored && decrypt(stored)
    } catch {
      secret = null
    }
    if (!secret) {
      throw new VpnConfigError(`${node.name} is missing its stored secret. Remove it and add it again.`)
    }
    return secret
  }

  function buildRequest() {
    const settings = vpn()
    const node = selectedVpnNode(settings)
    if (!node) throw new VpnConfigError('Add a VPN node first.')
    const [blocked] = unroutableRules(settings)
    if (blocked) throw new VpnConfigError(assignedLimitation(settings, blocked))
    const nodes = sessionNodes(settings)
    const combined = nodeSetLimitation(nodes)
    if (combined) throw new VpnConfigError(combined)
    const rules = vpnRuleSpecs(settings, nodes)
    if (settings.trafficMode === 'split' && !rules.length) {
      throw new VpnConfigError('Add at least one app or website for the VPN, or switch it to all traffic.')
    }
    return {
      node,
      nodes,
      request: {
        mode: 'direct',
        trafficMode: settings.trafficMode,
        rules,
        remoteDns: settings.remoteDns,
        ownHostnames: ownHostnames(state()),
        killSwitch: settings.killSwitch,
        direct: direct.spec(),
        nodes: nodes.map((item) => nodeSpec(item, storedSecret(item))),
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

  direct = createVpnDirect({
    ipcMain,
    vpn,
    saveState,
    publicState,
    controller,
    store: directLists,
    logger,
  })

  function publicVpn() {
    const settings = vpn()
    const node = selectedVpnNode(settings)
    const limitations = Object.fromEntries(
      settings.rules
        .map((rule) => [rule.id, assignedLimitation(settings, rule)])
        .filter(([, limitation]) => limitation),
    )
    return {
      ...settings,
      node,
      session: controller.snapshot(),
      conflicts: ruleConflicts(settings.rules, activeGameRules(state().rules, state().ruleGroups)),
      limitations,
      nodeLimitation: nodeSetLimitation(sessionNodes(settings)),
      canSelectApps: !(node?.kind === 'l2tp' && settings.trafficMode === 'split'),
      direct: direct.publicDirect(node),
    }
  }

  /** Settings a running session cannot take live are applied by reconnecting. */
  function saveAndReconnect(why) {
    saveState()
    void controller.restart(why)
    return publicState()
  }

  function setNode(node, secret) {
    return changeNodes(() => {
      const sealed = encrypt(secret)
      const selected = !selectedVpnNode(vpn())
      vpn().nodes.push({ ...node, enabled: selected })
      if (selected) vpn().selectedNodeId = node.id
      state().encryptedVpnConfigs[node.id] = sealed
      logger.scope('vpn').info(`node added: kind=${node.kind} selected=${selected}`)
      saveState()
      return publicState()
    })
  }

  function selectNode(id) {
    return changeNodes(async () => {
      const node = vpn().nodes.find((item) => item.id === id)
      if (!node) throw new Error('That VPN node no longer exists.')
      if (id === vpn().selectedNodeId) return publicState()
      const proposed = { ...vpn(), selectedNodeId: id }
      const [blocked] = unroutableRules(proposed)
      if (blocked) throw new Error(assignedLimitation(proposed, blocked))
      const combined = nodeSetLimitation(sessionNodes(proposed))
      if (combined) throw new Error(combined)
      if (!state().encryptedVpnConfigs[id])
        throw new Error('That VPN node is missing its stored secret. Remove it and add it again.')
      vpn().selectedNodeId = id
      vpn().nodes = vpn().nodes.map((item) => ({ ...item, enabled: item.id === id }))
      saveState()
      await controller.restart('the default VPN node changed')
      vpn().wantConnected = controller.wanted
      saveState()
      return publicState()
    })
  }

  /**
   * Same contract as the game's rule edits: live, or not at all. The one
   * exception is a change to which nodes are in use, since a node joining or
   * leaving is a tunnel opening or closing: that reconnects the VPN.
   */
  function commitRuleChange(change) {
    const operation = ruleQueue.then(async () => {
      const previous = structuredClone(vpn().rules)
      change(vpn())
      const nodes = sessionNodes(vpn())
      const combined = nodeSetLimitation(nodes)
      if (combined) {
        vpn().rules = previous
        throw new Error(combined)
      }
      if (!controller.carriesNodes(nodes.map((node) => node.id))) {
        saveState()
        await controller.restart('the VPN nodes in use changed')
        return publicState()
      }
      try {
        await controller.applyRules(vpnRuleSpecs(vpn(), nodes), vpn().trafficMode)
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
    if (on && !selectedVpnNode(vpn())) throw new Error('Add a VPN node first.')
    vpn().wantConnected = on
    saveState()
    if (on) await controller.connect()
    else await controller.disconnect()
    if (vpn().wantConnected !== controller.wanted) {
      vpn().wantConnected = controller.wanted
      saveState()
    }
  }

  function readSecret(node = selectedVpnNode(vpn())) {
    const stored = node && state().encryptedVpnConfigs[node.id]
    if (!stored) throw new Error('The VPN node is missing its stored secret. Remove it and add it again.')
    return JSON.parse(decrypt(stored))
  }

  function register() {
    direct.register()
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
      return {
        canceled: false,
        state: await setNode(parseWireGuardConfig(source, filePath, crypto.randomUUID()), source),
      }
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

    ipcMain.handle('vpn:test-l2tp', (_event, input, nodeId) => {
      if (!service.ready()) throw new Error('Install and start the GamePath Network Service first')
      const node = nodeId === undefined ? selectedVpnNode(vpn()) : vpn().nodes.find((item) => item.id === nodeId)
      if (!input && node?.kind !== 'l2tp') throw new Error('The VPN node is not an L2TP/IPsec node')
      const credentials = input ? parseL2tpNode(input, 'probe').credentials : readSecret(node)
      return service.request('probe-l2tp-node', credentials, 60000)
    })

    // The proxy is tested the way the VPN uses it: a login, then a
    // connection out through it. No relay is involved.
    ipcMain.handle('vpn:test-socks5', (_event, input, nodeId) => {
      if (!engine.ready()) throw new Error('The native routing engine is unavailable')
      const saved = nodeId === undefined ? selectedVpnNode(vpn()) : vpn().nodes.find((item) => item.id === nodeId)
      if (!input && saved?.kind !== 'socks5') throw new Error('The VPN node is not a SOCKS5 proxy')
      const { node, credentials } = input
        ? parseSocks5Node(input, 'probe')
        : { node: saved, credentials: readSecret(saved) }
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

    ipcMain.handle('vpn:select-node', (_event, id) => selectNode(id))

    ipcMain.handle('vpn:remove-node', (_event, nodeId) =>
      changeNodes(async () => {
        const id = nodeId ?? vpn().selectedNodeId
        if (!vpn().nodes.some((node) => node.id === id)) throw new Error('That VPN node no longer exists.')
        const selected = id === vpn().selectedNodeId
        const inUse = !selected && sessionNodes(vpn()).some((node) => node.id === id)
        if (selected) {
          vpn().wantConnected = false
          await controller.disconnect()
        }
        vpn().nodes = vpn().nodes.filter((node) => node.id !== id)
        if (selected) {
          vpn().selectedNodeId = vpn().nodes[0]?.id ?? null
          vpn().nodes = vpn().nodes.map((node) => ({ ...node, enabled: node.id === vpn().selectedNodeId }))
        }
        // Its targets stay, on the default node.
        vpn().rules = vpn().rules.map((rule) => (rule.nodeId === id ? { ...rule, nodeId: null } : rule))
        delete state().encryptedVpnConfigs[id]
        logger.scope('vpn').info(`node removed: selected=${selected} inUse=${inUse}`)
        saveState()
        if (inUse) await controller.restart('a VPN node in use was removed')
        return publicState()
      }),
    )

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
      if (rule.nodeId && !vpn().nodes.some((node) => node.id === rule.nodeId)) {
        throw new Error('That VPN node no longer exists.')
      }
      if (vpn().rules.some((existing) => sameTarget(existing, rule))) {
        throw new Error(`${rule.label} is already in the list. Choose its node there instead.`)
      }
      const limitation = assignedLimitation(vpn(), rule)
      if (limitation) throw new Error(limitation)
      return commitRuleChange((settings) => settings.rules.push(rule))
    })

    // Null puts the target back on the default node.
    ipcMain.handle('vpn:set-rule-node', (_event, id, nodeId) => {
      const target = nodeId ? vpn().nodes.find((node) => node.id === nodeId) : null
      if (nodeId && !target) throw new Error('That VPN node no longer exists.')
      const rule = vpn().rules.find((item) => item.id === id)
      if (!rule) throw new Error('That target no longer exists.')
      const limitation = assignedLimitation(vpn(), { ...rule, nodeId: target?.id ?? null })
      if (limitation) throw new Error(limitation)
      return commitRuleChange((settings) => {
        const current = settings.rules.find((item) => item.id === id)
        if (current) current.nodeId = target?.id ?? null
      })
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
      if (vpn().wantConnected && selectedVpnNode(vpn())) return controller.connect()
      return Promise.resolve()
    },
    setWanted,
    onPowerResume: () => controller.onResume(),
    shutdown: () => {
      direct.shutdown()
      return controller.shutdown()
    },
  }
}

module.exports = { createVpnFeature }
