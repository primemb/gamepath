const { app, BrowserWindow, dialog, ipcMain, safeStorage, shell } = require('electron')
const { spawn } = require('node:child_process')
const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')
const { parseWireGuardConfig } = require('./wireguard.cjs')
const { parseOpenVpnConfig } = require('./openvpn.cjs')
const { parseSocks5Node } = require('./socks5.cjs')
const { directNodeSelection, directSelectionAfterSwitch } = require('./connection.cjs')
const { EngineBridge } = require('./engine.cjs')
const { ServiceBridge } = require('./service.cjs')
const { provisionRelay, removeRelay } = require('./vps.cjs')
const { createIpCountryLookup } = require('./ip-country.cjs')

const lookupIpCountry = createIpCountryLookup()

const defaultState = () => ({
  tunnels: [],
  encryptedConfigs: {},
  encryptedRelayTokens: {},
  rules: [],
  ruleGroups: [],
  trafficMode: 'split',
  connectionMode: 'relay',
  relays: [
    {
      id: 'tr-istanbul-01',
      city: 'Istanbul',
      country: 'Turkey',
      code: 'TR',
      address: '',
      port: 51821,
      status: 'setup-required',
      hasEnrollmentToken: false,
    },
  ],
  activeRelayId: 'tr-istanbul-01',
  session: { status: 'idle' },
})

let state
let engineBridge
let serviceBridge

function statePath() {
  return path.join(app.getPath('userData'), 'gamepath-state.json')
}

function publicState() {
  const { encryptedConfigs, encryptedRelayTokens, ...safeState } = state
  return structuredClone({
    ...safeState,
    clientVersion: app.getVersion(),
    engine: engineBridge?.status ?? {
      status: 'offline',
      version: '',
      message: 'Native engine is starting',
      capabilities: null,
    },
    service: serviceBridge?.status ?? {
      status: 'offline',
      version: '',
      message: 'Network service is starting',
      elevated: false,
    },
  })
}

function loadState() {
  try {
    const loaded = JSON.parse(fs.readFileSync(statePath(), 'utf8'))
    state = { ...defaultState(), ...loaded, session: { status: 'idle' } }
    state.encryptedRelayTokens ??= {}
    state.ruleGroups = Array.isArray(state.ruleGroups) ? state.ruleGroups : []
    const groupIds = new Set(state.ruleGroups.map((group) => group.id))
    state.rules = state.rules.map((rule) => ({
      ...rule,
      groupId: groupIds.has(rule.groupId) ? rule.groupId : null,
    }))
    // Sessions saved before direct mode existed all went through a relay.
    if (state.connectionMode !== 'direct') state.connectionMode = 'relay'
    // Nodes imported before SOCKS5 support existed are all WireGuard routes.
    state.tunnels = state.tunnels.map((tunnel) => ({ kind: 'wireguard', ...tunnel }))
    state.relays = state.relays.map((relay) => {
      const hasEnrollmentToken = Boolean(state.encryptedRelayTokens[relay.id])
      const normalized = { port: 51821, ...relay, hasEnrollmentToken }
      normalized.status = normalized.address && hasEnrollmentToken ? 'ready' : 'setup-required'
      return normalized
    })
  } catch {
    state = defaultState()
  }
}

function saveState() {
  const destination = statePath()
  const temporary = `${destination}.tmp`
  fs.mkdirSync(path.dirname(destination), { recursive: true })
  fs.writeFileSync(temporary, JSON.stringify(state, null, 2), { encoding: 'utf8', mode: 0o600 })
  fs.renameSync(temporary, destination)
}

/**
 * The `.ovpn` files the picker last offered.
 *
 * A retry sends paths back rather than making the user choose the same files
 * again, and this is what makes that safe: nothing outside the set the user
 * themselves selected is ever read.
 */
let offeredOpenVpnFiles = new Set()

function encryptConfig(source) {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('Windows secure storage is unavailable')
  }
  return safeStorage.encryptString(source).toString('base64')
}

function relaySessionMessage(plan, paths, dataPlane) {
  // A skipped route is one that is enabled but not in the session: it either
  // duplicates another node's endpoint, or it could not be dialled. Saying so
  // matters — the session runs without it, and nothing else would mention it.
  const skipped = paths.skippedRoutes ?? []
  const note = skipped.length
    ? ` ${skipped.length} node${skipped.length === 1 ? '' : 's'} did not join: ${skipped
        .map((route) => `${route.label} (${route.reason})`)
        .join('; ')}.`
    : ''
  return `Session ${plan.planId} is keeping ${paths.paths.length} encrypted paths connected; benchmark packet loop verified in ${Math.round(dataPlane.latencyMs)} ms.${note}`
}

function directSessionMessage(plan, node, dataPlane) {
  // A node that filters the test ping is still a working node, so say what was
  // and was not measured instead of implying something went wrong.
  const measured = dataPlane.reachable
    ? `benchmark packet loop verified in ${Math.round(dataPlane.latencyMs)} ms`
    : 'the node does not answer test pings, so only its own traffic is measured'
  return `Session ${plan.planId} is routing selected traffic through ${node.name}; ${measured}.`
}

/**
 * How often the main process renews the service's session lease. Well inside
 * the service's SESSION_LEASE so a slow request or two cannot expire it.
 */
const SESSION_POLL_MS = 3000

/**
 * Consecutive failed polls before the session is given up.
 *
 * The service's lease is far longer than this many polls, so retrying costs
 * nothing and a transient loopback hiccup no longer ends a working session.
 * Tearing down on the first failure is what turned one bad reply into a
 * disconnect after thirty-seven minutes of clean play.
 */
const SESSION_POLL_MAX_FAILURES = 3

const logger = require('./logger.cjs')
const { deriveJourney } = require('./journey.cjs')

let sessionKeepAlive = null
let sessionPollInFlight = false
// Only a change in the relay's view is worth a line; the poll runs every few
// seconds and logging each one would bury everything else.
let lastRuntimeState = null
let sessionPollFailures = 0

function updateSessionMetrics(runtime, dataPlane) {
  const paths = runtime.paths ?? []
  const fastest = paths
    .filter((path) => path.reachable)
    .sort((left, right) => (left.latencyMs ?? Infinity) - (right.latencyMs ?? Infinity))[0]
  const sent = paths.reduce((total, path) => total + path.packetsSent, 0)
  const received = paths.reduce((total, path) => total + path.packetsReceived, 0)
  const probesReceived = paths.reduce((total, path) => total + (path.probesReceived ?? 0), 0)
  const probesLost = paths.reduce((total, path) => total + (path.probesLost ?? 0), 0)
  const completedProbes = probesReceived + probesLost
  const direct = (runtime.mode ?? state.session.mode) === 'direct'
  const journey = deriveJourney({
    paths,
    selectedRoutes: runtime.selectedRoutes ?? [],
    direct,
  })
  // A direct session's node is the last hop, so there is no second leg to
  // report — reporting one would invent a hop the traffic never takes.
  state.session.mode = runtime.mode ?? state.session.mode ?? 'relay'
  state.session.pathMetrics = paths
  state.session.selectedRoutes = runtime.selectedRoutes ?? []
  // Routes the session is running without. A multipath session starts on the
  // routes that answered, so these have to be named rather than implied by a
  // route missing from the selection.
  state.session.degradedRoutes = runtime.degradedRoutes ?? []
  state.session.skippedRoutes = runtime.skippedRoutes ?? []
  state.session.strategy = runtime.strategy ?? 'adaptive'
  if (runtime.effectiveMtu) {
    state.session.transport = {
      effectiveMtu: runtime.effectiveMtu,
      overheadBytes: runtime.transportOverhead ?? null,
      queueCapacity: runtime.queueCapacity ?? null,
      queueDepth: runtime.queueDepth ?? [],
      droppedPackets: runtime.droppedPackets ?? [],
    }
  }
  if (runtime.capture) state.session.capture = runtime.capture
  state.session.routeLatencies = paths
    .filter((path) => path.latencyMs != null)
    .map((path) => Math.max(1, Math.round(path.latencyMs)))
  state.session.journey = journey
  state.session.metrics = {
    userToNodeMs: journey.userToNodeMs,
    nodeToRelayMs: journey.nodeToRelayMs,
    relayToServerMs: dataPlane?.relayToServerMs ?? state.session.metrics?.relayToServerMs ?? null,
    endToEndMs: dataPlane?.latencyMs ?? state.session.metrics?.endToEndMs ?? null,
    benchmarkServer: dataPlane?.benchmarkServer ?? state.session.metrics?.benchmarkServer ?? '',
    bytesSent: paths.reduce((total, path) => total + path.bytesSent, 0),
    bytesReceived: paths.reduce((total, path) => total + path.bytesReceived, 0),
    packetsSent: sent,
    packetsReceived: received,
    packetLossPercent: completedProbes ? (probesLost / completedProbes) * 100 : 0,
  }
}

/**
 * Decrypts each enabled node into the tagged list the engine expects. Secrets
 * live in Windows secure storage until this moment and never reach the
 * renderer: a WireGuard node yields its configuration body, a SOCKS5 node its
 * stored credentials, and an OpenVPN node both its file and its credentials.
 */
function sessionNodes(enabledTunnels) {
  return enabledTunnels.map((tunnel) => {
    const stored = state.encryptedConfigs[tunnel.id]
    if (!stored) {
      throw new Error(`${tunnel.name} is missing its stored secret. Remove the node and add it again.`)
    }
    const secret = safeStorage.decryptString(Buffer.from(stored, 'base64'))
    if (tunnel.kind === 'socks5') {
      const { username, password } = JSON.parse(secret)
      return {
        kind: 'socks5',
        host: tunnel.host,
        port: tunnel.port,
        username: username || null,
        password: password || null,
        label: tunnel.name,
      }
    }
    if (tunnel.kind === 'openvpn') {
      const { config, username, password } = JSON.parse(secret)
      return {
        kind: 'openvpn',
        config,
        username: username || null,
        password: password || null,
        label: tunnel.name,
      }
    }
    return { kind: 'wireguard', config: secret, label: tunnel.name }
  })
}

/**
 * Asks the relay to answer through the proxy.
 *
 * Accepting a UDP association proves nothing about whether the relay is
 * reachable through it, so the check that matters is an authenticated frame
 * making the round trip. That is what a session waits for, and what this
 * reports.
 */
function probeSocks5Node(host, port, credentials) {
  if (engineBridge?.status.status !== 'ready') throw new Error('The native routing engine is unavailable')
  const { relay, enrollmentToken } = activeRelayWithToken()
  return engineBridge.request(
    'probe-socks5-node',
    {
      relayHost: relay.address,
      relayPort: relay.port,
      enrollmentToken,
      host,
      port,
      username: credentials.username || null,
      password: credentials.password || null,
    },
    20000,
  )
}

function activeRelayWithToken() {
  const relay = state.relays.find((item) => item.id === state.activeRelayId)
  const encryptedToken = relay && state.encryptedRelayTokens[relay.id]
  if (!relay?.address || !encryptedToken) {
    // Only a relay can answer a proxy's authenticated probe, so this is also
    // what a direct-mode user sees when testing a SOCKS5 node.
    throw new Error('Testing a SOCKS5 node needs a relay. Configure its address and enrollment token first.')
  }
  return { relay, enrollmentToken: safeStorage.decryptString(Buffer.from(encryptedToken, 'base64')) }
}

function registerIpc() {
  ipcMain.handle('app:bootstrap', () => publicState())
  ipcMain.handle('ip-country:lookup', (_event, target) => lookupIpCountry(String(target ?? '').slice(0, 300)))

  ipcMain.handle('node:add-socks5', (_event, input) => {
    const { node, credentials } = parseSocks5Node(input ?? {}, crypto.randomUUID())
    if (state.tunnels.some((item) => item.kind === 'socks5' && item.endpoint === node.endpoint)) {
      throw new Error(`${node.endpoint} is already added. Two associations on one proxy carry no extra path.`)
    }
    state.tunnels.push(node)
    state.encryptedConfigs[node.id] = encryptConfig(JSON.stringify(credentials))
    saveState()
    return { state: publicState(), nodeId: node.id }
  })

  // Accepting UDP ASSOCIATE is not proof a proxy can carry GamePath traffic,
  // so this asks the relay for an authenticated reply through the proxy.
  ipcMain.handle('node:test-socks5', async (_event, input) => {
    const { node, credentials } = parseSocks5Node(input ?? {}, 'probe')
    return probeSocks5Node(node.host, node.port, credentials)
  })

  // Testing a node that is already saved reads its credentials back out of
  // secure storage, so nobody has to retype a password to re-run a check.
  ipcMain.handle('node:test-saved-socks5', async (_event, id) => {
    const tunnel = state.tunnels.find((item) => item.id === id)
    if (tunnel?.kind !== 'socks5') throw new Error('That node is not a SOCKS5 proxy')
    const stored = state.encryptedConfigs[tunnel.id]
    if (!stored) {
      throw new Error(`${tunnel.name} is missing its stored secret. Remove the node and add it again.`)
    }
    return probeSocks5Node(
      tunnel.host,
      tunnel.port,
      JSON.parse(safeStorage.decryptString(Buffer.from(stored, 'base64'))),
    )
  })

  // Choosing the files comes first, because only the files can say whether a
  // login is even wanted. Nothing is stored here: this reads each file, reports
  // what it is, and leaves the decision to the window.
  //
  // Only metadata goes back. The file body stays in this process, since it can
  // carry a private key.
  ipcMain.handle('openvpn:choose', async () => {
    const result = await dialog.showOpenDialog({
      title: 'Choose OpenVPN configurations',
      buttonLabel: 'Choose files',
      properties: ['openFile', 'multiSelections'],
      filters: [{ name: 'OpenVPN configuration', extensions: ['ovpn'] }],
    })
    if (result.canceled) return { canceled: true }
    offeredOpenVpnFiles = new Set(result.filePaths)

    const files = []
    const failures = []
    for (const filePath of result.filePaths) {
      try {
        const source = fs.readFileSync(filePath, 'utf8')
        const node = parseOpenVpnConfig(source, filePath, 'preview')
        files.push({
          path: filePath,
          name: node.name,
          endpoint: node.endpoint,
          protocol: node.protocol,
          wantsCredentials: node.wantsCredentials,
        })
      } catch (error) {
        failures.push({ file: path.basename(filePath), path: filePath, message: error.message })
      }
    }
    return { canceled: false, files, failures }
  })

  // Adds the files already chosen, with the login if they asked for one. Only
  // paths the picker itself offered are read, so the window cannot use this to
  // ask for the contents of an arbitrary file.
  ipcMain.handle('openvpn:add', (_event, input) => {
    const requested = Array.isArray(input?.filePaths) ? input.filePaths : []
    if (!requested.length) throw new Error('No files were chosen.')
    const unknown = requested.find((filePath) => !offeredOpenVpnFiles.has(filePath))
    if (unknown) throw new Error('Those files are no longer the ones you chose. Choose them again.')

    const username = String(input?.username ?? '').trim()
    const credentials = { username: username || null, password: input?.password || null }

    const failures = []
    let added = 0
    for (const filePath of requested) {
      try {
        const source = fs.readFileSync(filePath, 'utf8')
        const node = parseOpenVpnConfig(source, filePath, crypto.randomUUID())
        if (node.wantsCredentials && !credentials.username) {
          throw new Error('This file needs a username and password, and none were entered.')
        }
        state.tunnels.push({ ...node, hasCredentials: Boolean(credentials.username) })
        // The file itself can carry a private key, so it is stored the same way
        // a WireGuard configuration is and never leaves the main process.
        state.encryptedConfigs[node.id] = encryptConfig(JSON.stringify({ config: source, ...credentials }))
        added += 1
      } catch (error) {
        failures.push({ file: path.basename(filePath), path: filePath, message: error.message })
      }
    }
    saveState()
    return { state: publicState(), added, failures }
  })

  ipcMain.handle('tunnel:import', async () => {
    const result = await dialog.showOpenDialog({
      title: 'Import WireGuard configurations',
      buttonLabel: 'Import routes',
      properties: ['openFile', 'multiSelections'],
      filters: [{ name: 'WireGuard configuration', extensions: ['conf'] }],
    })
    if (result.canceled) return { canceled: true }

    const errors = []
    for (const filePath of result.filePaths) {
      try {
        const source = fs.readFileSync(filePath, 'utf8')
        const tunnel = parseWireGuardConfig(source, filePath, crypto.randomUUID())
        state.tunnels.push(tunnel)
        state.encryptedConfigs[tunnel.id] = encryptConfig(source)
      } catch (error) {
        errors.push(`${path.basename(filePath)}: ${error.message}`)
      }
    }
    saveState()
    return { canceled: false, state: publicState(), errors }
  })

  ipcMain.handle('tunnel:set-enabled', (_event, id, enabled) => {
    const tunnel = state.tunnels.find((item) => item.id === id)
    if (!tunnel) return publicState()
    tunnel.enabled = Boolean(enabled)
    // Direct mode carries traffic through one node, so selecting a node here
    // means choosing it rather than adding it to a pool.
    if (state.connectionMode === 'direct' && tunnel.enabled) {
      for (const other of state.tunnels) if (other.id !== id) other.enabled = false
    }
    saveState()
    return publicState()
  })

  // Switching modes changes what a selected node means, so the selection is
  // carried across rather than left in a shape the new mode cannot start with.
  ipcMain.handle('connection:set-mode', (_event, mode) => {
    if (mode !== 'relay' && mode !== 'direct') throw new Error('Unknown connection mode')
    state.connectionMode = mode
    if (mode === 'direct') {
      const chosen = directSelectionAfterSwitch(state.tunnels)
      for (const tunnel of state.tunnels) tunnel.enabled = tunnel.id === chosen
    }
    saveState()
    return publicState()
  })

  ipcMain.handle('tunnel:remove', (_event, id) => {
    state.tunnels = state.tunnels.filter((item) => item.id !== id)
    delete state.encryptedConfigs[id]
    saveState()
    return publicState()
  })

  ipcMain.handle('rule:browse', async (_event, kind) => {
    if (kind !== 'application' && kind !== 'folder') return { canceled: true }
    const result = await dialog.showOpenDialog({
      title: kind === 'application' ? 'Choose a game executable' : 'Choose a game folder',
      buttonLabel: 'Use this target',
      properties: kind === 'application' ? ['openFile'] : ['openDirectory'],
      filters: kind === 'application' ? [{ name: 'Windows applications', extensions: ['exe'] }] : undefined,
    })
    if (result.canceled) return { canceled: true }
    const value = result.filePaths[0]
    return { canceled: false, value, label: path.basename(value) }
  })

  ipcMain.handle('rule:add', (_event, input) => {
    const value = String(input.value ?? '').trim()
    if (!value) throw new Error('A target is required')
    state.rules.push({
      id: crypto.randomUUID(),
      kind: input.kind,
      value,
      label: String(input.label || path.basename(value) || value),
      enabled: true,
      groupId: state.ruleGroups.some((group) => group.id === input.groupId) ? input.groupId : null,
    })
    saveState()
    return publicState()
  })

  ipcMain.handle('rule:set-enabled', (_event, id, enabled) => {
    const rule = state.rules.find((item) => item.id === id)
    if (rule) rule.enabled = Boolean(enabled)
    saveState()
    return publicState()
  })

  ipcMain.handle('rule:set-group', (_event, id, groupId) => {
    const rule = state.rules.find((item) => item.id === id)
    if (rule) rule.groupId = state.ruleGroups.some((group) => group.id === groupId) ? groupId : null
    saveState()
    return publicState()
  })

  ipcMain.handle('rule:remove', (_event, id) => {
    state.rules = state.rules.filter((item) => item.id !== id)
    saveState()
    return publicState()
  })

  ipcMain.handle('rule-group:add', (_event, rawName) => {
    const name = String(rawName ?? '').trim()
    if (!name) throw new Error('A group name is required')
    if (state.ruleGroups.some((group) => group.name.toLocaleLowerCase() === name.toLocaleLowerCase())) {
      throw new Error('A group with that name already exists')
    }
    state.ruleGroups.push({ id: crypto.randomUUID(), name, enabled: true })
    saveState()
    return publicState()
  })

  ipcMain.handle('rule-group:rename', (_event, id, rawName) => {
    const name = String(rawName ?? '').trim()
    if (!name) throw new Error('A group name is required')
    if (
      state.ruleGroups.some((group) => group.id !== id && group.name.toLocaleLowerCase() === name.toLocaleLowerCase())
    ) {
      throw new Error('A group with that name already exists')
    }
    const group = state.ruleGroups.find((item) => item.id === id)
    if (group) group.name = name
    saveState()
    return publicState()
  })

  ipcMain.handle('rule-group:set-enabled', (_event, id, enabled) => {
    const group = state.ruleGroups.find((item) => item.id === id)
    if (group) group.enabled = Boolean(enabled)
    saveState()
    return publicState()
  })

  ipcMain.handle('rule-group:remove', (_event, id) => {
    state.ruleGroups = state.ruleGroups.filter((group) => group.id !== id)
    for (const rule of state.rules) if (rule.groupId === id) rule.groupId = null
    saveState()
    return publicState()
  })

  ipcMain.handle('traffic:set-mode', (_event, mode) => {
    if (mode === 'all' || mode === 'split') state.trafficMode = mode
    saveState()
    return publicState()
  })

  ipcMain.handle('relay:set', (_event, id) => {
    if (state.relays.some((relay) => relay.id === id)) state.activeRelayId = state.activeRelayId === id ? null : id
    saveState()
    return publicState()
  })

  ipcMain.handle('relay:add', (_event, input) => {
    const city = String(input?.city ?? '').trim() || 'Custom relay'
    const country = String(input?.country ?? '').trim() || 'Custom'
    const relay = {
      id: crypto.randomUUID(),
      city,
      country,
      code: country.slice(0, 2).toUpperCase(),
      address: '',
      port: 51821,
      status: 'setup-required',
      hasEnrollmentToken: false,
    }
    state.relays.push(relay)
    state.activeRelayId = relay.id
    saveState()
    return { state: publicState(), relayId: relay.id }
  })

  ipcMain.handle('relay:remove-local', (_event, id) => {
    state.relays = state.relays.filter((relay) => relay.id !== id)
    delete state.encryptedRelayTokens[id]
    if (state.activeRelayId === id) state.activeRelayId = null
    saveState()
    return publicState()
  })

  ipcMain.handle('relay:configure', (_event, id, input) => {
    const relay = state.relays.find((item) => item.id === id)
    if (!relay) throw new Error('Relay not found')
    const address = String(input.address ?? '').trim()
    const port = Number(input.port)
    if (!address || /\s|:\/\//.test(address)) throw new Error('Enter a hostname or IP address without http://')
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Port must be between 1 and 65535')
    const enrollmentToken = String(input.enrollmentToken ?? '').trim()
    if (enrollmentToken && (!enrollmentToken.startsWith('gpe1_') || enrollmentToken.length < 80)) {
      throw new Error('The enrollment token is not a valid GamePath token')
    }
    if (enrollmentToken) state.encryptedRelayTokens[id] = encryptConfig(enrollmentToken)
    if (!state.encryptedRelayTokens[id]) throw new Error('Import or paste the relay enrollment token')
    relay.address = address
    relay.port = port
    relay.status = 'ready'
    relay.hasEnrollmentToken = true
    saveState()
    return publicState()
  })

  ipcMain.handle('relay:import-enrollment', async (_event, id) => {
    const relay = state.relays.find((item) => item.id === id)
    if (!relay) throw new Error('Relay not found')
    const result = await dialog.showOpenDialog({
      title: 'Import GamePath enrollment token',
      buttonLabel: 'Import token',
      properties: ['openFile'],
      filters: [{ name: 'GamePath enrollment', extensions: ['enroll'] }],
    })
    if (result.canceled) return { canceled: true }
    const token = fs.readFileSync(result.filePaths[0], 'utf8').trim()
    if (!token.startsWith('gpe1_') || token.length < 80)
      throw new Error('The selected file is not a valid GamePath enrollment token')
    state.encryptedRelayTokens[id] = encryptConfig(token)
    relay.hasEnrollmentToken = true
    relay.status = relay.address ? 'ready' : 'setup-required'
    saveState()
    return { canceled: false, state: publicState() }
  })

  ipcMain.handle('relay:test', async (_event, id) => {
    const relay = state.relays.find((item) => item.id === id)
    const encryptedToken = state.encryptedRelayTokens[id]
    if (!relay?.address || !encryptedToken) throw new Error('Configure the relay address and enrollment token first')
    const result = await engineBridge.request('probe-relay', {
      relayHost: relay.address,
      relayPort: relay.port,
      enrollmentToken: safeStorage.decryptString(Buffer.from(encryptedToken, 'base64')),
    })
    relay.latency = Math.max(1, Math.round(result.latencyMs))
    relay.status = 'ready'
    saveState()
    return { state: publicState(), result }
  })

  ipcMain.handle('relay:vps-provision', async (_event, id, input) => {
    const relay = state.relays.find((item) => item.id === id)
    if (!relay) throw new Error('Relay not found')
    const host = String(input.host ?? '').trim()
    const username = String(input.username ?? '').trim()
    const password = String(input.password ?? '')
    const sshPort = Number(input.sshPort ?? 22)
    const relayPort = Number(input.relayPort ?? 51821)
    if (!host || /\s|:\/\//.test(host)) throw new Error('Enter a valid VPS hostname or IP address')
    if (!username || !password) throw new Error('Enter the SSH username and password')
    if (![sshPort, relayPort].every((port) => Number.isInteger(port) && port >= 1 && port <= 65535))
      throw new Error('Ports must be between 1 and 65535')
    const projectRoot = app.isPackaged ? process.resourcesPath : path.join(__dirname, '..')
    const progress = (update) => _event.sender.send('relay:vps-progress', { relayId: id, ...update })
    const result = await provisionRelay(
      projectRoot,
      { host, username, password, sshPort, relayPort, expectedFingerprint: relay.sshFingerprint },
      progress,
    )
    state.encryptedRelayTokens[id] = encryptConfig(result.token)
    Object.assign(relay, {
      address: host,
      port: relayPort,
      status: 'ready',
      hasEnrollmentToken: true,
      sshFingerprint: result.fingerprint,
    })
    state.activeRelayId = id
    saveState()
    return publicState()
  })

  ipcMain.handle('relay:vps-remove', async (_event, id, input) => {
    const relay = state.relays.find((item) => item.id === id)
    if (!relay) throw new Error('Relay not found')
    const host = String(input.host ?? relay.address ?? '').trim()
    const username = String(input.username ?? '').trim()
    const password = String(input.password ?? '')
    const sshPort = Number(input.sshPort ?? 22)
    if (!host || !username || !password) throw new Error('Enter the VPS hostname, SSH username, and password')
    const projectRoot = app.isPackaged ? process.resourcesPath : path.join(__dirname, '..')
    const progress = (update) => _event.sender.send('relay:vps-progress', { relayId: id, ...update })
    await removeRelay(
      projectRoot,
      { host, username, password, sshPort, expectedFingerprint: relay.sshFingerprint },
      progress,
    )
    delete state.encryptedRelayTokens[id]
    Object.assign(relay, { status: 'setup-required', hasEnrollmentToken: false, latency: undefined })
    if (state.activeRelayId === id) state.activeRelayId = null
    saveState()
    return publicState()
  })

  ipcMain.handle('service:refresh', async () => {
    await serviceBridge.inspect()
    return publicState()
  })

  ipcMain.handle('service:install', async () => {
    const projectRoot = app.isPackaged ? process.resourcesPath : path.join(__dirname, '..')
    const installer = path.join(projectRoot, 'deploy', 'install-windows-service.ps1')
    await new Promise((resolve, reject) => {
      const child = spawn(
        'powershell.exe',
        ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', installer, '-ProjectRoot', projectRoot, '-SkipBuild'],
        {
          windowsHide: true,
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      )
      let output = ''
      child.stdout.on('data', (chunk) => {
        output += chunk.toString()
      })
      child.stderr.on('data', (chunk) => {
        output += chunk.toString()
      })
      child.once('error', reject)
      child.once('exit', (code) => {
        if (code === 0) resolve()
        else reject(new Error(output.trim() || `Service installer exited with code ${code}`))
      })
    })
    await serviceBridge.inspect()
    if (serviceBridge.status.status !== 'ready') throw new Error(serviceBridge.status.message)
    return publicState()
  })

  ipcMain.handle('engine:start', async () => {
    const mode = state.connectionMode === 'direct' ? 'direct' : 'relay'
    const enabledTunnels = state.tunnels.filter((tunnel) => tunnel.enabled)
    const enabledGroupIds = new Set(state.ruleGroups.filter((group) => group.enabled).map((group) => group.id))
    const enabledRules = state.rules.filter(
      (rule) => rule.enabled && (!rule.groupId || enabledGroupIds.has(rule.groupId)),
    )
    const relay = state.relays.find((item) => item.id === state.activeRelayId)
    const encryptedRelayToken = relay && state.encryptedRelayTokens[relay.id]
    const direct = mode === 'direct'
    const selection = direct ? directNodeSelection(enabledTunnels) : { node: null, error: null }
    const blocker = direct
      ? selection.error
      : enabledTunnels.length < 1
        ? 'Enable at least one WireGuard or SOCKS5 node.'
        : !relay || relay.status !== 'ready' || !encryptedRelayToken
          ? 'The Istanbul relay needs its address and enrollment token.'
          : null
    if (blocker) {
      state.session = { status: 'error', message: blocker }
    } else if (state.trafficMode === 'split' && !enabledRules.length) {
      state.session = { status: 'error', message: 'Add at least one split-tunnel target.' }
    } else if (engineBridge?.status.status !== 'ready') {
      state.session = { status: 'error', message: 'The native routing engine is unavailable.' }
    } else if (serviceBridge?.status.status !== 'ready') {
      state.session = { status: 'error', message: 'Install and start the GamePath Network Service in Settings.' }
    } else {
      try {
        const rules = enabledRules.map((rule) => ({ kind: rule.kind, value: rule.value }))
        const nodes = sessionNodes(enabledTunnels)
        // A relay session addresses and authenticates itself to the relay; a
        // direct session has neither, so it sends neither.
        const relayCredentials = direct
          ? {}
          : {
              relayHost: relay.address,
              relayPort: relay.port,
              enrollmentToken: safeStorage.decryptString(Buffer.from(encryptedRelayToken, 'base64')),
            }
        const plan = await engineBridge.request('prepare-session', {
          mode,
          routeIds: enabledTunnels.map((tunnel) => tunnel.id),
          trafficMode: state.trafficMode,
          rules,
          ...relayCredentials,
        })
        let relayIp
        if (!direct) {
          const relayAddresses = await require('node:dns').promises.lookup(relay.address, { all: true })
          relayIp = relayAddresses.find((entry) => entry.family === 4)?.address ?? relayAddresses[0]?.address
          if (!relayIp) throw new Error('The relay hostname did not resolve')
        }
        await serviceBridge.request('validate-runtime', {
          mode,
          relayIp,
          trafficMode: state.trafficMode,
          nodes,
        })
        const serviceSession = await serviceBridge.request(
          'start-session',
          { mode, ...relayCredentials, nodes, trafficMode: state.trafficMode, rules },
          30000,
        )
        const paths = serviceSession.paths
        const dataPlane = serviceSession.dataPlane
        state.session = {
          status: 'connected',
          mode,
          message: direct
            ? directSessionMessage(plan, selection.node, dataPlane)
            : relaySessionMessage(plan, paths, dataPlane),
        }
        state.session.capture = serviceSession.capture
        updateSessionMetrics(paths, dataPlane)
        startSessionKeepAlive()
        logger.info(
          `session started: mode=${mode} traffic=${state.trafficMode} ` +
            `routes=${paths.paths.length} skipped=${(paths.skippedRoutes ?? []).length} ` +
            `mtu=${serviceSession.capture?.effectiveMtu ?? 'unknown'}`,
        )
        for (const route of paths.skippedRoutes ?? []) {
          logger.warn(`route ${route.route} (${route.label}) did not join: ${route.reason}`)
        }
      } catch (error) {
        try {
          await serviceBridge.request('stop-session')
        } catch {}
        state.session = { status: 'error', message: error.message }
        stopSessionKeepAlive()
        logger.error(`session failed to start: ${error.message}`)
      }
    }
    saveState()
    return publicState()
  })

  ipcMain.handle('engine:stop', async () => {
    stopSessionKeepAlive()
    logger.info('session stop requested')
    try {
      if (engineBridge?.status.status === 'ready') await engineBridge.request('stop-wireguard-session')
      if (serviceBridge?.status.status === 'ready') await serviceBridge.request('stop-session')
      state.session = { status: 'idle' }
    } catch (error) {
      state.session = { status: 'error', message: error.message }
    }
    saveState()
    return publicState()
  })

  ipcMain.handle('engine:session-status', async () => {
    // The keep-alive below already refreshes this every SESSION_POLL_MS, so the
    // renderer reads what it last saw rather than issuing a second request.
    // Only poll inline if the keep-alive somehow is not running.
    if (!sessionKeepAlive) await pollSessionStatus()
    return publicState()
  })
}

/**
 * Asks the service for session state and mirrors it into `state.session`.
 *
 * This also renews the service's session lease, which is the reason it runs on
 * a main-process timer rather than only when the renderer asks. See
 * `startSessionKeepAlive`.
 */
async function pollSessionStatus() {
  if (state.session.status !== 'connected' || serviceBridge?.status.status !== 'ready') return
  if (sessionPollInFlight) return
  sessionPollInFlight = true
  try {
    const runtime = await serviceBridge.request('session-status')
    updateSessionMetrics(runtime)
    // Selected traffic keeps going into the tunnel while the workers are
    // alive, so it is not quietly falling back to the normal connection:
    // it is not getting through, and stopping the session is what fixes it.
    if (runtime.state !== 'connected' && lastRuntimeState === 'connected') {
      logger.warn(`session degraded: relay state is ${runtime.state}`)
    } else if (runtime.state === 'connected' && lastRuntimeState && lastRuntimeState !== 'connected') {
      logger.info('session recovered')
    }
    lastRuntimeState = runtime.state
    sessionPollFailures = 0
    if (runtime.state !== 'connected') {
      state.session.message =
        runtime.mode === 'direct'
          ? 'The node has stopped answering. Selected traffic is not getting through — stop the session to use your normal connection.'
          : 'Relay paths are unavailable. Selected traffic is not getting through — stop the session to use your normal connection.'
    }
  } catch (error) {
    sessionPollFailures += 1
    if (sessionPollFailures < SESSION_POLL_MAX_FAILURES) {
      // The paths are almost certainly still carrying traffic; only the status
      // request failed. Say so and let the next poll decide.
      logger.warn(`session status failed (${sessionPollFailures}/${SESSION_POLL_MAX_FAILURES}): ${error.message}`)
      return
    }
    try {
      await serviceBridge.request('stop-session')
    } catch {}
    state.session = { status: 'error', message: error.message }
    stopSessionKeepAlive()
    logger.error(`session lost after ${sessionPollFailures} failed status requests: ${error.message}`)
  } finally {
    sessionPollInFlight = false
  }
}

/**
 * Keeps the service's session lease alive for as long as a session is up.
 *
 * The lease exists so the service tears down routes if the client dies. Only
 * `session-status` renews it, and that used to be driven solely by a renderer
 * `setInterval`. Chromium throttles timers in a window that is hidden, occluded
 * or minimized — which is exactly what a fullscreen game does to this one — so
 * the poll would stall, the lease would expire, and the service would stop the
 * capture a few minutes into play. This timer lives in the main process, which
 * is plain Node and is never throttled.
 */
function startSessionKeepAlive() {
  stopSessionKeepAlive()
  lastRuntimeState = null
  sessionPollFailures = 0
  sessionKeepAlive = setInterval(pollSessionStatus, SESSION_POLL_MS)
  // Nothing should be kept alive by this timer alone at quit time.
  sessionKeepAlive.unref?.()
}

function stopSessionKeepAlive() {
  if (sessionKeepAlive) clearInterval(sessionKeepAlive)
  sessionKeepAlive = null
}

function createWindow() {
  const icon = app.isPackaged
    ? path.join(process.resourcesPath, 'icon.png')
    : path.join(__dirname, '..', 'build', 'icon.png')
  const window = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 1050,
    minHeight: 700,
    backgroundColor: '#080b12',
    icon,
    title: 'GamePath',
    titleBarStyle: 'hidden',
    titleBarOverlay: { color: '#080b12', symbolColor: '#8b95a9', height: 42 },
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      // A fullscreen game leaves this window occluded, and Chromium then
      // throttles its timers to a crawl. The session lease no longer depends on
      // them, but the live metrics the window shows still do.
      backgroundThrottling: false,
    },
  })

  window.webContents.setWindowOpenHandler(({ url }) => {
    if (url === 'https://github.com/primemb/gamepath') {
      void shell.openExternal(url).catch((error) => logger.warn(`Could not open project link: ${error.message}`))
    }
    return { action: 'deny' }
  })

  if (app.isPackaged) {
    window.loadFile(path.join(__dirname, '..', 'dist', 'index.html'))
  } else {
    window.loadURL('http://127.0.0.1:5173')
  }
}

app.whenReady().then(async () => {
  logger.init()
  logger.info(`gamepath-client ${app.getVersion()} starting on ${process.platform}`)
  app.on('will-quit', () => {
    logger.info('client shutting down')
    logger.flush()
  })
  loadState()
  const projectRoot = app.isPackaged ? process.resourcesPath : path.join(__dirname, '..')
  engineBridge = new EngineBridge(projectRoot, app.isPackaged)
  serviceBridge = new ServiceBridge()
  await engineBridge.start()
  await serviceBridge.inspect()
  registerIpc()
  createWindow()
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('before-quit', () => engineBridge?.stop())

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})
