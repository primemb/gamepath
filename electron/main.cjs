const { app, BrowserWindow, dialog, ipcMain, safeStorage } = require('electron')
const { spawn } = require('node:child_process')
const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')
const { parseWireGuardConfig } = require('./wireguard.cjs')
const { EngineBridge } = require('./engine.cjs')
const { ServiceBridge } = require('./service.cjs')
const { provisionRelay, removeRelay } = require('./vps.cjs')

const defaultState = () => ({
  tunnels: [],
  encryptedConfigs: {},
  encryptedRelayTokens: {},
  rules: [],
  trafficMode: 'split',
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
    engine: engineBridge?.status ?? { status: 'offline', version: '', message: 'Native engine is starting', capabilities: null },
    service: serviceBridge?.status ?? { status: 'offline', version: '', message: 'Network service is starting', elevated: false },
  })
}

function loadState() {
  try {
    const loaded = JSON.parse(fs.readFileSync(statePath(), 'utf8'))
    state = { ...defaultState(), ...loaded, session: { status: 'idle' } }
    state.encryptedRelayTokens ??= {}
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

function encryptConfig(source) {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('Windows secure storage is unavailable')
  }
  return safeStorage.encryptString(source).toString('base64')
}

function updateSessionMetrics(runtime, dataPlane) {
  const paths = runtime.paths ?? []
  const wireGuard = paths.find((path) => path.pathKind === 'wireguard')
  const sent = paths.reduce((total, path) => total + path.packetsSent, 0)
  const received = paths.reduce((total, path) => total + path.packetsReceived, 0)
  const probesReceived = paths.reduce((total, path) => total + (path.probesReceived ?? 0), 0)
  const probesLost = paths.reduce((total, path) => total + (path.probesLost ?? 0), 0)
  const completedProbes = probesReceived + probesLost
  const userToNode = wireGuard?.nodeLatencyMs ?? null
  const nodeToRelay = userToNode != null && wireGuard?.latencyMs != null ? Math.max(0, wireGuard.latencyMs - userToNode) : null
  state.session.pathMetrics = paths
  if (runtime.capture) state.session.capture = runtime.capture
  state.session.routeLatencies = paths.filter((path) => path.latencyMs != null).map((path) => Math.max(1, Math.round(path.latencyMs)))
  state.session.metrics = {
    userToNodeMs: userToNode,
    nodeToRelayMs: nodeToRelay,
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

function registerIpc() {
  ipcMain.handle('app:bootstrap', () => publicState())

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
    if (tunnel) tunnel.enabled = Boolean(enabled)
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

  ipcMain.handle('rule:remove', (_event, id) => {
    state.rules = state.rules.filter((item) => item.id !== id)
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
    const relay = { id: crypto.randomUUID(), city, country, code: country.slice(0, 2).toUpperCase(), address: '', port: 51821, status: 'setup-required', hasEnrollmentToken: false }
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
    if (!token.startsWith('gpe1_') || token.length < 80) throw new Error('The selected file is not a valid GamePath enrollment token')
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
    if (![sshPort, relayPort].every((port) => Number.isInteger(port) && port >= 1 && port <= 65535)) throw new Error('Ports must be between 1 and 65535')
    const projectRoot = app.isPackaged ? process.resourcesPath : path.join(__dirname, '..')
    const progress = (update) => _event.sender.send('relay:vps-progress', { relayId: id, ...update })
    const result = await provisionRelay(projectRoot, { host, username, password, sshPort, relayPort, expectedFingerprint: relay.sshFingerprint }, progress)
    state.encryptedRelayTokens[id] = encryptConfig(result.token)
    Object.assign(relay, { address: host, port: relayPort, status: 'ready', hasEnrollmentToken: true, sshFingerprint: result.fingerprint })
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
    await removeRelay(projectRoot, { host, username, password, sshPort, expectedFingerprint: relay.sshFingerprint }, progress)
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
      const child = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', installer, '-ProjectRoot', projectRoot, '-SkipBuild'], {
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      })
      let output = ''
      child.stdout.on('data', (chunk) => { output += chunk.toString() })
      child.stderr.on('data', (chunk) => { output += chunk.toString() })
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
    const enabledTunnels = state.tunnels.filter((tunnel) => tunnel.enabled)
    const enabledRules = state.rules.filter((rule) => rule.enabled)
    const relay = state.relays.find((item) => item.id === state.activeRelayId)
    const encryptedRelayToken = relay && state.encryptedRelayTokens[relay.id]
    if (enabledTunnels.length < 1) {
      state.session = { status: 'error', message: 'Enable at least one WireGuard route.' }
    } else if (state.trafficMode === 'split' && !enabledRules.length) {
      state.session = { status: 'error', message: 'Add at least one split-tunnel target.' }
    } else if (!relay || relay.status !== 'ready' || !encryptedRelayToken) {
      state.session = { status: 'error', message: 'The Istanbul relay needs its address and enrollment token.' }
    } else if (engineBridge?.status.status !== 'ready') {
      state.session = { status: 'error', message: 'The native routing engine is unavailable.' }
    } else if (serviceBridge?.status.status !== 'ready') {
      state.session = { status: 'error', message: 'Install and start the GamePath Network Service in Settings.' }
    } else {
      try {
        const enrollmentToken = safeStorage.decryptString(Buffer.from(encryptedRelayToken, 'base64'))
        const wireguardConfigs = enabledTunnels.map((tunnel) => safeStorage.decryptString(Buffer.from(state.encryptedConfigs[tunnel.id], 'base64')))
        const plan = await engineBridge.request('prepare-session', {
          routeIds: enabledTunnels.map((tunnel) => tunnel.id),
          trafficMode: state.trafficMode,
          rules: enabledRules.map((rule) => ({ kind: rule.kind, value: rule.value })),
          relayHost: relay.address,
          relayPort: relay.port,
          enrollmentToken,
        })
        const relayAddresses = await require('node:dns').promises.lookup(relay.address, { all: true })
        const relayIp = relayAddresses.find((entry) => entry.family === 4)?.address ?? relayAddresses[0]?.address
        if (!relayIp) throw new Error('The relay hostname did not resolve')
        const runtime = await serviceBridge.request('validate-runtime', {
          relayIp,
          trafficMode: state.trafficMode,
          wireguardConfigs,
        })
        const serviceSession = await serviceBridge.request('start-session', {
          relayHost: relay.address,
          relayPort: relay.port,
          enrollmentToken,
          wireguardConfigs,
          trafficMode: state.trafficMode,
          rules: enabledRules.map((rule) => ({ kind: rule.kind, value: rule.value })),
        }, 30000)
        const paths = serviceSession.paths
        const dataPlane = serviceSession.dataPlane
        const standbyNote = paths.skippedRoutes.length ? ` ${paths.skippedRoutes.length} overlapping config${paths.skippedRoutes.length === 1 ? ' is' : 's are'} held as standby.` : ''
        state.session = { status: 'connected', message: `Session ${plan.planId} is keeping ${paths.paths.length} encrypted paths connected; benchmark packet loop verified in ${Math.round(dataPlane.latencyMs)} ms.${standbyNote}` }
        state.session.capture = serviceSession.capture
        updateSessionMetrics(paths, dataPlane)
      } catch (error) {
        try { await serviceBridge.request('stop-session') } catch {}
        state.session = { status: 'error', message: error.message }
      }
    }
    saveState()
    return publicState()
  })

  ipcMain.handle('engine:stop', async () => {
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
    if (state.session.status === 'connected' && serviceBridge?.status.status === 'ready') {
      try {
        const runtime = await serviceBridge.request('session-status')
        updateSessionMetrics(runtime)
        if (runtime.state !== 'connected') {
          state.session.message = 'Relay paths are temporarily unavailable; selected traffic is using the normal Internet connection.'
        }
      } catch (error) {
        try { await serviceBridge.request('stop-session') } catch {}
        state.session = { status: 'error', message: error.message }
      }
    }
    return publicState()
  })
}

function createWindow() {
  const window = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 1050,
    minHeight: 700,
    backgroundColor: '#080b12',
    title: 'GamePath',
    titleBarStyle: 'hidden',
    titleBarOverlay: { color: '#080b12', symbolColor: '#8b95a9', height: 42 },
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  })

  if (app.isPackaged) {
    window.loadFile(path.join(__dirname, '..', 'dist', 'index.html'))
  } else {
    window.loadURL('http://127.0.0.1:5173')
  }
}

app.whenReady().then(async () => {
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
