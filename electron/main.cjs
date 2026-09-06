const { app, BrowserWindow, dialog, ipcMain, safeStorage } = require('electron')
const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')
const { parseWireGuardConfig } = require('./wireguard.cjs')
const { EngineBridge } = require('./engine.cjs')

const defaultState = () => ({
  tunnels: [],
  encryptedConfigs: {},
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
    },
  ],
  activeRelayId: 'tr-istanbul-01',
  session: { status: 'idle' },
})

let state
let engineBridge

function statePath() {
  return path.join(app.getPath('userData'), 'gamepath-state.json')
}

function publicState() {
  const { encryptedConfigs, ...safeState } = state
  return structuredClone({ ...safeState, engine: engineBridge?.status ?? { status: 'offline', version: '', message: 'Native engine is starting', capabilities: null } })
}

function loadState() {
  try {
    const loaded = JSON.parse(fs.readFileSync(statePath(), 'utf8'))
    state = { ...defaultState(), ...loaded, session: { status: 'idle' } }
    state.relays = state.relays.map((relay) => ({ port: 51821, ...relay }))
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
    if (state.relays.some((relay) => relay.id === id)) state.activeRelayId = id
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
    relay.address = address
    relay.port = port
    relay.status = 'ready'
    saveState()
    return publicState()
  })

  ipcMain.handle('engine:start', async () => {
    const enabledTunnels = state.tunnels.filter((tunnel) => tunnel.enabled)
    const enabledRules = state.rules.filter((rule) => rule.enabled)
    const relay = state.relays.find((item) => item.id === state.activeRelayId)
    if (enabledTunnels.length < 2) {
      state.session = { status: 'error', message: 'Enable at least two WireGuard routes.' }
    } else if (state.trafficMode === 'split' && !enabledRules.length) {
      state.session = { status: 'error', message: 'Add at least one split-tunnel target.' }
    } else if (!relay || relay.status !== 'ready') {
      state.session = { status: 'error', message: 'The Istanbul relay needs its server component and address.' }
    } else if (engineBridge?.status.status !== 'ready') {
      state.session = { status: 'error', message: 'The native routing engine is unavailable.' }
    } else {
      try {
        const plan = await engineBridge.request('prepare-session', {
          routeIds: enabledTunnels.map((tunnel) => tunnel.id),
          trafficMode: state.trafficMode,
          ruleCount: enabledRules.length,
          relayHost: relay.address,
          relayPort: relay.port,
        })
        state.session = { status: 'prepared', message: `Session plan ${plan.planId} is ready for the packet adapter.` }
      } catch (error) {
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
  engineBridge = new EngineBridge(path.join(__dirname, '..'))
  await engineBridge.start()
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
