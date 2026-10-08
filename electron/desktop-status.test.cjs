const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')
const vm = require('node:vm')
const { MODES, INDICATORS, desktopStatus, createDesktopIcons } = require('./desktop-status.cjs')

const session = (status) => ({ status })

test('distinguishes off, VPN only, Game only and both running', () => {
  assert.equal(desktopStatus().key, 'off-normal')
  assert.equal(desktopStatus(session('idle'), session('connected')).key, 'vpn-normal')
  assert.equal(desktopStatus(session('connected'), session('idle')).key, 'game-normal')
  const both = desktopStatus(session('connected'), session('connected'))
  assert.equal(both.key, 'both-normal')
  assert.equal(both.tooltip, 'GamePath | Game: on | VPN: on')
})

test('connecting and retrying are never displayed as a connected VPN', () => {
  for (const status of ['connecting', 'reconnecting']) {
    const visual = desktopStatus(session('connected'), session(status))
    assert.equal(visual.key, 'game-busy')
    assert.equal(visual.vpnLabel, `VPN: ${status}`)
  }
  assert.equal(desktopStatus(session('starting')).key, 'off-busy')
  assert.equal(desktopStatus(session('prepared')).key, 'off-normal')
})

test('paused VPN is excluded from both-on status and is explained', () => {
  const visual = desktopStatus(session('connected'), session('paused'))
  assert.equal(visual.key, 'game-paused')
  assert.equal(visual.vpnLabel, 'VPN: paused for Game')
})

test('lost game paths and degraded VPN show warnings, then clear on recovery', () => {
  const game = session('connected')
  const vpn = session('connected')
  const failed = desktopStatus(game, vpn, 'degraded')
  assert.equal(failed.key, 'both-warning')
  assert.equal(failed.gameLabel, 'Game: paths unavailable')
  assert.equal(desktopStatus(game, session('degraded'), 'connected').key, 'both-warning')
  assert.equal(desktopStatus(game, vpn, 'connected').key, 'both-normal')
  assert.equal(desktopStatus(game, vpn, null).key, 'both-normal')
})

test('errors remain visible alongside the other running connection', () => {
  assert.equal(desktopStatus(session('error'), session('connected')).key, 'vpn-error')
  assert.equal(desktopStatus(session('connected'), session('error')).key, 'game-error')
  assert.equal(desktopStatus(session('error'), session('reconnecting')).key, 'off-error')
})

function surface() {
  const calls = []
  return {
    calls,
    isDestroyed: () => false,
    setImage: (icon) => calls.push(['image', icon]),
    setToolTip: (text) => calls.push(['tooltip', text]),
    setIcon: (icon) => calls.push(['icon', icon]),
    setOverlayIcon: (icon, text) => calls.push(['overlay', icon, text]),
  }
}

test('updates both Windows surfaces without rebuilding icons on each lease poll', () => {
  const loaded = []
  const icons = createDesktopIcons({
    platform: 'win32',
    nativeImage: { createFromPath: (file) => (loaded.push(file), file) },
  })
  const tray = surface()
  const window = surface()
  const off = desktopStatus()
  icons.update(off, tray, window)
  assert.equal(tray.calls.length, 2)
  assert.equal(window.calls.length, 1)
  icons.update(off, tray, window)
  assert.equal(tray.calls.length, 2)
  assert.equal(window.calls.length, 1)
  const both = desktopStatus(session('connected'), session('connected'))
  icons.update(both, tray, window)
  assert.match(tray.calls[2][1], /both-normal\.ico$/)
  assert.equal(window.calls[1][2], both.tooltip)
  assert.ok(window.calls.every(([method]) => method === 'overlay'))
  assert.equal(loaded.length, 2)
  icons.update(off, tray, window)
  assert.equal(loaded.length, 2)
})

test('restored and recreated windows receive the current taskbar status', () => {
  const icons = createDesktopIcons({ platform: 'win32', nativeImage: { createFromPath: (file) => file } })
  const visual = desktopStatus(session('connected'))
  const window = surface()
  icons.update(visual, null, window)
  icons.update(visual, null, window, true)
  assert.equal(window.calls.length, 2)
  const replacement = surface()
  icons.update(visual, null, replacement)
  assert.equal(replacement.calls[0][2], visual.tooltip)
  const dead = { isDestroyed: () => true }
  assert.doesNotThrow(() => icons.update(visual, dead, dead))
})

test('tooltip updates when a connecting VPN begins retrying with the same icon', () => {
  const icons = createDesktopIcons({ platform: 'win32', nativeImage: { createFromPath: (file) => file } })
  const tray = surface()
  icons.update(desktopStatus({}, session('connecting')), tray, null)
  icons.update(desktopStatus({}, session('reconnecting')), tray, null)
  assert.equal(tray.calls.filter(([method]) => method === 'image').length, 1)
  assert.equal(tray.calls[2][1], 'GamePath | Game: off | VPN: reconnecting')
})

test('window creation always uses the original GamePath icon', () => {
  const main = fs.readFileSync(path.join(__dirname, 'main.cjs'), 'utf8')
  const options = []
  const app = { isPackaged: false }
  const resourcesPath = path.join(__dirname, 'packaged-resources')
  const context = vm.createContext({
    app,
    path,
    __dirname,
    process: { resourcesPath },
    startInBackground: false,
    mainWindow: null,
    refreshDesktopStatus() {},
    BrowserWindow: class {
      constructor(config) {
        options.push(config)
        this.webContents = { setWindowOpenHandler() {} }
      }
      on() {}
      loadURL() {}
      loadFile() {}
    },
  })
  const iconStart = main.indexOf('function appIconPath()')
  const iconSource = main.slice(iconStart, main.indexOf('\n}\n', iconStart) + 3)
  const windowSource = main.slice(main.indexOf('function createWindow()'), main.indexOf('// One client per user.'))
  vm.runInContext(`${iconSource}\n${windowSource}`, context)
  context.createWindow()
  assert.equal(options[0].icon, path.join(__dirname, '..', 'build', 'icon.png'))
  app.isPackaged = true
  context.createWindow()
  assert.equal(options[1].icon, path.join(resourcesPath, 'icon.png'))
})

test('every status ships a multi-size Windows icon and DPI-scaled overlay PNGs', () => {
  const directory = path.join(__dirname, 'assets', 'status')
  for (const mode of MODES) {
    for (const indicator of INDICATORS) {
      const key = `${mode}-${indicator}`
      const ico = fs.readFileSync(path.join(directory, `${key}.ico`))
      assert.equal(ico.readUInt16LE(2), 1)
      assert.equal(ico.readUInt16LE(4), 8)
      for (const [index, size] of [16, 20, 24, 32, 40, 48, 64, 256].entries()) {
        const entry = 6 + index * 16
        assert.equal(ico[entry] || 256, size)
        const offset = ico.readUInt32LE(entry + 12)
        assert.equal(ico.subarray(offset + 1, offset + 4).toString(), 'PNG')
      }
      const png = fs.readFileSync(path.join(directory, `${key}.png`))
      assert.equal(png.readUInt32BE(16), 16)
      const highDpi = fs.readFileSync(path.join(directory, `${key}@2x.png`))
      assert.equal(highDpi.readUInt32BE(16), 32)
    }
  }
  const packageConfig = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'))
  assert.ok(packageConfig.build.files.includes('electron/**/*'))
})

test('tray menu enables Connect after the first node is added and follows connection status', () => {
  const menus = []
  const main = fs.readFileSync(path.join(__dirname, 'main.cjs'), 'utf8')
  const context = vm.createContext({
    state: { vpn: { node: null, wantConnected: false } },
    vpnFeature: { controller: { snapshot: () => session('idle') } },
    selectedVpnNode: (vpn) => vpn.node,
    tray: { isDestroyed: () => false, setContextMenu: (menu) => menus.push(menu) },
    Menu: { buildFromTemplate: (template) => template },
    showMainWindow() {},
  })
  vm.runInContext(main.slice(main.indexOf('let trayMenuKey'), main.indexOf('function createTray()')), context)
  context.refreshTrayMenu(desktopStatus())
  assert.equal(menus[0].find((item) => item.label === 'Connect VPN').enabled, false)
  context.state.vpn.node = { id: 'first-node' }
  context.refreshTrayMenu(desktopStatus())
  assert.equal(menus[1].find((item) => item.label === 'Connect VPN').enabled, true)
  context.refreshTrayMenu(desktopStatus())
  assert.equal(menus.length, 2)
  context.refreshTrayMenu(desktopStatus(session('connected')))
  assert.ok(menus[2].some((item) => item.label === 'Game: on'))
})
