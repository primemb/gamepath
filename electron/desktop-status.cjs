const path = require('node:path')

const MODES = ['off', 'game', 'vpn', 'both']
const INDICATORS = ['normal', 'busy', 'warning', 'paused', 'error']

function desktopStatus(game = {}, vpn = {}, gameRuntimeState = null) {
  const gameStatus = game.status ?? 'idle'
  const vpnStatus = vpn.status ?? 'idle'
  const gameOn = gameStatus === 'connected'
  const vpnOn = vpnStatus === 'connected' || vpnStatus === 'degraded'
  const mode = gameOn ? (vpnOn ? 'both' : 'game') : vpnOn ? 'vpn' : 'off'
  const gameDegraded = gameOn && gameRuntimeState != null && gameRuntimeState !== 'connected'
  const indicator =
    gameStatus === 'error' || vpnStatus === 'error'
      ? 'error'
      : gameDegraded || vpnStatus === 'degraded'
        ? 'warning'
        : gameStatus === 'starting' || vpnStatus === 'connecting' || vpnStatus === 'reconnecting'
          ? 'busy'
          : vpnStatus === 'paused'
            ? 'paused'
            : 'normal'
  const gameLabel = gameDegraded
    ? 'Game: paths unavailable'
    : ({
        idle: 'Game: off',
        starting: 'Game: connecting',
        prepared: 'Game: off (ready to connect)',
        connected: 'Game: on',
        error: 'Game: connection error',
      }[gameStatus] ?? 'Game: off')
  const vpnLabel =
    {
      idle: 'VPN: off',
      connecting: 'VPN: connecting',
      reconnecting: 'VPN: reconnecting',
      connected: 'VPN: on',
      degraded: 'VPN: node not answering',
      paused: 'VPN: paused for Game',
      error: 'VPN: connection error',
    }[vpnStatus] ?? 'VPN: off'
  return { key: `${mode}-${indicator}`, gameLabel, vpnLabel, tooltip: `GamePath | ${gameLabel} | ${vpnLabel}` }
}

function createDesktopIcons({
  nativeImage,
  platform = process.platform,
  assetRoot = path.join(__dirname, 'assets', 'status'),
}) {
  const overlays = new Map()
  let lastTray = null
  let lastTrayKey = null
  let lastTrayText = null
  let lastWindow = null
  let lastWindowKey = null

  function iconPath(key) {
    return path.join(assetRoot, `${key}.ico`)
  }

  function overlay(key) {
    if (!overlays.has(key)) overlays.set(key, nativeImage.createFromPath(path.join(assetRoot, `${key}.png`)))
    return overlays.get(key)
  }

  return {
    iconPath,
    update(status, tray, window, forceWindow = false) {
      if (tray && !tray.isDestroyed() && (tray !== lastTray || status.key !== lastTrayKey)) {
        tray.setImage(iconPath(status.key))
        lastTray = tray
        lastTrayKey = status.key
        lastTrayText = null
      }
      // The text can change while the icon stays the same (e.g. connect -> retry).
      if (tray && !tray.isDestroyed() && status.tooltip !== lastTrayText) {
        tray.setToolTip(status.tooltip)
        lastTrayText = status.tooltip
      }
      if (
        window &&
        !window.isDestroyed() &&
        (forceWindow || window !== lastWindow || status.tooltip !== lastWindowKey)
      ) {
        if (platform === 'win32') window.setOverlayIcon(overlay(status.key), status.tooltip)
        lastWindow = window
        lastWindowKey = status.tooltip
      }
    },
  }
}

module.exports = { MODES, INDICATORS, desktopStatus, createDesktopIcons }
