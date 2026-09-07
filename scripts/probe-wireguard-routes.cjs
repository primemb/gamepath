const { app, safeStorage } = require('electron')
const fs = require('node:fs')
const path = require('node:path')
const { EngineBridge } = require('../electron/engine.cjs')

app.setName('gamepath-client')

app
  .whenReady()
  .then(async () => {
    const projectRoot = path.join(__dirname, '..')
    const state = JSON.parse(fs.readFileSync(path.join(app.getPath('userData'), 'gamepath-state.json'), 'utf8'))
    const relay = state.relays.find((item) => item.id === state.activeRelayId)
    const tunnels = state.tunnels.filter((item) => item.enabled)
    const encryptedToken = relay && state.encryptedRelayTokens?.[relay.id]
    if (!relay?.address || !encryptedToken) throw new Error('The active relay is not configured')
    if (tunnels.length < 2) throw new Error('At least two WireGuard routes must be enabled')
    if (!safeStorage.isEncryptionAvailable()) throw new Error('Windows secure storage is unavailable')
    const engine = new EngineBridge(projectRoot)
    await engine.start()
    try {
      const result = await engine.request('probe-wireguard-routes', {
        relayHost: relay.address,
        relayPort: relay.port,
        enrollmentToken: safeStorage.decryptString(Buffer.from(encryptedToken, 'base64')),
        wireguardConfigs: tunnels.map((tunnel) =>
          safeStorage.decryptString(Buffer.from(state.encryptedConfigs[tunnel.id], 'base64')),
        ),
      })
      const summary = result.routes
        .map((route) => `route ${route.route}: ${Math.round(route.latencyMs)} ms`)
        .join(' · ')
      console.log(`User-space WireGuard paths authenticated through the relay — ${summary}.`)
    } finally {
      engine.stop()
    }
    app.quit()
  })
  .catch((error) => {
    console.error(error.message)
    app.exit(1)
  })
