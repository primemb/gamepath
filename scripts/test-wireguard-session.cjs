const { app, safeStorage } = require('electron')
const fs = require('node:fs')
const path = require('node:path')
const { EngineBridge } = require('../electron/engine.cjs')

app.setName('gamepath-client')

const wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds))

app
  .whenReady()
  .then(async () => {
    const projectRoot = path.join(__dirname, '..')
    const state = JSON.parse(fs.readFileSync(path.join(app.getPath('userData'), 'gamepath-state.json'), 'utf8'))
    const relay = state.relays.find((item) => item.id === state.activeRelayId)
    const tunnels = state.tunnels.filter((item) => item.enabled)
    const encryptedToken = relay && state.encryptedRelayTokens?.[relay.id]
    if (!relay?.address || !encryptedToken) throw new Error('The active relay is not configured')
    if (tunnels.length < 1) throw new Error('At least one WireGuard route must be enabled')
    if (!safeStorage.isEncryptionAvailable()) throw new Error('Windows secure storage is unavailable')

    const engine = new EngineBridge(projectRoot)
    await engine.start()
    try {
      const payload = {
        relayHost: relay.address,
        relayPort: relay.port,
        enrollmentToken: safeStorage.decryptString(Buffer.from(encryptedToken, 'base64')),
        wireguardConfigs: tunnels.map((tunnel) =>
          safeStorage.decryptString(Buffer.from(state.encryptedConfigs[tunnel.id], 'base64')),
        ),
      }
      const started = await engine.request('start-wireguard-session', payload, 25000)
      if (started.state !== 'connected' || started.paths.some((route) => !route.reachable)) {
        throw new Error('Persistent WireGuard session did not connect every route')
      }
      const dataPlane = await engine.request('probe-data-plane', {}, 15000)
      if (!dataPlane.reachable) throw new Error('Multipath packet did not return from the relay TUN')
      const deadline = Date.now() + 20000
      let current
      do {
        await wait(500)
        current = await engine.request('wireguard-session-status')
      } while (Date.now() < deadline && current.paths.some((route) => route.packetsReceived < 2))
      if (current.state !== 'connected' || current.paths.some((route) => route.packetsReceived < 2)) {
        const counts = current.paths
          .map(
            (route) =>
              `route ${route.route} sent=${route.packetsSent} received=${route.packetsReceived} reachable=${route.reachable} error=${route.lastError || 'none'}`,
          )
          .join(' · ')
        throw new Error(`Persistent WireGuard path health checks did not continue: ${counts}`)
      }
      const summary = current.paths
        .map((route) => `${route.label}: ${Math.round(route.latencyMs)} ms, ${route.packetsReceived} replies`)
        .join(' · ')
      console.log(
        `Persistent user-space WireGuard session healthy — ${summary}; relay TUN data ${Math.round(dataPlane.latencyMs)} ms.`,
      )
      await engine.request('stop-wireguard-session')
    } finally {
      engine.stop()
    }
    app.quit()
  })
  .catch((error) => {
    console.error(error.message)
    app.exit(1)
  })
