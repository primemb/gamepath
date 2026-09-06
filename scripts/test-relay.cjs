const { app, safeStorage } = require('electron')
const fs = require('node:fs')
const path = require('node:path')
const { EngineBridge } = require('../electron/engine.cjs')

app.setName('gamepath-client')

app.whenReady().then(async () => {
  const projectRoot = path.join(__dirname, '..')
  const state = JSON.parse(fs.readFileSync(path.join(app.getPath('userData'), 'gamepath-state.json'), 'utf8'))
  const relay = state.relays.find((item) => item.id === state.activeRelayId)
  const encryptedToken = relay && state.encryptedRelayTokens?.[relay.id]
  if (!relay?.address || !encryptedToken) throw new Error('The active relay is not configured')
  if (!safeStorage.isEncryptionAvailable()) throw new Error('Windows secure storage is unavailable')
  const engine = new EngineBridge(projectRoot)
  await engine.start()
  try {
    const result = await engine.request('probe-relay', {
      relayHost: relay.address,
      relayPort: relay.port,
      enrollmentToken: safeStorage.decryptString(Buffer.from(encryptedToken, 'base64')),
    })
    console.log(`Authenticated relay ready at ${Math.round(result.latencyMs)} ms; tunnel IP ${result.virtualIpv4}.`)
  } finally {
    engine.stop()
  }
  app.quit()
}).catch((error) => {
  console.error(error.message)
  app.exit(1)
})

