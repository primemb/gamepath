const { app, safeStorage } = require('electron')
const dns = require('node:dns').promises
const fs = require('node:fs')
const path = require('node:path')
const { ServiceBridge } = require('../electron/service.cjs')

app.setName('gamepath-client')

app.whenReady().then(async () => {
  const state = JSON.parse(fs.readFileSync(path.join(app.getPath('userData'), 'gamepath-state.json'), 'utf8'))
  const relay = state.relays.find((item) => item.id === state.activeRelayId)
  const tunnels = state.tunnels.filter((item) => item.enabled)
  if (!relay?.address) throw new Error('The active relay is not configured')
  if (tunnels.length < 2) throw new Error('At least two WireGuard routes must be enabled')
  if (!safeStorage.isEncryptionAvailable()) throw new Error('Windows secure storage is unavailable')
  const addresses = await dns.lookup(relay.address, { all: true })
  const relayIp = addresses.find((entry) => entry.family === 4)?.address ?? addresses[0]?.address
  const service = new ServiceBridge()
  const result = await service.request('validate-runtime', {
    relayIp,
    trafficMode: 'all',
    wireguardConfigs: tunnels.map((tunnel) => safeStorage.decryptString(Buffer.from(state.encryptedConfigs[tunnel.id], 'base64'))),
  })
  console.log(`Privileged runtime validated ${result.routeCount} routes in ${result.trafficMode} mode.`)
  app.quit()
}).catch((error) => {
  console.error(error.message)
  app.exit(1)
})
