const { app, safeStorage } = require('electron')
const fs = require('node:fs')
const path = require('node:path')
const dns = require('node:dns').promises
const { ServiceBridge } = require('../electron/service.cjs')

app.setName('gamepath-client')
const wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds))

app.whenReady().then(async () => {
  const state = JSON.parse(fs.readFileSync(path.join(app.getPath('userData'), 'gamepath-state.json'), 'utf8'))
  const relay = state.relays.find((item) => item.id === state.activeRelayId)
  if (!relay) throw new Error('No active relay is configured')
  const configs = state.tunnels.filter((item) => item.enabled).map((item) => safeStorage.decryptString(Buffer.from(state.encryptedConfigs[item.id], 'base64')))
  const enrollmentToken = safeStorage.decryptString(Buffer.from(state.encryptedRelayTokens[relay.id], 'base64'))
  const service = new ServiceBridge()
  await service.inspect()
  try {
    await service.request('start-session', {
      relayHost: relay.address,
      relayPort: relay.port,
      enrollmentToken,
      wireguardConfigs: configs,
      trafficMode: 'split',
      rules: state.rules.filter((rule) => rule.enabled).map(({ kind, value }) => ({ kind, value })),
    }, 30_000)
    for (let sample = 1; sample <= 5; sample++) {
      await wait(2_000)
      const status = await service.request('session-status')
      await dns.lookup('example.com')
      console.log(`sample=${sample} state=${status.state} normalInternet=reachable`)
    }
  } finally {
    await service.request('stop-session').catch(() => {})
    app.quit()
  }
}).catch((error) => { console.error(error.message); app.exit(1) })
