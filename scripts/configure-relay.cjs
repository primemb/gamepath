const { app, safeStorage } = require('electron')
const fs = require('node:fs')
const path = require('node:path')

app.setName('gamepath-client')

function argument(name, fallback = '') {
  const index = process.argv.indexOf(name)
  return index >= 0 ? process.argv[index + 1] : fallback
}

app.whenReady().then(() => {
  const address = argument('--address')
  const port = Number(argument('--port', '51821'))
  const tokenFile = argument('--token-file')
  const relayId = argument('--relay-id', 'tr-istanbul-01')
  if (!address || !tokenFile || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('Usage: electron scripts/configure-relay.cjs --address HOST --port PORT --token-file FILE [--relay-id ID]')
  }
  if (!safeStorage.isEncryptionAvailable()) throw new Error('Windows secure storage is unavailable')
  const token = fs.readFileSync(path.resolve(tokenFile), 'utf8').trim()
  if (!token.startsWith('gpe1_') || token.length < 80) throw new Error('Invalid GamePath enrollment token')

  const destination = path.join(app.getPath('userData'), 'gamepath-state.json')
  const state = fs.existsSync(destination) ? JSON.parse(fs.readFileSync(destination, 'utf8')) : {}
  state.encryptedRelayTokens ??= {}
  state.encryptedRelayTokens[relayId] = safeStorage.encryptString(token).toString('base64')
  state.relays ??= []
  const relay = state.relays.find((item) => item.id === relayId)
  if (!relay) throw new Error(`Relay not found in local state: ${relayId}`)
  relay.address = address
  relay.port = port
  relay.status = 'ready'
  relay.hasEnrollmentToken = true
  state.activeRelayId = relayId
  const temporary = `${destination}.tmp`
  fs.writeFileSync(temporary, JSON.stringify(state, null, 2), { encoding: 'utf8', mode: 0o600 })
  fs.renameSync(temporary, destination)
  console.log(`Configured ${relay.city} relay at ${address}:${port}; credential protected by Windows.`)
  app.quit()
}).catch((error) => {
  console.error(error.message)
  app.exit(1)
})
