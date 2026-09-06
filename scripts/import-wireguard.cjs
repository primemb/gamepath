const { app, safeStorage } = require('electron')
const crypto = require('node:crypto')
const fs = require('node:fs')
const path = require('node:path')
const { parseWireGuardConfig } = require('../electron/wireguard.cjs')

app.setName('gamepath-client')

app.whenReady().then(() => {
  const files = process.argv.filter((value) => value.toLowerCase().endsWith('.conf'))
  if (!files.length) throw new Error('Pass one or more WireGuard .conf files')
  if (!safeStorage.isEncryptionAvailable()) throw new Error('Windows secure storage is unavailable')
  const destination = path.join(app.getPath('userData'), 'gamepath-state.json')
  const state = JSON.parse(fs.readFileSync(destination, 'utf8'))
  state.tunnels ??= []
  state.encryptedConfigs ??= {}
  for (const input of files) {
    const filePath = path.resolve(input)
    const source = fs.readFileSync(filePath, 'utf8')
    const tunnel = parseWireGuardConfig(source, filePath, crypto.randomUUID())
    const duplicates = state.tunnels.filter((item) => item.name === tunnel.name)
    for (const duplicate of duplicates) delete state.encryptedConfigs[duplicate.id]
    state.tunnels = state.tunnels.filter((item) => item.name !== tunnel.name)
    state.tunnels.push(tunnel)
    state.encryptedConfigs[tunnel.id] = safeStorage.encryptString(source).toString('base64')
  }
  const temporary = `${destination}.tmp`
  fs.writeFileSync(temporary, JSON.stringify(state, null, 2), { encoding: 'utf8', mode: 0o600 })
  fs.renameSync(temporary, destination)
  console.log(`Imported and protected ${files.length} WireGuard configuration(s).`)
  app.quit()
}).catch((error) => {
  console.error(error.message)
  app.exit(1)
})

