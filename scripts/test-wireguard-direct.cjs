// Manual integration test using an encrypted saved WireGuard node.
// Close GamePath and deactivate this profile in the official WireGuard app.
// Run: electron scripts/test-wireguard-direct.cjs --node <saved-node-name>
// Optional --mtu <1280..1500> changes only this test's config, never saved state.
const { app, safeStorage } = require('electron')
const fs = require('node:fs')
const path = require('node:path')
const dns = require('node:dns').promises
const https = require('node:https')
const { ServiceBridge } = require('../electron/service.cjs')

app.setName('gamepath-client')
app.disableHardwareAcceleration()

function option(name) {
  const index = process.argv.indexOf(name)
  return index < 0 ? undefined : process.argv[index + 1]
}

function download(hostname, address) {
  return new Promise((resolve, reject) => {
    const started = Date.now()
    const request = https.get(
      {
        hostname,
        path: '/',
        lookup: (_host, options, callback) => callback(null, options.all ? [{ address, family: 4 }] : address, 4),
        agent: false,
        headers: { 'User-Agent': 'GamePath-diagnostic' },
      },
      (response) => {
        let bytes = 0
        response.on('data', (chunk) => (bytes += chunk.length))
        response.on('error', reject)
        response.on('end', () => {
          if (response.statusCode !== 200 || bytes < 16384) {
            reject(new Error(`${hostname}: HTTP ${response.statusCode}, ${bytes} bytes`))
          } else {
            resolve({ hostname, bytes, ms: Date.now() - started })
          }
        })
      },
    )
    const timer = setTimeout(() => request.destroy(new Error(`${hostname}: download timed out`)), 15000)
    request.on('close', () => clearTimeout(timer))
    request.on('error', reject)
  })
}

app
  .whenReady()
  .then(async () => {
    const name = option('--node')
    if (!name) throw new Error('Supply --node <saved-node-name>')
    const state = JSON.parse(fs.readFileSync(path.join(app.getPath('userData'), 'gamepath-state.json'), 'utf8'))
    const node = [...(state.vpn?.nodes || []), ...(state.tunnels || [])].find(
      (item) => item.name === name && item.kind === 'wireguard',
    )
    const stored = node && (state.encryptedVpnConfigs?.[node.id] || state.encryptedConfigs?.[node.id])
    if (!stored || !safeStorage.isEncryptionAvailable()) throw new Error('Saved WireGuard configuration unavailable')
    let config = safeStorage.decryptString(Buffer.from(stored, 'base64'))
    const mtuOption = option('--mtu')
    if (mtuOption !== undefined) {
      const mtu = Number(mtuOption)
      if (!Number.isInteger(mtu) || mtu < 1280 || mtu > 1500) throw new Error('--mtu must be 1280..1500')
      config = config.replace(/^\s*MTU\s*=.*$/gim, '').replace(/\[Interface\]/i, `[Interface]\nMTU = ${mtu}`)
    }
    const service = new ServiceBridge()
    const slots = (await service.request('status')).slots
    if (slots.game.sessionStatus !== 'idle') throw new Error('Stop the game session before this test')
    const targets = await Promise.all(
      ['github.com', 'www.cloudflare.com'].map(async (hostname) => ({
        hostname,
        address: (await dns.lookup(hostname, { family: 4 })).address,
      })),
    )
    let sessionId
    let heartbeat
    try {
      await service.request(
        'start-session',
        {
          slot: 'game',
          sessionId: 'wireguard-direct-test',
          mode: 'direct',
          trafficMode: 'split',
          remoteDns: false,
          killSwitch: true,
          nodes: [{ kind: 'wireguard', config, label: name }],
          rules: [
            ...targets.map(({ address }) => ({ kind: 'ip', value: `${address}/32` })),
            { kind: 'ip', value: '8.8.8.8/32' },
          ],
        },
        30000,
      )
      sessionId = (await service.request('session-status')).sessionId
      heartbeat = setInterval(() => service.request('session-status').catch(() => {}), 3000)
      const resolver = new dns.Resolver({ timeout: 2000, tries: 3 })
      resolver.setServers(['8.8.8.8'])
      await resolver.resolve4('example.com')
      const downloads = await Promise.all(targets.map(({ hostname, address }) => download(hostname, address)))
      const status = await service.request('session-status')
      if (status.sessionId !== sessionId) throw new Error('Another client replaced the test session')
      const capture = status.capture?.diagnostics
      if (!capture?.relayedPackets || !capture?.injectedReturnPackets) throw new Error('Downloads bypassed capture')
      console.log(JSON.stringify({ node: name, effectiveMtu: status.effectiveMtu, tcpMss: capture.tcpMss, downloads }))
    } finally {
      clearInterval(heartbeat)
      const current = await service.request('session-status').catch(() => null)
      if (sessionId && current?.sessionId === sessionId) await service.request('stop-session', {}, 10000)
    }
    app.quit()
  })
  .catch((error) => {
    console.error(error.message)
    app.exit(1)
  })
