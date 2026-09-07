const { app, safeStorage } = require('electron')
const fs = require('node:fs')
const path = require('node:path')
const { spawnSync } = require('node:child_process')
const { ServiceBridge } = require('../electron/service.cjs')

app.setName('gamepath-client')

app
  .whenReady()
  .then(async () => {
    const state = JSON.parse(fs.readFileSync(path.join(app.getPath('userData'), 'gamepath-state.json'), 'utf8'))
    const relay = state.relays.find((item) => item.id === state.activeRelayId)
    const tunnels = state.tunnels.filter((item) => item.enabled)
    const encryptedToken = relay && state.encryptedRelayTokens?.[relay.id]
    if (!relay?.address || !encryptedToken || !tunnels.length) throw new Error('Local test profile is incomplete')
    const splitIp = process.argv.includes('--split-ip')
    const service = new ServiceBridge(
      process.env.GAMEPATH_SERVICE_PORT
        ? {
            port: Number(process.env.GAMEPATH_SERVICE_PORT),
            tokenFile: process.env.GAMEPATH_SERVICE_TOKEN_FILE,
          }
        : undefined,
    )
    const payload = {
      relayHost: relay.address,
      relayPort: relay.port,
      enrollmentToken: safeStorage.decryptString(Buffer.from(encryptedToken, 'base64')),
      wireguardConfigs: tunnels.map((tunnel) =>
        safeStorage.decryptString(Buffer.from(state.encryptedConfigs[tunnel.id], 'base64')),
      ),
      trafficMode: splitIp ? 'split' : 'all',
      rules: splitIp ? [{ kind: 'ip', value: '1.1.1.1/32' }] : [],
    }
    try {
      const started = await service.request('start-session', payload, 30000)
      const current = await service.request('session-status')
      if (current.state !== 'connected' || !started.dataPlane.reachable)
        throw new Error('Privileged session did not reach connected state')
      if (started.capture?.state === 'capturing') {
        const ping = spawnSync('ping.exe', ['-n', '1', '-w', '5000', '1.1.1.1'], {
          encoding: 'utf8',
          windowsHide: true,
        })
        if (ping.status !== 0) {
          const afterPing = await service.request('session-status')
          const routes = spawnSync('route.exe', ['PRINT', '-4'], { encoding: 'utf8', windowsHide: true })
          const addresses = spawnSync(
            'powershell.exe',
            [
              '-NoProfile',
              '-NonInteractive',
              '-Command',
              `Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex ${started.capture.adapterIndex} -ErrorAction SilentlyContinue | ConvertTo-Json -Compress`,
            ],
            { encoding: 'utf8', windowsHide: true },
          )
          throw new Error(
            `Wintun system ping failed; capture=${JSON.stringify(started.capture)}; addresses=${(addresses.stdout || '').trim()}; paths=${JSON.stringify(afterPing.paths)}; ping=${(ping.stdout || ping.stderr || '').trim()}; routes=${(routes.stdout || '').trim()}`,
          )
        }
      }
      console.log(
        `Privileged multipath session connected ${current.paths.length} paths with ${started.capture?.backend ?? 'no'} ${payload.trafficMode} capture; benchmark loop ${Math.round(started.dataPlane.latencyMs)} ms.`,
      )
    } finally {
      await service.request('stop-session').catch(() => undefined)
    }
    app.quit()
  })
  .catch((error) => {
    console.error(error.message)
    app.exit(1)
  })
