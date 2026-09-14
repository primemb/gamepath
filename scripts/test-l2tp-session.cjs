const { app, safeStorage } = require('electron')
const fs = require('node:fs')
const path = require('node:path')
const { execFileSync } = require('node:child_process')
const { ServiceBridge } = require('../electron/service.cjs')

app.setName('gamepath-client')

function routeExists(prefix, interfaceIndex) {
  const script =
    `$r=Get-NetRoute -PolicyStore ActiveStore -AddressFamily IPv4 -DestinationPrefix '${prefix}' ` +
    `-InterfaceIndex ${Number(interfaceIndex)} -ErrorAction SilentlyContinue;if($r){exit 0}else{exit 1}`
  try {
    execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
}

function interfaceMtu(interfaceIndex) {
  const script =
    `Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex ${Number(interfaceIndex)} -ErrorAction Stop|` +
    'Select-Object -ExpandProperty NlMtuBytes'
  return Number(
    execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
      encoding: 'utf8',
      windowsHide: true,
    }).trim(),
  )
}

app
  .whenReady()
  .then(async () => {
    const server = process.env.GAMEPATH_L2TP_SERVER
    const preSharedKey = process.env.GAMEPATH_L2TP_PSK
    const username = process.env.GAMEPATH_L2TP_USERNAME
    const password = process.env.GAMEPATH_L2TP_PASSWORD
    if (!server || !preSharedKey || !username || !password) {
      throw new Error('Set GAMEPATH_L2TP_SERVER, GAMEPATH_L2TP_PSK, GAMEPATH_L2TP_USERNAME and GAMEPATH_L2TP_PASSWORD')
    }
    const mode = process.argv.includes('--direct') ? 'direct' : 'relay'
    const service = new ServiceBridge({
      port: Number(process.env.GAMEPATH_SERVICE_PORT || 47983),
      tokenFile: process.env.GAMEPATH_SERVICE_TOKEN_FILE,
    })
    const node = { kind: 'l2tp', server, preSharedKey, username, password, label: 'L2TP live test' }
    let relayFields = {}
    if (mode === 'relay') {
      const state = JSON.parse(fs.readFileSync(path.join(app.getPath('userData'), 'gamepath-state.json'), 'utf8'))
      const relay = state.relays.find((item) => item.id === state.activeRelayId)
      const encryptedToken = relay && state.encryptedRelayTokens?.[relay.id]
      if (!relay?.address || !encryptedToken) throw new Error('The selected GamePath relay is not configured')
      relayFields = {
        relayHost: relay.address,
        relayPort: relay.port,
        enrollmentToken: safeStorage.decryptString(Buffer.from(encryptedToken, 'base64')),
      }
    }
    let directAdapterIndex = null
    try {
      const result = await service.request(
        'start-session',
        {
          mode,
          strategy: 'adaptive',
          nodes: [node],
          trafficMode: 'split',
          rules: [{ kind: 'ip', value: '1.1.1.1/32' }],
          ...relayFields,
        },
        60000,
      )
      console.log(
        `L2TP ${mode} session connected; data-plane RTT ${Math.round(result.dataPlane.latencyMs)} ms; capture ${result.capture.backend}.`,
      )
      if (mode === 'direct') {
        directAdapterIndex = result.capture.adapterIndex
        if (!result.capture.splitTunneling) {
          throw new Error(
            'The live split test requires the installed elevated service; it refused a full-tunnel fallback',
          )
        }
        if (result.capture.effectiveMtu !== 1384 || interfaceMtu(directAdapterIndex) !== 1384) {
          throw new Error('Windows did not apply the safe L2TP interface MTU')
        }
        if (!routeExists('1.1.1.1/32', directAdapterIndex)) {
          throw new Error('Windows did not install the initial L2TP split route')
        }
        const status = await service.request('session-status')
        if (status.state !== 'connected' || status.capture?.backend !== 'windows-ras') {
          throw new Error('The native L2TP direct session did not remain connected')
        }
        const capture = await service.request('update-session-rules', {
          rules: [{ kind: 'ip', value: '1.0.0.1/32' }],
        })
        if (capture.targetCount !== 1) throw new Error('The native L2TP split route did not update')
        await service.request('session-status')
        if (!routeExists('1.0.0.1/32', directAdapterIndex) || routeExists('1.1.1.1/32', directAdapterIndex)) {
          throw new Error('Windows did not replace the live L2TP split route')
        }
      }
    } finally {
      await service.request('stop-session').catch(() => undefined)
      if (
        directAdapterIndex &&
        (routeExists('1.1.1.1/32', directAdapterIndex) || routeExists('1.0.0.1/32', directAdapterIndex))
      ) {
        throw new Error('An L2TP split route remained after the session stopped')
      }
      app.quit()
    }
  })
  .catch((error) => {
    console.error(error.message)
    app.exit(1)
  })
