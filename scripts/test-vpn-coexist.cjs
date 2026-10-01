// Manual harness: the game session and the VPN running side by side.
//
// Uses the saved state, so it needs a configured relay with enabled WireGuard
// nodes, a saved VPN node, the network service installed, and an elevated
// shell. Run with the GamePath app closed: `npm run vpn:coexist-test`.
//
// What it proves, in order:
//   1. Both slots connect at once.
//   2. Traffic to an address the VPN selects leaves with the VPN's public IP.
//   3. Starting the VPN does not move the game's latency (p50 within 1 ms).
//   4. Twenty VPN rule edits leave the game session untouched.
//   5. Killing the VPN's engine leaves the game connected.
//
// The address check is a TCP request, never DNS: a TCP-only proxy hijacks DNS
// replies, so a lookup proves nothing about where traffic leaves.
const { app, safeStorage } = require('electron')
const dns = require('node:dns').promises
const fs = require('node:fs')
const https = require('node:https')
const path = require('node:path')
const { spawnSync } = require('node:child_process')
const { ServiceBridge } = require('../electron/service.cjs')
const { nodeSpec } = require('../electron/node-spec.cjs')

app.setName('gamepath-client')

const IP_ECHO = process.env.GAMEPATH_IP_ECHO || 'https://api.ipify.org'
const GAME_PROBE = { kind: 'ip', value: '8.8.4.4/32' }
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
const decrypt = (stored) => safeStorage.decryptString(Buffer.from(stored, 'base64'))

function publicAddress(url) {
  return new Promise((resolve) => {
    const request = https.get(url, { timeout: 8000 }, (response) => {
      let body = ''
      response.on('data', (chunk) => (body += chunk))
      response.on('end', () => resolve(body.trim()))
    })
    request.on('timeout', () => request.destroy())
    request.on('error', () => resolve(null))
  })
}

async function latencySamples(service, count) {
  const samples = []
  for (let index = 0; index < count; index += 1) {
    const status = await service.request('session-status')
    const best = Math.min(...status.paths.map((route) => route.latencyMs ?? Infinity))
    if (Number.isFinite(best)) samples.push(best)
    await wait(1000)
  }
  samples.sort((left, right) => left - right)
  return samples[Math.floor(samples.length / 2)] ?? null
}

function vpnEngineProcessIds() {
  const result = spawnSync(
    'powershell.exe',
    [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      "Get-CimInstance Win32_Process -Filter \"Name='gamepath-engine.exe'\" | Where-Object { $_.CommandLine -like '*--role vpn*' } | ForEach-Object { $_.ProcessId }",
    ],
    { encoding: 'utf8', windowsHide: true },
  )
  return (result.stdout || '').split(/\s+/).filter(Boolean)
}

function check(condition, message) {
  if (!condition) throw new Error(message)
  console.log(`ok - ${message}`)
}

app
  .whenReady()
  .then(async () => {
    const state = JSON.parse(fs.readFileSync(path.join(app.getPath('userData'), 'gamepath-state.json'), 'utf8'))
    const relay = state.relays.find((item) => item.id === state.activeRelayId)
    const tunnels = state.tunnels.filter((item) => item.enabled && item.kind === 'wireguard')
    if (!relay?.address || !state.encryptedRelayTokens?.[relay.id] || !tunnels.length) {
      throw new Error('Configure a relay and enable at least one WireGuard node first')
    }
    if (!state.vpn?.node || !state.encryptedVpnConfig) throw new Error('Save a VPN node first')

    const service = new ServiceBridge()
    const echoHost = new URL(IP_ECHO).hostname
    const echoIp = (await dns.lookup(echoHost, { family: 4 })).address
    const before = await publicAddress(IP_ECHO)
    console.log(`public address without the VPN: ${before ?? 'unreachable'}`)

    const game = {
      relayHost: relay.address,
      relayPort: relay.port,
      enrollmentToken: decrypt(state.encryptedRelayTokens[relay.id]),
      wireguardConfigs: tunnels.map((tunnel) => decrypt(state.encryptedConfigs[tunnel.id])),
      trafficMode: 'split',
      rules: [GAME_PROBE],
    }
    const vpn = {
      slot: 'vpn',
      sessionId: 'vpn-harness',
      mode: 'direct',
      trafficMode: 'split',
      remoteDns: false,
      killSwitch: false,
      rules: [{ kind: 'ip', value: `${echoIp}/32` }],
      nodes: [nodeSpec(state.vpn.node, decrypt(state.encryptedVpnConfig))],
    }
    try {
      await service.request('start-session', game, 30000)
      const gameBefore = await service.request('session-status')
      const baseline = await latencySamples(service, 15)
      console.log(`game p50 before the VPN: ${baseline} ms`)

      await service.request('start-session', vpn, 60000)
      const slots = (await service.request('status')).slots
      check(
        slots.game.sessionStatus === 'connected' && slots.vpn.sessionStatus === 'connected',
        'both slots are connected at once',
      )

      const through = await publicAddress(IP_ECHO)
      check(through && through !== before, `the VPN-selected address leaves through the VPN (${through})`)

      const during = await latencySamples(service, 15)
      console.log(`game p50 with the VPN: ${during} ms`)
      check(during != null && baseline != null && during - baseline <= 1, 'the game latency did not move')

      for (let index = 0; index < 20; index += 1) {
        const rules = index % 2 ? vpn.rules : [...vpn.rules, { kind: 'ip', value: '203.0.113.0/24' }]
        await service.request('update-session-rules', { slot: 'vpn', rules })
      }
      const gameAfterEdits = await service.request('session-status')
      check(
        gameAfterEdits.sessionId === gameBefore.sessionId && gameAfterEdits.state === 'connected',
        'twenty VPN rule edits left the game session untouched',
      )

      const engines = vpnEngineProcessIds()
      check(engines.length === 1, 'the VPN runs in an engine of its own')
      spawnSync('taskkill.exe', ['/PID', engines[0], '/F'], { windowsHide: true })
      await wait(3000)
      const gameAfterKill = await service.request('session-status')
      check(gameAfterKill.state === 'connected', 'the game stayed connected when the VPN engine died')
    } finally {
      await service.request('stop-session', { slot: 'vpn' }).catch(() => undefined)
      await service.request('stop-session').catch(() => undefined)
    }
    app.quit()
  })
  .catch((error) => {
    console.error(`not ok - ${error.message}`)
    app.exit(1)
  })
