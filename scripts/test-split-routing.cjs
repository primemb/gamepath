const { app, safeStorage } = require('electron')
const { execFile } = require('node:child_process')
const fs = require('node:fs')
const http = require('node:http')
const path = require('node:path')
const { promisify } = require('node:util')
const { ServiceBridge } = require('../electron/service.cjs')

const run = promisify(execFile)
app.setName('gamepath-client')

function readPublicAddress() {
  return new Promise((resolve, reject) => {
    const request = http.get('http://api.ipify.org', { timeout: 10_000 }, (response) => {
      let body = ''
      response.setEncoding('utf8')
      response.on('data', (chunk) => { body += chunk })
      response.on('end', () => resolve(body.trim()))
    })
    request.on('timeout', () => request.destroy(new Error('normal Internet check timed out')))
    request.on('error', reject)
  })
}

app.whenReady().then(async () => {
  const state = JSON.parse(fs.readFileSync(path.join(app.getPath('userData'), 'gamepath-state.json'), 'utf8'))
  const relay = state.relays.find((item) => item.id === state.activeRelayId)
  if (!relay) throw new Error('No active relay is configured')
  const configs = state.tunnels
    .filter((item) => item.enabled)
    .map((item) => safeStorage.decryptString(Buffer.from(state.encryptedConfigs[item.id], 'base64')))
  const enrollmentToken = safeStorage.decryptString(Buffer.from(state.encryptedRelayTokens[relay.id], 'base64'))
  const service = new ServiceBridge()
  const curl = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'curl.exe')

  try {
    const started = await service.request('start-session', {
      relayHost: relay.address,
      relayPort: relay.port,
      enrollmentToken,
      wireguardConfigs: configs,
      trafficMode: 'split',
      rules: [{ kind: 'application', value: curl }],
    }, 30_000)
    let response
    let requestError
    let throughputBytesPerSecond = null
    let throughputSeconds = null
    let throughputConnectSeconds = null
    let throughputStartTransferSeconds = null
    const keepAlive = setInterval(() => service.request('session-status').catch(() => {}), 2_000)
    try {
      response = await run(curl, ['-4', '--fail', '--max-time', '15', 'http://api.ipify.org'], { windowsHide: true })
      if (process.argv.includes('--throughput')) {
        const throughputBytes = Number(process.env.GAMEPATH_TEST_BYTES || 1_000_000)
        const download = await run(curl, [
          '-4', '--location', '--fail', '--max-time', '120', '--output', 'NUL',
          '--silent', '--show-error', '--write-out', '%{speed_download} %{time_total} %{time_connect} %{time_starttransfer}',
          `http://speed.cloudflare.com/__down?bytes=${throughputBytes}`,
        ], { windowsHide: true })
        const [speed, seconds, connectSeconds, startTransferSeconds] = download.stdout.trim().split(/\s+/).map(Number)
        throughputBytesPerSecond = speed
        throughputSeconds = seconds
        throughputConnectSeconds = connectSeconds
        throughputStartTransferSeconds = startTransferSeconds
      }
    } catch (error) {
      requestError = error
      response ??= { stdout: '' }
    } finally {
      clearInterval(keepAlive)
    }
    const status = await service.request('session-status')
    const normalPublicAddress = await readPublicAddress()
    const diagnostics = status.capture?.diagnostics
    if (!diagnostics || diagnostics.relayedPackets < 1 || diagnostics.capturedPackets < 1) {
      throw new Error(`curl traffic was not routed: ${JSON.stringify(diagnostics)}`)
    }
    if (!status.paths?.length || status.paths.some((item) => item.pathKind !== 'wireguard')) {
      throw new Error(`session exposed a non-WireGuard relay path: ${JSON.stringify(status.paths)}`)
    }
    const publicAddress = response.stdout.trim()
    if (publicAddress !== relay.address) {
      throw new Error(`selected application exited as ${publicAddress || 'unknown'} instead of relay ${relay.address}`)
    }
    if (!normalPublicAddress || normalPublicAddress === relay.address) {
      throw new Error(`unselected traffic did not remain on the normal Internet: ${normalPublicAddress || 'unknown'}`)
    }
    console.log(JSON.stringify({
      backend: started.capture.backend,
      publicAddress,
      normalPublicAddress,
      throughputMbps: throughputBytesPerSecond == null ? undefined : Number((throughputBytesPerSecond * 8 / 1_000_000).toFixed(2)),
      throughputSeconds,
      throughputConnectSeconds,
      throughputStartTransferSeconds,
      relayPaths: status.paths.map(({ label, pathKind, reachable, probesSent, probesReceived, probesLost }) => ({ label, pathKind, reachable, probesSent, probesReceived, probesLost })),
      diagnostics,
    }, null, 2))
    if (requestError) throw new Error(`routed curl request failed: ${requestError.message}`)
  } finally {
    await service.request('stop-session').catch(() => {})
    app.quit()
  }
}).catch((error) => { console.error(error.message); app.exit(1) })
