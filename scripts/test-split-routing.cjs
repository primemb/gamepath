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
      response.on('data', (chunk) => {
        body += chunk
      })
      response.on('end', () => resolve(body.trim()))
    })
    request.on('timeout', () => request.destroy(new Error('normal Internet check timed out')))
    request.on('error', reject)
  })
}

async function firstByteSample(curl) {
  const result = await run(
    curl,
    [
      '-4',
      '--fail',
      '--max-time',
      '15',
      '--output',
      'NUL',
      '--silent',
      '--write-out',
      '%{time_starttransfer}',
      'http://speed.cloudflare.com/__down?bytes=1',
    ],
    { windowsHide: true },
  )
  return Number(result.stdout.trim()) * 1000
}

function summarize(samples) {
  const sorted = [...samples].sort((left, right) => left - right)
  const percentile = (value) => sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * value) - 1)]
  return {
    samples: sorted.length,
    p50Ms: Number(percentile(0.5).toFixed(2)),
    p95Ms: Number(percentile(0.95).toFixed(2)),
    p99Ms: Number(percentile(0.99).toFixed(2)),
  }
}

app
  .whenReady()
  .then(async () => {
    const state = JSON.parse(fs.readFileSync(path.join(app.getPath('userData'), 'gamepath-state.json'), 'utf8'))
    const relay = state.relays.find((item) => item.id === state.activeRelayId)
    if (!relay) throw new Error('No active relay is configured')
    const enabledTunnels = state.tunnels.filter((item) => item.enabled)
    const configs = enabledTunnels.map((item) =>
      safeStorage.decryptString(Buffer.from(state.encryptedConfigs[item.id], 'base64')),
    )
    const enrollmentToken = safeStorage.decryptString(Buffer.from(state.encryptedRelayTokens[relay.id], 'base64'))
    const service = new ServiceBridge()
    const curl = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'curl.exe')
    const benchmarkSamples = process.argv.includes('--latency-benchmark')
      ? Number(process.env.GAMEPATH_LATENCY_SAMPLES || 20)
      : 0

    try {
      const directLatency = []
      for (let index = 0; index < benchmarkSamples; index += 1) directLatency.push(await firstByteSample(curl))
      const started = await service.request(
        'start-session',
        {
          relayHost: relay.address,
          relayPort: relay.port,
          enrollmentToken,
          wireguardConfigs: configs,
          routeLabels: enabledTunnels.map((item) => item.name),
          trafficMode: 'split',
          rules: [{ kind: 'application', value: curl }],
        },
        30_000,
      )
      let response
      let requestError
      let throughputBytesPerSecond = null
      let throughputSeconds = null
      let throughputConnectSeconds = null
      let throughputStartTransferSeconds = null
      const routedLatency = []
      const keepAlive = setInterval(() => service.request('session-status').catch(() => {}), 2_000)
      try {
        response = await run(curl, ['-4', '--fail', '--max-time', '15', 'http://api.ipify.org'], { windowsHide: true })
        if (process.argv.includes('--throughput')) {
          const throughputBytes = Number(process.env.GAMEPATH_TEST_BYTES || 1_000_000)
          const download = await run(
            curl,
            [
              '-4',
              '--location',
              '--fail',
              '--max-time',
              '120',
              '--output',
              'NUL',
              '--silent',
              '--show-error',
              '--write-out',
              '%{speed_download} %{time_total} %{time_connect} %{time_starttransfer}',
              `http://speed.cloudflare.com/__down?bytes=${throughputBytes}`,
            ],
            { windowsHide: true },
          )
          const [speed, seconds, connectSeconds, startTransferSeconds] = download.stdout.trim().split(/\s+/).map(Number)
          throughputBytesPerSecond = speed
          throughputSeconds = seconds
          throughputConnectSeconds = connectSeconds
          throughputStartTransferSeconds = startTransferSeconds
        }
        for (let index = 0; index < benchmarkSamples; index += 1) routedLatency.push(await firstByteSample(curl))
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
        throw new Error(
          `selected application exited as ${publicAddress || 'unknown'} instead of relay ${relay.address}`,
        )
      }
      if (!normalPublicAddress || normalPublicAddress === relay.address) {
        throw new Error(`unselected traffic did not remain on the normal Internet: ${normalPublicAddress || 'unknown'}`)
      }
      console.log(
        JSON.stringify(
          {
            backend: started.capture.backend,
            publicAddress,
            normalPublicAddress,
            throughputMbps:
              throughputBytesPerSecond == null
                ? undefined
                : Number(((throughputBytesPerSecond * 8) / 1_000_000).toFixed(2)),
            throughputSeconds,
            throughputConnectSeconds,
            throughputStartTransferSeconds,
            latencyBenchmark: benchmarkSamples
              ? {
                  direct: summarize(directLatency),
                  routed: summarize(routedLatency),
                  addedP50Ms: Number((summarize(routedLatency).p50Ms - summarize(directLatency).p50Ms).toFixed(2)),
                  addedP99Ms: Number((summarize(routedLatency).p99Ms - summarize(directLatency).p99Ms).toFixed(2)),
                }
              : undefined,
            relayPaths: status.paths.map(
              ({ label, pathKind, reachable, packetsReceived, probesSent, probesReceived, probesLost }, index) => ({
                label,
                pathKind,
                reachable,
                packetsReceived,
                workerIterations: status.pathWorkerIterations?.[index],
                probesSent,
                probesReceived,
                probesLost,
              }),
            ),
            strategy: status.strategy,
            selectedRoutes: status.selectedRoutes,
            diagnostics,
          },
          null,
          2,
        ),
      )
      if (requestError) throw new Error(`routed curl request failed: ${requestError.message}`)
    } finally {
      await service.request('stop-session').catch(() => {})
      app.quit()
    }
  })
  .catch((error) => {
    console.error(error.message)
    app.exit(1)
  })
