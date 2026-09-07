/**
 * Isolates which leg of a SOCKS5 route is failing.
 *
 * A SOCKS5 node in relay mode has three things that must all work, and the
 * session error only reports that the last one did not. So each is checked in
 * order, and the first failure names the leg rather than the symptom:
 *
 *   1. the relay itself, reached directly over the normal connection;
 *   2. the proxy's UDP association, opened and addressed at the relay;
 *   3. an authenticated frame carried through the proxy to the relay, and the
 *      relay's reply carried back.
 *
 * Step 3 is what a session waits for. A proxy that passes step 2 but fails
 * step 3 is forwarding datagrams somewhere other than the relay, or is not
 * getting the reply back — which is what happens when a proxy's routing rules
 * treat the relay's port differently from DNS, or when its egress port moves
 * between datagrams.
 */
const { app, safeStorage } = require('electron')
const fs = require('node:fs')
const path = require('node:path')
const { EngineBridge } = require('../electron/engine.cjs')

app.setName('gamepath-client')

const line = (label, detail) => console.log(`${label.padEnd(26)} ${detail}`)

app
  .whenReady()
  .then(async () => {
    const projectRoot = path.join(__dirname, '..')
    const state = JSON.parse(fs.readFileSync(path.join(app.getPath('userData'), 'gamepath-state.json'), 'utf8'))
    if (!safeStorage.isEncryptionAvailable()) throw new Error('Windows secure storage is unavailable')

    const relay = state.relays.find((item) => item.id === state.activeRelayId)
    const encryptedToken = relay && state.encryptedRelayTokens?.[relay.id]
    if (!relay?.address || !encryptedToken) throw new Error('The active relay is not configured')
    const enrollmentToken = safeStorage.decryptString(Buffer.from(encryptedToken, 'base64'))

    const proxies = state.tunnels.filter((tunnel) => tunnel.kind === 'socks5')
    if (!proxies.length) throw new Error('No SOCKS5 node is saved')

    line('Relay', `${relay.address}:${relay.port}`)
    line('SOCKS5 nodes', proxies.map((item) => item.endpoint).join(', '))
    console.log()

    const engine = new EngineBridge(projectRoot)
    await engine.start()
    try {
      // 1. The relay over the normal connection. If this fails nothing else
      //    can pass, and the proxy is not the problem.
      try {
        const direct = await engine.request('probe-relay', {
          relayHost: relay.address,
          relayPort: relay.port,
          enrollmentToken,
        })
        line('1. relay direct', `OK — ${Math.round(direct.latencyMs)} ms, tunnel IP ${direct.virtualIpv4}`)
      } catch (error) {
        line('1. relay direct', `FAILED — ${error.message}`)
        console.log('\nThe relay is not answering over your normal connection, so no node can reach it.')
        return
      }

      // 2 and 3 together: the engine's node probe opens the association and
      //    then waits for the relay's authenticated reply through it.
      for (const proxy of proxies) {
        const stored = state.encryptedConfigs?.[proxy.id]
        const credentials = stored ? JSON.parse(safeStorage.decryptString(Buffer.from(stored, 'base64'))) : {}
        try {
          const result = await engine.request(
            'probe-socks5-node',
            {
              relayHost: relay.address,
              relayPort: relay.port,
              enrollmentToken,
              host: proxy.host,
              port: proxy.port,
              username: credentials.username || null,
              password: credentials.password || null,
            },
            20000,
          )
          line(`2. ${proxy.endpoint} associate`, `OK — ${Math.round(result.setupLatencyMs)} ms`)
          line(`3. ${proxy.endpoint} to relay`, `OK — ${Math.round(result.latencyMs)} ms round trip`)
        } catch (error) {
          const associated = /did not answer|no reply|timed out/i.test(error.message)
          line(`2. ${proxy.endpoint} associate`, associated ? 'OK' : `FAILED — ${error.message}`)
          if (associated) {
            line(`3. ${proxy.endpoint} to relay`, `FAILED — ${error.message}`)
            console.log(
              [
                '',
                'The proxy accepted a UDP association but the relay never answered through it.',
                'The association working for DNS does not prove this: proxy clients often route',
                `port 53 through a dedicated outbound. Check that the proxy forwards UDP to`,
                `${relay.address}:${relay.port} rather than blocking it or sending it direct, and that`,
                `UDP ${relay.port} is open on the relay's firewall.`,
              ].join('\n'),
            )
          }
        }
      }
    } finally {
      engine.stop()
    }
    app.quit()
  })
  .catch((error) => {
    console.error(error.message)
    app.exit(1)
  })
