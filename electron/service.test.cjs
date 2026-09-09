const assert = require('node:assert/strict')
const fs = require('node:fs')
const net = require('node:net')
const os = require('node:os')
const path = require('node:path')
const test = require('node:test')
const { ServiceBridge } = require('./service.cjs')

test('authenticates and parses a network service response', async (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gamepath-service-test-'))
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  const tokenFile = path.join(directory, 'token')
  fs.writeFileSync(tokenFile, 'test-token-that-is-long-enough-for-the-bridge')
  const server = net.createServer((socket) => {
    let source = ''
    socket.setEncoding('utf8')
    socket.on('data', (chunk) => {
      source += chunk
      if (!source.includes('\n')) return
      const request = JSON.parse(source)
      assert.equal(request.token, fs.readFileSync(tokenFile, 'utf8'))
      socket.end(
        `${JSON.stringify({ id: request.id, ok: true, result: { version: 'test', elevated: true, sessionStatus: 'idle' } })}\n`,
      )
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  context.after(() => server.close())
  const bridge = new ServiceBridge({ tokenFile, port: server.address().port })
  const status = await bridge.inspect()
  assert.equal(status.status, 'ready')
  assert.equal(status.elevated, true)
})

test('the session lease is renewed from the main process, well inside its window', () => {
  const main = fs.readFileSync(path.join(__dirname, 'main.cjs'), 'utf8')
  const service = fs.readFileSync(path.join(__dirname, '..', 'service', 'src', 'main.rs'), 'utf8')

  const pollMs = Number(main.match(/const SESSION_POLL_MS = (\d+)/)[1])
  const leaseSeconds = Number(service.match(/const SESSION_LEASE: Duration = Duration::from_secs\((\d+)\)/)[1])

  // The lease is what stops the service tearing down a live session. Renewing
  // it has to survive several consecutive failures, or a slow request during a
  // game drops the connection.
  assert.ok(
    pollMs * 5 <= leaseSeconds * 1000,
    `a ${pollMs}ms poll leaves too little headroom in a ${leaseSeconds}s lease`,
  )

  // It must be renewed by a main-process timer. Chromium throttles renderer
  // timers in an occluded window, which is what a fullscreen game makes this.
  assert.match(main, /sessionKeepAlive = setInterval\(pollSessionStatus, SESSION_POLL_MS\)/)
  assert.match(main, /startSessionKeepAlive\(\)/)
  assert.match(main, /backgroundThrottling: false/)
})

test('the declared MSRV matches the toolchain the relay is built with', () => {
  const script = fs.readFileSync(path.join(__dirname, '..', 'deploy', 'install-relay.sh'), 'utf8')
  const pinned = script.match(/RUST_TOOLCHAIN="(\d+)\.(\d+)\.(\d+)"/)
  assert.ok(pinned, 'install-relay.sh must pin a toolchain')
  const [, pinnedMajor, pinnedMinor] = pinned

  // The relay compiles from source on its own host with that pinned toolchain,
  // so no crate it pulls in may need anything newer. Cargo and clippy both read
  // rust-version, which is what stops a newer language feature or std API being
  // used here and only failing at deploy time.
  for (const crate of ['engine', 'relay', 'service']) {
    const manifest = fs.readFileSync(path.join(__dirname, '..', crate, 'Cargo.toml'), 'utf8')
    const declared = manifest.match(/rust-version = "(\d+)\.(\d+)"/)
    assert.ok(declared, `${crate}/Cargo.toml must declare rust-version`)
    assert.equal(
      `${declared[1]}.${declared[2]}`,
      `${pinnedMajor}.${pinnedMinor}`,
      `${crate} declares an MSRV that the relay's pinned toolchain cannot build`,
    )
  }
})

test('a server-level error reaches the caller instead of a bare mismatch', async (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gamepath-service-test-'))
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  const tokenFile = path.join(directory, 'token')
  fs.writeFileSync(tokenFile, 'test-token-that-is-long-enough-for-the-bridge')
  const server = net.createServer((socket) => {
    socket.on('data', () => {
      // id 0 is what the service sends when it could not attribute the request
      // at all. Its message is the only account of what went wrong.
      socket.end(`${JSON.stringify({ id: 0, ok: false, error: 'service is busy; retry' })}\n`)
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  context.after(() => server.close())
  const bridge = new ServiceBridge({ tokenFile, port: server.address().port })
  await assert.rejects(() => bridge.request('session-status'), /service is busy; retry/)
})
