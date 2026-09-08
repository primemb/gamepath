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
