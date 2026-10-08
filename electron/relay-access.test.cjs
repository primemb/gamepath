const test = require('node:test')
const assert = require('node:assert/strict')
const { EventEmitter } = require('node:events')
const { registerRelayAccess } = require('./relay-access.cjs')
const { parseClientAccess, accessCommandScript } = require('./relay-access-ssh.cjs')
const { existingEnrollmentScript } = require('./vps.cjs')

const ownId = Buffer.alloc(16, 2).toString('base64url')
const friendId = Buffer.alloc(16, 3).toString('base64url')
const initialClients = [
  { clientId: ownId, name: 'Owner', virtualIpv4: '10.203.0.2' },
  { clientId: friendId, name: 'Ali', virtualIpv4: '10.203.0.3' },
]
function harness(overrides = {}) {
  const handlers = new Map()
  const sender = new EventEmitter()
  sender.id = 1
  sender.isDestroyed = () => false
  const state = {
    relays: [{ id: 'relay', address: 'relay.example.com', sshFingerprint: 'pinned' }],
    activeRelayId: 'relay',
    session: { status: 'connected' },
  }
  let clients = structuredClone(initialClients)
  let closes = 0
  let expires
  let received
  const remote = {
    fingerprint: 'pinned',
    list: async () => structuredClone(clients),
    revoke: async (id) => {
      clients = clients.filter((client) => client.clientId !== id)
      return structuredClone(clients)
    },
    close: () => {
      closes += 1
    },
  }
  registerRelayAccess({
    ipcMain: { handle: (name, handler) => handlers.set(name, handler) },
    vpsSetupInput: (_id, input) => ({ relay: state.relays[0], ...input, expectedFingerprint: 'pinned' }),
    connectRelayAccess: async (input) => {
      received = input
      return remote
    },
    currentClientId: () => ownId,
    getState: () => state,
    publicState: () => structuredClone(state),
    saveState() {},
    setTimer: (callback, delay) => {
      assert.equal(delay, 15 * 60_000)
      expires = callback
      return { unref() {} }
    },
    clearTimer() {},
    ...overrides,
  })
  return {
    remote,
    sender,
    state,
    invoke: (name, ...args) => handlers.get(`relay:access-${name}`)({ sender }, ...args),
    foreign: (name, ...args) => handlers.get(`relay:access-${name}`)({ sender: { id: 2 } }, ...args),
    expire: () => expires(),
    closes: () => closes,
    received: () => received,
  }
}
const credentials = {
  host: 'relay.example.com',
  username: 'root',
  password: 'ssh-secret',
  relayPort: 51821,
  sshPort: 22,
}

test('SSH is required and pins the host; access list contains only public metadata', async () => {
  const h = harness()
  const result = await h.invoke('open', 'relay', credentials)
  assert.equal(h.received().password, 'ssh-secret')
  assert.equal(h.received().expectedFingerprint, 'pinned')
  assert.ok(!JSON.stringify(result).includes('ssh-secret'))
  assert.equal(result.clients[0].isCurrentClient, true)
  await h.invoke('close', result.accessId)
  assert.equal(h.closes(), 1)
})

test('revoke targets exactly one client, preserves routing, and protects this PC', async () => {
  const h = harness()
  const before = structuredClone(h.state)
  const result = await h.invoke('open', 'relay', credentials)
  await assert.rejects(h.invoke('revoke', result.accessId, ownId), /cannot revoke this PC/)
  const remaining = await h.invoke('revoke', result.accessId, friendId)
  assert.deepEqual(
    remaining.map((client) => client.clientId),
    [ownId],
  )
  assert.deepEqual(h.state, before)
  await h.invoke('close', result.accessId)
})

test('access handles cannot be used from another window or after expiry', async () => {
  const h = harness()
  await assert.rejects(h.invoke('revoke', 'missing', friendId), /Sign in/)
  const result = await h.invoke('open', 'relay', credentials)
  await assert.rejects(h.foreign('revoke', result.accessId, friendId), /Sign in/)
  h.expire()
  assert.equal(h.closes(), 1)
  assert.equal(h.sender.listenerCount('destroyed'), 0)
  await assert.rejects(h.invoke('list', result.accessId), /Sign in/)
})

test('a closed window or failed listing closes its SSH connection', async () => {
  const h = harness()
  await h.invoke('open', 'relay', credentials)
  h.sender.emit('destroyed')
  assert.equal(h.closes(), 1)
  const failed = harness()
  failed.remote.list = async () => {
    throw new Error('sudo denied')
  }
  await assert.rejects(failed.invoke('open', 'relay', credentials), /sudo denied/)
  assert.equal(failed.closes(), 1)
})

test('parallel administrative mutations are refused while a revoke is pending', async () => {
  const h = harness()
  const result = await h.invoke('open', 'relay', credentials)
  let finish
  h.remote.revoke = () =>
    new Promise((resolve) => {
      finish = resolve
    })
  const pending = h.invoke('revoke', result.accessId, friendId)
  await assert.rejects(h.invoke('revoke', result.accessId, friendId), /still running/)
  finish([initialClients[0]])
  await pending
  await h.invoke('close', result.accessId)
})

test('parser strips unexpected secret fields and errors never echo raw responses', () => {
  assert.deepEqual(
    parseClientAccess(
      JSON.stringify(
        initialClients.map((client) => ({ ...client, preSharedKey: 'private-key', enrollmentToken: 'private-token' })),
      ),
    ),
    initialClients,
  )
  for (const raw of [
    'private-secret',
    JSON.stringify({ preSharedKey: 'private-secret' }),
    JSON.stringify([...initialClients, initialClients[0]]),
  ]) {
    assert.throws(() => parseClientAccess(raw), { message: 'The VPS returned an invalid client access list' })
  }
})

test('admin commands serialize with enrollment, check capabilities, and never restart or accept paths', () => {
  assert.throws(() => accessCommandScript('../../owner.json'), /Invalid/)
  const script = accessCommandScript(friendId)
  assert.ok(script.includes(`revoke --client-id '${friendId}'`))
  assert.ok(script.indexOf('flock -x 9') < script.indexOf('revoke --client-id'))
  assert.ok(script.indexOf('client-access-management-v1') < script.indexOf('revoke --client-id'))
  assert.ok(!script.includes('systemctl restart'))
  const labeled = existingEnrollmentScript('friend-123', "Ali's PC")
  assert.ok(labeled.includes('--label'))
  assert.throws(() => existingEnrollmentScript('friend-123', 'bad\nname'), /Invalid/)
})
