const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs/promises')
const os = require('node:os')
const path = require('node:path')
const { encodeInvite, decodeInvite } = require('./relay-invite.cjs')
const { registerRelaySharing } = require('./relay-sharing.cjs')
const { existingEnrollmentScript } = require('./vps.cjs')
const { withoutSecrets } = require('./public-state.cjs')

const token = (id) =>
  'gpe1_' +
  Buffer.from(
    JSON.stringify({
      version: 1,
      clientId: Buffer.alloc(16, id).toString('base64url'),
      preSharedKey: Buffer.alloc(32, id).toString('base64url'),
      virtualIpv4: `10.203.0.${id}`,
    }),
  ).toString('base64url')
const payload = (credential = token(3)) => ({
  version: 1,
  city: 'Frankfurt',
  country: 'Germany',
  address: '203.0.113.10',
  port: 51821,
  recipientName: 'Ali',
  enrollmentToken: credential,
})
const event = (id = 1) => ({ sender: { id, send() {} } })

function harness(overrides = {}) {
  const state = {
    relays: [
      {
        id: 'owner',
        city: 'Frankfurt',
        country: 'Germany',
        address: '203.0.113.10',
        port: 51821,
        sshFingerprint: 'pinned',
      },
    ],
    activeRelayId: 'owner',
    encryptedRelayTokens: { owner: 'owner-secret' },
    session: { status: 'connected', relayId: 'owner' },
    connectionMode: 'relay',
  }
  const handlers = new Map()
  const calls = []
  let clipboardText = ''
  registerRelaySharing({
    ipcMain: { handle: (name, handler) => handlers.set(name, handler) },
    getState: () => state,
    publicState: () => structuredClone(withoutSecrets(state)),
    saveState() {},
    encryptConfig: (text) => `encrypted:${text}`,
    clipboard: {
      writeText: async (text) => {
        clipboardText = text
      },
      readText: async () => clipboardText,
    },
    dialog: {},
    vpsSetupInput: (id, input) => ({
      relay: state.relays.find((r) => r.id === id),
      ...input,
      expectedFingerprint: 'pinned',
    }),
    enrollExistingRelay: async (input) => {
      calls.push(input)
      return { token: token(3 + calls.length), port: 40000, fingerprint: 'pinned' }
    },
    ...overrides,
  })
  return {
    state,
    calls,
    invoke: (name, ...args) => handlers.get(`relay:${name}`)(...args),
    setClipboard: (text) => {
      clipboardText = text
    },
    getClipboard: () => clipboardText,
  }
}

test('an invitation carries endpoint, recipient, and unique credential together', () => {
  const input = { ...payload(), recipientName: 'علی' }
  assert.deepEqual(decodeInvite(`\n${encodeInvite(input)}\n`), input)
})

test('malformed, oversized, IPv6, and unsupported invitations fail without echoing credentials', () => {
  const invalid = [
    '',
    'https://example.com',
    encodeInvite(payload()) + '?tracking=yes',
    'gamepath://relay/' + 'a'.repeat(17000),
  ]
  for (const change of [
    { version: 2 },
    { port: 0 },
    { port: 65536 },
    { address: '::1' },
    { address: 'host/path' },
    { enrollmentToken: 'gpe1_secret' },
    { city: '\nsecret' },
  ]) {
    invalid.push('gamepath://relay/' + Buffer.from(JSON.stringify({ ...payload(), ...change })).toString('base64url'))
  }
  for (const input of invalid)
    assert.throws(() => decodeInvite(input), { message: 'This is not a valid GamePath relay invitation' })
})

test('each share enrolls a fresh client and never replaces the owner credential or session', async () => {
  const h = harness()
  const before = structuredClone(h.state)
  const input = { host: '203.0.113.10', recipientName: 'Ali', password: 'ssh-secret' }
  const first = await h.invoke('share-create', event(), 'owner', input)
  await h.invoke('share-copy', event(), first.shareId)
  const a = decodeInvite(h.getClipboard())
  const second = await h.invoke('share-create', event(), 'owner', input)
  await h.invoke('share-copy', event(), second.shareId)
  const b = decodeInvite(h.getClipboard())
  assert.notEqual(h.calls[0].clientName, h.calls[1].clientName)
  assert.notEqual(a.enrollmentToken, b.enrollmentToken)
  assert.equal(a.port, 40000)
  assert.equal(h.calls[0].expectedFingerprint, 'pinned')
  assert.deepEqual(h.state, before)
  assert.ok(!JSON.stringify(first).includes('gpe1_'))
  assert.ok(!JSON.stringify(first).includes('ssh-secret'))
})

test('preview reveals metadata only; accept encrypts the token and preserves current routing', async () => {
  const h = harness()
  h.setClipboard(encodeInvite(payload()))
  const preview = await h.invoke('invite-preview', event(), 'clipboard')
  assert.ok(!JSON.stringify(preview).includes('gpe1_'))
  assert.equal(h.state.relays.length, 1)
  const result = await h.invoke('invite-accept', event(), preview.invitationId)
  assert.equal(h.state.relays.length, 2)
  const imported = h.state.relays[1]
  assert.equal(h.state.encryptedRelayTokens[imported.id], `encrypted:${token(3)}`)
  assert.equal(result.activeRelayId, 'owner')
  assert.deepEqual(result.session, { status: 'connected', relayId: 'owner' })
  assert.ok(!JSON.stringify(result).includes('gpe1_'))
  assert.throws(() => h.invoke('invite-accept', event(), preview.invitationId), /expired/)
})

test('bad imports do not mutate saved state; invitations are bound to the requesting window', async () => {
  const h = harness()
  const before = structuredClone(h.state)
  h.setClipboard('gamepath://relay/invalid')
  await assert.rejects(h.invoke('invite-preview', event(), 'clipboard'), /not a valid/)
  assert.deepEqual(h.state, before)
  h.setClipboard(encodeInvite(payload()))
  const preview = await h.invoke('invite-preview', event(), 'clipboard')
  assert.throws(() => h.invoke('invite-accept', event(2), preview.invitationId), /expired/)
  assert.deepEqual(h.state, before)
})

test('saving and importing a file round trips; cancelling export can be retried without enrollment', async () => {
  const folder = await fs.mkdtemp(path.join(os.tmpdir(), 'gamepath-invite-'))
  const target = path.join(folder, 'friend.gprelay')
  try {
    let canceled = true
    const h = harness({
      dialog: {
        showSaveDialog: async () => ({ canceled, filePath: target }),
        showOpenDialog: async () => ({ canceled: false, filePaths: [target] }),
      },
    })
    const share = await h.invoke('share-create', event(), 'owner', { host: '203.0.113.10', recipientName: 'Friend' })
    assert.deepEqual(await h.invoke('share-save', event(), share.shareId), { canceled: true })
    canceled = false
    await h.invoke('share-save', event(), share.shareId)
    const preview = await h.invoke('invite-preview', event(), 'file')
    assert.equal(preview.details.recipientName, 'Friend')
    assert.equal(h.calls.length, 1)
    assert.ok(!JSON.stringify(preview).includes('gpe1_'))
  } finally {
    await fs.rm(folder, { recursive: true, force: true })
  }
})

test('enrollment names are shell safe and serialized on the VPS to avoid overwrites and duplicate IPs', () => {
  assert.throws(() => existingEnrollmentScript('friend; cat /etc/shadow'), /Invalid/)
  const script = existingEnrollmentScript('friend-abcdef')
  assert.ok(script.includes("--name 'friend-abcdef'"))
  const enrollment = '"/proc/$pid/exe" enroll'
  assert.ok(script.includes(enrollment))
  assert.ok(script.indexOf('flock -x 9') < script.indexOf(enrollment))
  assert.ok(!script.includes('systemctl restart'))
  assert.ok(script.indexOf('live-client-reload-v1') < script.indexOf(enrollment))
})
