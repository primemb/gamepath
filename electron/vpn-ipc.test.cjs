const assert = require('node:assert/strict')
const test = require('node:test')
const { createVpnFeature } = require('./vpn-ipc.cjs')
const { defaultVpn } = require('./vpn-state.cjs')

function harness({ service: script = {}, game = { status: 'idle' }, gameMode = 'split', saved = {} } = {}) {
  const handlers = new Map()
  const state = {
    session: game,
    trafficMode: gameMode,
    rules: [{ id: 'g', kind: 'application', value: 'C:\\Games\\game.exe', enabled: true, groupId: null }],
    ruleGroups: [],
    vpn: defaultVpn(),
    ...saved,
  }
  const calls = []
  const service = {
    ready: () => true,
    request: async (command, payload) => {
      calls.push({ command, payload })
      const answer = script[command]
      if (answer instanceof Error) throw answer
      return answer ?? { paths: { paths: [] }, capture: {} }
    },
  }
  const quiet = { info() {}, warn() {}, error() {}, debug() {} }
  let saves = 0
  const feature = createVpnFeature({
    ipcMain: { handle: (channel, handler) => handlers.set(channel, handler) },
    dialog: {},
    getState: () => state,
    saveState: () => (saves += 1),
    publicState: () => ({ vpn: feature.publicVpn() }),
    encrypt: (secret) => `sealed:${secret}`,
    decrypt: (stored) => stored.replace(/^sealed:/, ''),
    service,
    engine: {
      ready: () => true,
      request: async (command, payload) => {
        calls.push({ command, payload })
        return { reachable: true, proxy: `${payload.host}:${payload.port}`, setupLatencyMs: 12, latencyMs: 40 }
      },
    },
    logger: { ...quiet, scope: () => quiet },
    usage: null,
    onChange: () => {},
  })
  feature.register()
  // Electron turns a handler that throws into a rejected invoke, so this does too.
  const invoke = async (channel, ...args) => handlers.get(channel)({}, ...args)
  return { feature, state, calls, invoke, saves: () => saves }
}

const socks5 = { address: 'proxy.example:1080', label: 'Proxy' }
const l2tp = { server: 'office.example', preSharedKey: 'psk', username: 'me', password: 'pw' }

test('a node is stored sealed and never appears in what the window sees', async () => {
  const { state, invoke } = harness()
  const result = await invoke('vpn:add-socks5', { ...socks5, username: 'user', password: 'secret' })
  assert.equal(result.vpn.node.kind, 'socks5')
  assert.match(state.encryptedVpnConfigs[result.vpn.node.id], /^sealed:/)
  assert.doesNotMatch(JSON.stringify(result), /secret/)
})

test('connecting sends the node, rules and settings to the vpn slot', async () => {
  const { state, invoke, calls } = harness()
  await invoke('vpn:add-socks5', socks5)
  await invoke('vpn:add-rule', { kind: 'application', value: 'C:\\Apps\\chat.exe' })
  await invoke('vpn:set-kill-switch', true)
  const result = await invoke('vpn:connect')
  const start = calls.find((call) => call.command === 'start-session').payload
  assert.equal(start.slot, 'vpn')
  assert.equal(start.mode, 'direct')
  assert.equal(start.killSwitch, true)
  assert.deepEqual(start.rules, [{ kind: 'application', value: 'C:\\Apps\\chat.exe' }])
  assert.equal(start.nodes[0].kind, 'socks5')
  // Its own proxy's name is never answered through the tunnel it carries.
  assert.ok(start.ownHostnames.includes('proxy.example'))
  assert.equal(state.vpn.wantConnected, true)
  assert.equal(result.vpn.session.status, 'connected')
})

test('a split VPN with nothing selected says what to do instead of connecting', async () => {
  const { invoke, calls, state } = harness()
  await invoke('vpn:add-socks5', socks5)
  const result = await invoke('vpn:connect')
  assert.equal(result.vpn.session.status, 'error')
  assert.match(result.vpn.session.message, /Add at least one app or website/)
  assert.equal(calls.length, 0)
  // Retrying at the next launch would only fail the same way.
  assert.equal(state.vpn.wantConnected, false)
})

test('an L2TP split VPN refuses an application rule when it is added', async () => {
  const { invoke } = harness()
  await invoke('vpn:add-l2tp', l2tp)
  await assert.rejects(
    invoke('vpn:add-rule', { kind: 'application', value: 'C:\\a.exe' }),
    /cannot select applications/,
  )
  const result = await invoke('vpn:add-rule', { kind: 'hostname', value: 'intranet.example' })
  assert.equal(result.vpn.rules.length, 1)
  assert.equal(result.vpn.canSelectApps, false)
})

test('a rule the running session rejects is not kept', async () => {
  const { invoke, state } = harness({ service: { 'update-session-rules': new Error('invalid target') } })
  await invoke('vpn:add-socks5', socks5)
  await invoke('vpn:add-rule', { kind: 'hostname', value: 'news.example' })
  await invoke('vpn:connect')
  await assert.rejects(invoke('vpn:add-rule', { kind: 'hostname', value: 'bad.example' }), /invalid target/)
  assert.deepEqual(
    state.vpn.rules.map((rule) => rule.value),
    ['news.example'],
  )
})

test('a VPN rule the game also selects is flagged for the window', async () => {
  const { invoke } = harness()
  await invoke('vpn:add-socks5', socks5)
  const result = await invoke('vpn:add-rule', { kind: 'application', value: 'c:\\games\\GAME.exe' })
  assert.deepEqual(result.vpn.conflicts, [result.vpn.rules[0].id])
})

test('the game about to take all traffic pauses the VPN before it starts', async () => {
  const { feature, state, invoke } = harness()
  await invoke('vpn:add-socks5', socks5)
  await invoke('vpn:add-rule', { kind: 'hostname', value: 'news.example' })
  await invoke('vpn:connect')
  state.trafficMode = 'all'
  await feature.beforeGameStart()
  assert.equal(feature.publicVpn().session.status, 'paused')
  // The game failed to start: the VPN comes straight back.
  state.session = { status: 'error' }
  await feature.gameChanged()
  assert.equal(feature.publicVpn().session.status, 'connected')
})

test('a running split game is judged by its own mode, not a setting saved since', async () => {
  const { feature, invoke } = harness({
    game: { status: 'connected', capture: { trafficMode: 'split' } },
    gameMode: 'all',
  })
  await invoke('vpn:add-socks5', socks5)
  await invoke('vpn:add-rule', { kind: 'hostname', value: 'news.example' })
  await invoke('vpn:connect')
  await feature.gameChanged()
  assert.equal(feature.publicVpn().session.status, 'connected')
})

test('removing the node turns the VPN off and forgets its secret', async () => {
  const { state, invoke } = harness()
  await invoke('vpn:add-socks5', socks5)
  await invoke('vpn:add-rule', { kind: 'hostname', value: 'news.example' })
  await invoke('vpn:connect')
  await invoke('vpn:remove-node')
  assert.deepEqual(state.vpn.nodes, [])
  assert.equal(state.vpn.selectedNodeId, null)
  assert.deepEqual(state.encryptedVpnConfigs, {})
  assert.equal(state.vpn.wantConnected, false)
})

test('adding and removing an unused node keeps the running VPN untouched', async () => {
  const { feature, invoke, calls, state } = harness()
  const first = (await invoke('vpn:add-socks5', socks5)).vpn.node
  await invoke('vpn:add-rule', { kind: 'hostname', value: 'news.example' })
  await invoke('vpn:connect')
  const sessionId = feature.publicVpn().session.sessionId
  const before = calls.length
  const added = await invoke('vpn:add-socks5', {
    address: 'second.example:1081',
    username: 'other',
    password: 'second-secret',
  })
  const other = added.vpn.nodes.find((node) => node.id !== first.id)
  assert.equal(added.vpn.nodes.length, 2)
  assert.equal(added.vpn.node.id, first.id)
  assert.equal(added.vpn.session.sessionId, sessionId)
  assert.equal(calls.length, before)
  assert.doesNotMatch(JSON.stringify(added), /second-secret/)
  await invoke('vpn:test-socks5', undefined, other.id)
  assert.equal(calls.at(-1).payload.host, 'second.example')
  assert.equal(calls.at(-1).payload.username, 'other')
  const afterTest = calls.length
  const removed = await invoke('vpn:remove-node', other.id)
  assert.equal(removed.vpn.node.id, first.id)
  assert.equal(removed.vpn.session.sessionId, sessionId)
  assert.equal(calls.length, afterTest)
  assert.equal(state.encryptedVpnConfigs[other.id], undefined)
  assert.ok(state.encryptedVpnConfigs[first.id])
})

test('switching saved nodes stops the old path before starting only the selected path', async () => {
  const { invoke, calls, feature } = harness()
  const first = (await invoke('vpn:add-socks5', socks5)).vpn.node
  const second = (
    await invoke('vpn:add-socks5', { address: 'second.example:1081', username: 'second', password: 'pw' })
  ).vpn.nodes.find((node) => node.id !== first.id)
  await invoke('vpn:add-rule', { kind: 'hostname', value: 'news.example' })
  await invoke('vpn:connect')
  const before = calls.length
  const selected = await invoke('vpn:select-node', second.id)
  assert.deepEqual(
    calls.slice(before).map((call) => call.command),
    ['stop-session', 'validate-runtime', 'start-session'],
  )
  const start = calls.at(-1).payload
  assert.equal(start.slot, 'vpn')
  assert.equal(start.nodes.length, 1)
  assert.equal(start.nodes[0].host, 'second.example')
  assert.equal(start.nodes[0].username, 'second')
  assert.equal(selected.vpn.session.node.id, second.id)
  assert.equal(selected.vpn.session.status, 'connected')
  assert.equal(selected.vpn.nodes.filter((node) => node.enabled).length, 1)
  const after = calls.length
  await invoke('vpn:select-node', second.id)
  assert.equal(calls.length, after)
  await invoke('vpn:disconnect')
  const off = calls.length
  await invoke('vpn:select-node', first.id)
  assert.equal(calls.length, off)
  assert.equal(feature.publicVpn().session.status, 'idle')
})

test('an incompatible selection does not disturb the current node or connection', async () => {
  const { invoke, calls } = harness()
  const first = (await invoke('vpn:add-socks5', socks5)).vpn.node
  const saved = await invoke('vpn:add-l2tp', l2tp)
  const second = saved.vpn.nodes.find((node) => node.id !== first.id)
  await invoke('vpn:add-rule', { kind: 'application', value: 'C:\\Apps\\chat.exe' })
  const connected = await invoke('vpn:connect')
  const before = calls.length
  await assert.rejects(invoke('vpn:select-node', second.id), /cannot select applications/)
  await assert.rejects(invoke('vpn:select-node', 'missing'), /no longer exists/)
  const current = await invoke('vpn:status')
  assert.equal(current.vpn.node.id, first.id)
  assert.equal(current.vpn.session.sessionId, connected.vpn.session.sessionId)
  assert.equal(calls.length, before)
})

test('removing the selected node stops the VPN and keeps the remaining node and secret', async () => {
  const { state, invoke, calls } = harness()
  const first = (await invoke('vpn:add-socks5', socks5)).vpn.node
  const second = (await invoke('vpn:add-socks5', { address: 'second.example:1081' })).vpn.nodes.find(
    (node) => node.id !== first.id,
  )
  await invoke('vpn:add-rule', { kind: 'hostname', value: 'news.example' })
  await invoke('vpn:connect')
  const before = calls.length
  const removed = await invoke('vpn:remove-node', first.id)
  assert.equal(calls.length, before + 1)
  assert.equal(calls.at(-1).command, 'stop-session')
  assert.equal(removed.vpn.node.id, second.id)
  assert.equal(removed.vpn.session.status, 'idle')
  assert.equal(removed.vpn.wantConnected, false)
  assert.equal(state.encryptedVpnConfigs[first.id], undefined)
  assert.ok(state.encryptedVpnConfigs[second.id])
})

test('a SOCKS5 proxy is tested through the engine, not the relay', async () => {
  const { invoke, calls } = harness()
  const fresh = await invoke('vpn:test-socks5', { address: 'proxy.example:1080', username: 'u', password: 'p' })
  assert.equal(fresh.reachable, true)
  assert.deepEqual(calls.at(-1), {
    command: 'probe-socks5-proxy',
    payload: { host: 'proxy.example', port: 1080, username: 'u', password: 'p' },
  })
  // A saved node is tested with its stored login.
  await invoke('vpn:add-socks5', { address: 'saved.example:1080', username: 'saved', password: 'secret' })
  await invoke('vpn:test-socks5')
  assert.equal(calls.at(-1).payload.username, 'saved')
})

test('a restored legacy VPN reconnects with its original encrypted configuration', async () => {
  const saved = {
    vpn: {
      node: { id: 'legacy', name: 'Legacy proxy', kind: 'socks5', host: 'legacy.example', port: 1080 },
      rules: [{ id: 'target', kind: 'hostname', value: 'news.example', enabled: true }],
      wantConnected: true,
    },
    encryptedVpnConfig: 'sealed:{"username":"original","password":"secret"}',
  }
  const { feature, calls } = harness({ saved })
  await feature.resume()
  assert.equal(feature.publicVpn().selectedNodeId, 'legacy')
  assert.equal(feature.publicVpn().session.status, 'connected')
  assert.equal(calls.at(-1).payload.nodes[0].host, 'legacy.example')
  assert.equal(calls.at(-1).payload.nodes[0].username, 'original')
  assert.doesNotMatch(JSON.stringify(feature.publicVpn()), /secret/)
})

test('rapid selections are serialized and each start carries exactly one node', async () => {
  const { invoke, calls } = harness()
  const first = (await invoke('vpn:add-socks5', socks5)).vpn.node
  const second = (await invoke('vpn:add-socks5', { address: 'second.example:1081' })).vpn.nodes.find(
    (node) => node.id !== first.id,
  )
  await invoke('vpn:add-rule', { kind: 'hostname', value: 'news.example' })
  await invoke('vpn:connect')
  await Promise.all([invoke('vpn:select-node', second.id), invoke('vpn:select-node', first.id)])
  const starts = calls.filter((call) => call.command === 'start-session')
  assert.deepEqual(
    starts.map((call) => call.payload.nodes.map((node) => node.host)),
    [['proxy.example'], ['second.example'], ['proxy.example']],
  )
  const result = await invoke('vpn:status')
  assert.equal(result.vpn.node.id, first.id)
  assert.equal(result.vpn.session.node.id, first.id)
})

test('switching while paused keeps the VPN out of the games way and resumes the new node', async () => {
  const { invoke, calls, state, feature } = harness({ game: { status: 'connected' }, gameMode: 'all' })
  const first = (await invoke('vpn:add-socks5', socks5)).vpn.node
  const second = (await invoke('vpn:add-socks5', { address: 'second.example:1081' })).vpn.nodes.find(
    (node) => node.id !== first.id,
  )
  await invoke('vpn:add-rule', { kind: 'hostname', value: 'news.example' })
  await invoke('vpn:connect')
  const result = await invoke('vpn:select-node', second.id)
  assert.equal(result.vpn.session.status, 'paused')
  assert.equal(result.vpn.wantConnected, true)
  assert.equal(calls.length, 0)
  state.session = { status: 'idle' }
  await feature.gameChanged()
  assert.equal(calls.at(-1).payload.nodes[0].host, 'second.example')
  assert.ok(calls.every((call) => call.payload.slot === 'vpn'))
})
