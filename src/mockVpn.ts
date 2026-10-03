import type { AppState, VpnApi, VpnNode, VpnRule, VpnSession, VpnState } from './types'

/** Saved VPN nodes and targets, for exploring the screen in a browser. */
export function seedVpn(): VpnState {
  const nodes: VpnNode[] = [
    {
      id: 'vpn-demo',
      kind: 'wireguard',
      name: 'Frankfurt Home',
      endpoint: 'de-01.example:51820',
      address: '10.66.0.2/32',
      dns: '1.1.1.1',
      enabled: true,
      importedAt: new Date().toISOString(),
      hasPrivateKey: true,
    },
    {
      id: 'vpn-backup',
      kind: 'socks5',
      name: 'Amsterdam Proxy',
      endpoint: 'nl-01.example:1080',
      address: 'Proxy',
      dns: 'Proxy',
      enabled: false,
      importedAt: new Date().toISOString(),
      hasPrivateKey: false,
    },
  ]
  return {
    nodes,
    selectedNodeId: nodes[0].id,
    node: nodes[0],
    trafficMode: 'split',
    remoteDns: true,
    killSwitch: false,
    rules: [
      {
        id: 'vpn-rule-1',
        kind: 'application',
        value: 'C:\\Program Files\\Chat\\chat.exe',
        label: 'chat.exe',
        enabled: true,
      },
      { id: 'vpn-rule-2', kind: 'hostname', value: 'news.example.com', label: 'news.example.com', enabled: true },
    ],
    wantConnected: false,
    session: { status: 'idle' },
    conflicts: [],
    limitations: {},
    canSelectApps: true,
  }
}

const CONNECT_DELAY_MS = 900
const TICK_MS = 3000

/**
 * The VPN half of the mock API. It shares the mock's state so the game
 * session can pause it, exactly as the real one does.
 */
export function createMockVpn(get: () => AppState, snapshot: () => AppState): VpnApi {
  const listeners = new Set<(vpn: VpnState) => void>()
  let tick = 0
  let timer: number | undefined
  let connectTimer: number | undefined
  const vpn = () => get().vpn
  const emit = () => listeners.forEach((listener) => listener(structuredClone(vpn())))
  const setSession = (session: VpnSession) => {
    vpn().session = session
    emit()
  }

  const gameHoldsAllTraffic = () => get().session.status === 'connected' && get().trafficMode === 'all'

  const connected = (): VpnSession => ({
    status: 'connected',
    sessionId: 'vpn-3f9a1c',
    node: vpn().node ? { id: vpn().node!.id, name: vpn().node!.name, kind: vpn().node!.kind } : undefined,
    startedAt: Date.now(),
    trafficMode: vpn().trafficMode,
    killSwitch: vpn().killSwitch,
    message: `Connected through ${vpn().node?.name}.`,
    metrics: { latencyMs: 58, lossPercent: 0, bytesSent: 0, bytesReceived: 0, sampledAt: Date.now() },
    capture: {
      state: 'capturing',
      backend: 'windivert',
      trafficMode: vpn().trafficMode,
      diagnostics: {
        matchedSockets: 2,
        captureFilterCount: 2,
        capturedPackets: 0,
        capturedBytes: 0,
        relayedPackets: 0,
        bypassedPackets: 0,
        handledConnections: [
          {
            application: 'chat.exe',
            path: 'C:\\Program Files\\Chat\\chat.exe',
            destinationIp: '203.0.113.40',
            destinationPort: 443,
            protocol: 'TCP',
            startedAt: Math.floor(Date.now() / 1000) - 30,
          },
        ],
      },
    },
  })

  const animate = () => {
    window.clearInterval(timer)
    timer = window.setInterval(() => {
      const session = vpn().session
      if (gameHoldsAllTraffic() && session.status !== 'paused') {
        setSession({
          status: 'paused',
          pauseReason: 'game-all-traffic',
          message:
            'Your game session is carrying all traffic. The VPN resumes when it stops or switches to split mode.',
        })
        return
      }
      if (session.status === 'paused' && !gameHoldsAllTraffic()) {
        setSession(connected())
        return
      }
      if (session.status !== 'connected' || !session.metrics) return
      tick += 1
      session.metrics = {
        ...session.metrics,
        latencyMs: 56 + (tick % 6),
        bytesSent: session.metrics.bytesSent + 48_000 + (tick % 4) * 9000,
        bytesReceived: session.metrics.bytesReceived + 320_000 + (tick % 5) * 41_000,
        sampledAt: Date.now(),
      }
      emit()
    }, TICK_MS)
  }

  const mutate = async (change: (state: VpnState) => void) => {
    change(vpn())
    emit()
    return snapshot()
  }

  const syncSelection = (state: VpnState) => {
    state.nodes = state.nodes.map((node) => ({ ...node, enabled: node.id === state.selectedNodeId }))
    state.node = state.nodes.find((node) => node.enabled) ?? null
    state.canSelectApps = !(state.node?.kind === 'l2tp' && state.trafficMode === 'split')
    state.limitations = {}
    if (!state.canSelectApps) {
      for (const rule of state.rules) {
        if (
          rule.kind === 'application' ||
          rule.kind === 'folder' ||
          (rule.kind === 'hostname' && rule.value.startsWith('*.'))
        ) {
          state.limitations[rule.id] = 'This L2TP/IPsec node routes exact hostnames and IP ranges only.'
        }
      }
    }
  }

  const start = () => {
    window.clearTimeout(connectTimer)
    window.clearInterval(timer)
    setSession({ status: 'connecting', message: `Connecting to ${vpn().node?.name}…` })
    connectTimer = window.setTimeout(() => {
      if (!vpn().wantConnected) return
      setSession(
        gameHoldsAllTraffic()
          ? {
              status: 'paused',
              pauseReason: 'game-all-traffic',
              message:
                'Your game session is carrying all traffic. The VPN resumes when it stops or switches to split mode.',
            }
          : connected(),
      )
      animate()
    }, CONNECT_DELAY_MS)
  }

  const addNode = (node: VpnNode) =>
    mutate((state) => {
      state.nodes.push(node)
      state.selectedNodeId ??= node.id
      syncSelection(state)
    })

  return {
    importWireGuard: async () => ({ canceled: true }),
    chooseOpenVpn: async () => {
      throw new Error('Choosing files needs the desktop app: this window has no file picker.')
    },
    addOpenVpn: async () => snapshot(),
    addSocks5: async (input) =>
      addNode({
        id: crypto.randomUUID(),
        kind: 'socks5',
        name: input.label || input.address,
        endpoint: input.address,
        address: 'Proxy',
        dns: 'Proxy',
        enabled: true,
        importedAt: new Date().toISOString(),
        hasPrivateKey: false,
      }),
    addL2tp: async (input) =>
      addNode({
        id: crypto.randomUUID(),
        kind: 'l2tp',
        name: input.label || input.server,
        endpoint: input.server,
        address: 'Assigned by server',
        dns: 'Assigned by server',
        enabled: true,
        importedAt: new Date().toISOString(),
        hasPrivateKey: false,
      }),
    testL2tp: async () => ({
      reachable: true,
      server: vpn().node?.endpoint ?? 'vpn.example',
      assignedIpv4: '10.10.0.7',
      interfaceIndex: 31,
      setupLatencyMs: 2400,
      dataLatencyMs: 61,
    }),
    testSocks5: async () => ({ reachable: true, proxy: '203.0.113.20:1080', setupLatencyMs: 42, latencyMs: 96 }),
    selectNode: async (id) =>
      mutate((state) => {
        const node = state.nodes.find((item) => item.id === id)
        if (!node) throw new Error('That VPN node no longer exists.')
        if (state.selectedNodeId === id) return
        if (
          node.kind === 'l2tp' &&
          state.trafficMode === 'split' &&
          state.rules.some(
            (rule) =>
              rule.enabled &&
              (rule.kind === 'application' ||
                rule.kind === 'folder' ||
                (rule.kind === 'hostname' && rule.value.startsWith('*.'))),
          )
        ) {
          throw new Error(
            'This L2TP/IPsec node routes exact hostnames and IP ranges only. Use another node or all traffic.',
          )
        }
        state.selectedNodeId = id
        syncSelection(state)
        if (state.wantConnected) start()
      }),
    removeNode: async (id = vpn().selectedNodeId ?? undefined) =>
      mutate((state) => {
        if (!state.nodes.some((node) => node.id === id)) throw new Error('That VPN node no longer exists.')
        const selected = state.selectedNodeId === id
        state.nodes = state.nodes.filter((node) => node.id !== id)
        if (selected) {
          window.clearTimeout(connectTimer)
          window.clearInterval(timer)
          state.selectedNodeId = state.nodes[0]?.id ?? null
          state.wantConnected = false
          state.session = { status: 'idle' }
        }
        syncSelection(state)
      }),
    setTrafficMode: async (mode) =>
      mutate((state) => {
        state.trafficMode = mode
        syncSelection(state)
      }),
    setRemoteDns: async (enabled) => mutate((state) => void (state.remoteDns = enabled)),
    setKillSwitch: async (enabled) => mutate((state) => void (state.killSwitch = enabled)),
    browseTarget: async () => ({ canceled: true }),
    addRule: async (input) =>
      mutate((state) => {
        const rule: VpnRule = { id: `vpn-rule-${Date.now()}`, enabled: true, ...input }
        state.rules.push(rule)
      }),
    setRuleEnabled: async (id, enabled) =>
      mutate((state) => {
        const rule = state.rules.find((item) => item.id === id)
        if (rule) rule.enabled = enabled
      }),
    removeRule: async (id) => mutate((state) => void (state.rules = state.rules.filter((rule) => rule.id !== id))),
    connect: async () => {
      if (!vpn().node) throw new Error('Add a VPN node first.')
      vpn().wantConnected = true
      start()
      return snapshot()
    },
    disconnect: async () => {
      window.clearTimeout(connectTimer)
      window.clearInterval(timer)
      vpn().wantConnected = false
      setSession({ status: 'idle' })
      return snapshot()
    },
    status: async () => snapshot(),
    onChanged: (callback) => {
      listeners.add(callback)
      return () => listeners.delete(callback)
    },
  }
}
