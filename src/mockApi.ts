import type { AppState, GamePathApi } from './types'

let state: AppState = {
  clientVersion: '0.1.12',
  tunnels: [
    {
      id: 'demo-1',
      name: 'Istanbul Falcon',
      endpoint: 'tr-01.example:51820',
      address: '10.44.0.2/32',
      dns: '1.1.1.1',
      enabled: true,
      importedAt: new Date().toISOString(),
      hasPrivateKey: true,
    },
    {
      id: 'demo-2',
      name: 'Istanbul Nova',
      endpoint: 'tr-02.example:51820',
      address: '10.71.0.8/32',
      dns: 'System default',
      enabled: true,
      importedAt: new Date().toISOString(),
      hasPrivateKey: true,
    },
  ],
  rules: [
    {
      id: 'rule-1',
      kind: 'application',
      value: 'C:\\Games\\VALORANT\\VALORANT.exe',
      label: 'VALORANT.exe',
      enabled: true,
    },
    { id: 'rule-2', kind: 'hostname', value: '*.riotgames.com', label: 'Riot game services', enabled: true },
  ],
  trafficMode: 'split',
  relays: [
    {
      id: 'tr-istanbul-01',
      city: 'Istanbul',
      country: 'Turkey',
      code: 'TR',
      address: 'tr-relay.example',
      port: 51821,
      status: 'ready',
      hasEnrollmentToken: true,
      latency: 38,
    },
  ],
  activeRelayId: 'tr-istanbul-01',
  session: { status: 'idle' },
  engine: {
    status: 'ready',
    version: '0.1.0',
    message: 'Native engine ready',
    capabilities: {
      platform: 'windows',
      architecture: 'x86_64',
      wireGuardInstalled: true,
      activeWireGuardInterfaces: [],
      packetAdapterInstalled: false,
      packetAdapter: { libraryAvailable: true, libraryLoaded: true, message: 'Signed Wintun library is ready' },
      interception: {
        backend: 'windivert-2.2.2',
        libraryAvailable: true,
        libraryLoaded: true,
        driverAvailable: true,
        administratorRequired: true,
        message: 'Signed WFP capture runtime is ready',
      },
    },
  },
  service: { status: 'not-installed', version: '', message: 'Network service is not installed', elevated: false },
}

const snapshot = () => structuredClone(state)
let mockTelemetryTick = 0

export const mockApi: GamePathApi = {
  bootstrap: async () => snapshot(),
  importWireGuard: async () => ({ canceled: true }),
  setTunnelEnabled: async (id, enabled) => {
    state.tunnels = state.tunnels.map((item) => (item.id === id ? { ...item, enabled } : item))
    return snapshot()
  },
  removeTunnel: async (id) => {
    state.tunnels = state.tunnels.filter((item) => item.id !== id)
    return snapshot()
  },
  browseRuleTarget: async () => ({ canceled: true }),
  addRule: async (input) => {
    state.rules.push({ ...input, id: crypto.randomUUID(), enabled: true })
    return snapshot()
  },
  setRuleEnabled: async (id, enabled) => {
    state.rules = state.rules.map((item) => (item.id === id ? { ...item, enabled } : item))
    return snapshot()
  },
  removeRule: async (id) => {
    state.rules = state.rules.filter((item) => item.id !== id)
    return snapshot()
  },
  setTrafficMode: async (mode) => {
    state.trafficMode = mode
    return snapshot()
  },
  setRelay: async (id) => {
    state.activeRelayId = state.activeRelayId === id ? null : id
    return snapshot()
  },
  addRelay: async (input) => {
    const relay = {
      id: crypto.randomUUID(),
      city: input.city || 'Custom relay',
      country: input.country || 'Custom',
      code: 'VP',
      address: '',
      port: 51821,
      status: 'setup-required' as const,
      hasEnrollmentToken: false,
    }
    state.relays.push(relay)
    state.activeRelayId = relay.id
    return { state: snapshot(), relayId: relay.id }
  },
  removeRelayLocal: async (id) => {
    state.relays = state.relays.filter((relay) => relay.id !== id)
    if (state.activeRelayId === id) state.activeRelayId = null
    return snapshot()
  },
  configureRelay: async (id, input) => {
    state.relays = state.relays.map((relay) =>
      relay.id === id
        ? {
            ...relay,
            address: input.address,
            port: input.port,
            hasEnrollmentToken: relay.hasEnrollmentToken || Boolean(input.enrollmentToken),
            status: relay.hasEnrollmentToken || input.enrollmentToken ? 'ready' : 'setup-required',
          }
        : relay,
    )
    return snapshot()
  },
  importRelayEnrollment: async (id) => {
    state.relays = state.relays.map((relay) =>
      relay.id === id
        ? { ...relay, hasEnrollmentToken: true, status: relay.address ? 'ready' : 'setup-required' }
        : relay,
    )
    return { canceled: false, state: snapshot() }
  },
  testRelay: async (id) => {
    state.relays = state.relays.map((relay) => (relay.id === id ? { ...relay, latency: 31, status: 'ready' } : relay))
    return { state: snapshot(), result: { reachable: true, latencyMs: 31, virtualIpv4: '10.203.0.2' } }
  },
  provisionRelayVps: async (id, input) => {
    state.relays = state.relays.map((relay) =>
      relay.id === id
        ? {
            ...relay,
            address: input.host,
            port: input.relayPort,
            hasEnrollmentToken: true,
            status: 'ready',
            sshFingerprint: 'preview-fingerprint',
          }
        : relay,
    )
    state.activeRelayId = id
    return snapshot()
  },
  removeRelayVps: async (id) => {
    state.relays = state.relays.map((relay) =>
      relay.id === id ? { ...relay, hasEnrollmentToken: false, status: 'setup-required', latency: undefined } : relay,
    )
    if (state.activeRelayId === id) state.activeRelayId = null
    return snapshot()
  },
  onRelayVpsProgress: () => () => undefined,
  refreshService: async () => snapshot(),
  installService: async () => {
    state.service = { status: 'ready', version: '0.1.0', message: 'Privileged network service ready', elevated: true }
    return snapshot()
  },
  startSession: async () => {
    const relay = state.relays.find((item) => item.id === state.activeRelayId)
    state.session =
      relay?.status === 'ready'
        ? {
            status: 'connected',
            message: 'Two encrypted paths are connected to the relay.',
            routeLatencies: [34, 39],
            pathMetrics: [
              {
                route: 1,
                pathKind: 'wireguard',
                label: 'Istanbul Falcon',
                endpoint: 'tr-01.example:51820',
                reachable: true,
                latencyMs: 39,
                nodeLatencyMs: 22,
                packetsSent: 128,
                packetsReceived: 127,
                bytesSent: 148320,
                bytesReceived: 232410,
                probesSent: 12,
                probesReceived: 12,
                probesLost: 0,
                lastError: null,
              },
              {
                route: 2,
                pathKind: 'wireguard',
                label: 'Istanbul Nova',
                endpoint: 'tr-02.example:51820',
                reachable: true,
                latencyMs: 34,
                nodeLatencyMs: 19,
                packetsSent: 128,
                packetsReceived: 126,
                bytesSent: 148320,
                bytesReceived: 232410,
                probesSent: 12,
                probesReceived: 11,
                probesLost: 1,
                lastError: null,
              },
            ],
            capture: {
              state: 'active',
              backend: 'windivert',
              trafficMode: 'split',
              targetCount: 3,
              diagnostics: {
                matchedSockets: 3,
                captureFilterCount: 3,
                capturedPackets: 256,
                capturedBytes: 296640,
                relayedPackets: 256,
                bypassedPackets: 0,
                handledConnections: [
                  {
                    application: 'EscapeFromTarkov.exe',
                    destinationIp: '92.223.76.12',
                    destinationPort: 17001,
                    protocol: 'UDP',
                    startedAt: Math.floor(Date.now() / 1000) - 42,
                  },
                  {
                    application: 'EscapeFromTarkov.exe',
                    destinationIp: '92.223.76.18',
                    destinationPort: 17002,
                    protocol: 'UDP',
                    startedAt: Math.floor(Date.now() / 1000) - 25,
                  },
                  {
                    application: 'BEService.exe',
                    destinationIp: '51.195.60.87',
                    destinationPort: 443,
                    protocol: 'TCP',
                    startedAt: Math.floor(Date.now() / 1000) - 18,
                  },
                ],
              },
            },
            metrics: {
              userToNodeMs: 22,
              nodeToRelayMs: 17,
              relayToServerMs: 9,
              endToEndMs: 48,
              benchmarkServer: '1.1.1.1',
              bytesSent: 296640,
              bytesReceived: 464820,
              packetsSent: 256,
              packetsReceived: 253,
              packetLossPercent: 1.17,
            },
          }
        : { status: 'error', message: 'The Istanbul relay needs its server component and address.' }
    return snapshot()
  },
  stopSession: async () => {
    state.session = { status: 'idle' }
    return snapshot()
  },
  refreshSession: async () => {
    if (state.session.status === 'connected' && state.session.pathMetrics) {
      mockTelemetryTick += 1
      state.session.pathMetrics = state.session.pathMetrics.map((path, index) => ({
        ...path,
        latencyMs: 34 + index * 5 + ((mockTelemetryTick + index * 2) % 5),
        packetsSent: path.packetsSent + 24 + index * 3,
        packetsReceived: path.packetsReceived + 23 + index * 3,
        bytesSent: path.bytesSent + 18400 + index * 2100,
        bytesReceived: path.bytesReceived + 42600 + index * 3700,
        probesSent: (path.probesSent ?? 0) + 1,
        probesReceived: (path.probesReceived ?? 0) + 1,
      }))
    }
    return snapshot()
  },
}
