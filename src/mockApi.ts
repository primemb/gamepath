import type { AppState, GamePathApi } from './types'

let state: AppState = {
  tunnels: [
    { id: 'demo-1', name: 'Istanbul Falcon', endpoint: 'tr-01.example:51820', address: '10.44.0.2/32', dns: '1.1.1.1', enabled: true, importedAt: new Date().toISOString(), hasPrivateKey: true },
    { id: 'demo-2', name: 'Istanbul Nova', endpoint: 'tr-02.example:51820', address: '10.71.0.8/32', dns: 'System default', enabled: true, importedAt: new Date().toISOString(), hasPrivateKey: true },
  ],
  rules: [
    { id: 'rule-1', kind: 'application', value: 'C:\\Games\\VALORANT\\VALORANT.exe', label: 'VALORANT.exe', enabled: true },
    { id: 'rule-2', kind: 'hostname', value: '*.riotgames.com', label: 'Riot game services', enabled: true },
  ],
  trafficMode: 'split',
  relays: [{ id: 'tr-istanbul-01', city: 'Istanbul', country: 'Turkey', code: 'TR', address: '', port: 51821, status: 'setup-required', hasEnrollmentToken: false, latency: 38 }],
  activeRelayId: 'tr-istanbul-01',
  session: { status: 'idle' },
  engine: { status: 'ready', version: '0.1.0', message: 'Native engine ready', capabilities: { platform: 'windows', architecture: 'x86_64', wireGuardInstalled: true, activeWireGuardInterfaces: [], packetAdapterInstalled: false, packetAdapter: { libraryAvailable: true, libraryLoaded: true, message: 'Signed Wintun library is ready' }, interception: { backend: 'windivert-2.2.2', libraryAvailable: true, libraryLoaded: true, driverAvailable: true, administratorRequired: true, message: 'Signed WFP capture runtime is ready' } } },
  service: { status: 'not-installed', version: '', message: 'Network service is not installed', elevated: false },
}

const snapshot = () => structuredClone(state)

export const mockApi: GamePathApi = {
  bootstrap: async () => snapshot(),
  importWireGuard: async () => ({ canceled: true }),
  setTunnelEnabled: async (id, enabled) => {
    state.tunnels = state.tunnels.map((item) => item.id === id ? { ...item, enabled } : item)
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
    state.rules = state.rules.map((item) => item.id === id ? { ...item, enabled } : item)
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
    state.activeRelayId = id
    return snapshot()
  },
  configureRelay: async (id, input) => {
    state.relays = state.relays.map((relay) => relay.id === id ? { ...relay, address: input.address, port: input.port, hasEnrollmentToken: relay.hasEnrollmentToken || Boolean(input.enrollmentToken), status: relay.hasEnrollmentToken || input.enrollmentToken ? 'ready' : 'setup-required' } : relay)
    return snapshot()
  },
  importRelayEnrollment: async (id) => {
    state.relays = state.relays.map((relay) => relay.id === id ? { ...relay, hasEnrollmentToken: true, status: relay.address ? 'ready' : 'setup-required' } : relay)
    return { canceled: false, state: snapshot() }
  },
  testRelay: async (id) => {
    state.relays = state.relays.map((relay) => relay.id === id ? { ...relay, latency: 31, status: 'ready' } : relay)
    return { state: snapshot(), result: { reachable: true, latencyMs: 31, virtualIpv4: '10.203.0.2' } }
  },
  refreshService: async () => snapshot(),
  installService: async () => ({ launched: true }),
  startSession: async () => {
    const relay = state.relays.find((item) => item.id === state.activeRelayId)
    state.session = relay?.status === 'ready'
      ? { status: 'prepared', message: 'Session plan is ready for the packet adapter.' }
      : { status: 'error', message: 'The Istanbul relay needs its server component and address.' }
    return snapshot()
  },
}
