export type Tunnel = {
  id: string
  name: string
  endpoint: string
  address: string
  dns: string
  enabled: boolean
  importedAt: string
  hasPrivateKey: boolean
}

export type RuleKind = 'application' | 'folder' | 'hostname' | 'ip'

export type SplitRule = {
  id: string
  kind: RuleKind
  value: string
  label: string
  enabled: boolean
}

export type Relay = {
  id: string
  city: string
  country: string
  code: string
  address: string
  port: number
  status: 'ready' | 'setup-required' | 'offline'
  hasEnrollmentToken: boolean
  latency?: number
  sshFingerprint?: string
}

export type PathMetric = {
  route: number
  pathKind: string
  label: string
  endpoint: string
  reachable: boolean
  latencyMs: number | null
  nodeLatencyMs: number | null
  packetsSent: number
  packetsReceived: number
  bytesSent: number
  bytesReceived: number
  probesSent?: number
  probesReceived?: number
  probesLost?: number
  lastError: string | null
}

export type AppState = {
  clientVersion?: string
  tunnels: Tunnel[]
  rules: SplitRule[]
  trafficMode: 'all' | 'split'
  relays: Relay[]
  activeRelayId: string | null
  session: {
    status: 'idle' | 'starting' | 'prepared' | 'connected' | 'error'
    message?: string
    routeLatencies?: number[]
    pathMetrics?: PathMetric[]
    capture?: { state: string; backend: string; trafficMode?: string; targetCount?: number; diagnostics?: { matchedSockets: number; captureFilterCount: number; capturedPackets: number; capturedBytes: number; relayedPackets: number; bypassedPackets: number } }
    metrics?: { userToNodeMs: number | null; nodeToRelayMs: number | null; relayToServerMs: number | null; endToEndMs: number | null; benchmarkServer: string; bytesSent: number; bytesReceived: number; packetsSent: number; packetsReceived: number; packetLossPercent: number }
  }
  engine: {
    status: 'offline' | 'ready' | 'error'
    version: string
    message: string
    capabilities: null | {
      platform: string
      architecture: string
      wireGuardInstalled: boolean
      activeWireGuardInterfaces: string[]
      packetAdapterInstalled: boolean
      packetAdapter?: { libraryAvailable: boolean; libraryLoaded: boolean; driverVersion?: string; message: string }
      interception?: { backend: string; libraryAvailable: boolean; libraryLoaded: boolean; driverAvailable: boolean; administratorRequired: boolean; message: string }
    }
  }
  service: {
    status: 'not-installed' | 'offline' | 'ready'
    version: string
    message: string
    elevated: boolean
    sessionStatus?: string
  }
}

export type AddRuleInput = Pick<SplitRule, 'kind' | 'value' | 'label'>

export type GamePathApi = {
  bootstrap: () => Promise<AppState>
  importWireGuard: () => Promise<{ canceled: boolean; state?: AppState; errors?: string[] }>
  setTunnelEnabled: (id: string, enabled: boolean) => Promise<AppState>
  removeTunnel: (id: string) => Promise<AppState>
  browseRuleTarget: (kind: RuleKind) => Promise<{ canceled: boolean; value?: string; label?: string }>
  addRule: (input: AddRuleInput) => Promise<AppState>
  setRuleEnabled: (id: string, enabled: boolean) => Promise<AppState>
  removeRule: (id: string) => Promise<AppState>
  setTrafficMode: (mode: 'all' | 'split') => Promise<AppState>
  setRelay: (id: string) => Promise<AppState>
  addRelay: (input: { city: string; country: string }) => Promise<{ state: AppState; relayId: string }>
  removeRelayLocal: (id: string) => Promise<AppState>
  configureRelay: (id: string, input: { address: string; port: number; enrollmentToken?: string }) => Promise<AppState>
  importRelayEnrollment: (id: string) => Promise<{ canceled: boolean; state?: AppState }>
  testRelay: (id: string) => Promise<{ state: AppState; result: { reachable: boolean; latencyMs: number; virtualIpv4: string } }>
  provisionRelayVps: (id: string, input: VpsCredentials & { relayPort: number }) => Promise<AppState>
  removeRelayVps: (id: string, input: VpsCredentials) => Promise<AppState>
  onRelayVpsProgress: (callback: (update: { relayId: string; stage: string; percent: number; message: string }) => void) => () => void
  refreshService: () => Promise<AppState>
  installService: () => Promise<AppState>
  startSession: () => Promise<AppState>
  stopSession: () => Promise<AppState>
  refreshSession: () => Promise<AppState>
}

export type VpsCredentials = { host: string; sshPort: number; username: string; password: string }
