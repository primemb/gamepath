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
  latency?: number
}

export type AppState = {
  tunnels: Tunnel[]
  rules: SplitRule[]
  trafficMode: 'all' | 'split'
  relays: Relay[]
  activeRelayId: string
  session: { status: 'idle' | 'starting' | 'prepared' | 'connected' | 'error'; message?: string }
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
  configureRelay: (id: string, input: { address: string; port: number }) => Promise<AppState>
  startSession: () => Promise<AppState>
}
