export type NodeKind = 'wireguard' | 'socks5' | 'openvpn' | 'l2tp'

/**
 * How traffic reaches the Internet. `relay` combines every enabled node at a
 * relay the user runs; `direct` sends it through one tunnelling node instead,
 * for people with no server of their own.
 */
export type ConnectionMode = 'relay' | 'direct'

/**
 * A named collection of nodes with one switch over all of them.
 *
 * A node inside a switched-off group stays exactly as the user left it and
 * simply stops carrying traffic, so turning the group back on restores the
 * selection rather than re-enabling everything.
 */
export type NodeGroup = {
  id: string
  name: string
  enabled: boolean
}

export type Tunnel = {
  id: string
  kind: NodeKind
  name: string
  endpoint: string
  address: string
  dns: string
  enabled: boolean
  /** The group whose switch also gates this node, or null when ungrouped. */
  groupId: string | null
  importedAt: string
  hasPrivateKey: boolean
  /** SOCKS5 nodes only. */
  host?: string
  port?: number
  hasCredentials?: boolean
  /** OpenVPN nodes only: the transport its file asks for, before any fallback. */
  protocol?: 'udp' | 'tcp'
  /** OpenVPN nodes only: whether the file uses `auth-user-pass`. */
  wantsCredentials?: boolean
}

/** Why one chosen file could not be used. */
export type OpenVpnRejection = { file: string; path: string; message: string }

/**
 * One `.ovpn` file the user chose, described well enough to decide what to ask
 * them next. The file's own contents stay in the main process.
 */
export type OpenVpnCandidate = {
  path: string
  name: string
  endpoint: string
  protocol: 'udp' | 'tcp'
  /** True when the file uses `auth-user-pass` and so needs a login. */
  wantsCredentials: boolean
}

export type OpenVpnChoice = {
  canceled: boolean
  files?: OpenVpnCandidate[]
  failures?: OpenVpnRejection[]
}

/**
 * Adding several files can partly succeed, so the result carries both how many
 * nodes were added and which files were rejected and why.
 */
export type OpenVpnAddResult = {
  state: AppState
  added: number
  failures: OpenVpnRejection[]
}

export type IpCountry = { ip: string; country: string; countryCode: string }

export type Socks5NodeInput = {
  address: string
  label?: string
  username?: string
  password?: string
}

export type Socks5ProbeResult = {
  reachable: boolean
  udpAssociate: boolean
  proxy: string
  setupLatencyMs: number
  latencyMs: number
}

export type L2tpNodeInput = {
  server: string
  label?: string
  preSharedKey: string
  username: string
  password: string
}

export type L2tpProbeResult = {
  reachable: boolean
  server: string
  assignedIpv4: string
  interfaceIndex: number
  setupLatencyMs: number
  dataLatencyMs: number
}

export type RuleKind = 'application' | 'folder' | 'hostname' | 'ip'

export type SplitRule = {
  id: string
  kind: RuleKind
  value: string
  label: string
  enabled: boolean
  groupId: string | null
}

export type SplitRuleGroup = {
  id: string
  name: string
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
  /** One-time cost of establishing this path's transport, not a hop latency. */
  handshakeMs: number | null
  /** Round trips inside `handshakeMs`; null when the protocol's count varies. */
  handshakeRoundTrips: number | null
  packetsSent: number
  packetsReceived: number
  bytesSent: number
  bytesReceived: number
  probesSent?: number
  probesReceived?: number
  probesLost?: number
  /**
   * Current probe loss as a percentage, smoothed by the engine. Unlike the
   * lifetime `probesLost`/`probesReceived` counters it decays, so a path that
   * has recovered stops reporting the loss it once had.
   */
  lossPercent?: number
  lastError: string | null
}

export type HandledConnection = {
  application: string
  destinationIp: string
  destinationPort: number
  protocol: string
  startedAt: number
}

export type AppState = {
  clientVersion?: string
  tunnels: Tunnel[]
  nodeGroups: NodeGroup[]
  rules: SplitRule[]
  ruleGroups: SplitRuleGroup[]
  trafficMode: 'all' | 'split'
  remoteDns: boolean
  connectionMode: ConnectionMode
  /** Smart uses the best two paths; manual duplicates across every healthy path. */
  routingStrategy: 'smart' | 'manual'
  relays: Relay[]
  activeRelayId: string | null
  session: {
    status: 'idle' | 'starting' | 'prepared' | 'connected' | 'error'
    mode?: ConnectionMode
    message?: string
    routeLatencies?: number[]
    strategy?: 'adaptive' | 'all-paths' | 'fastest-path' | 'duplicate' | 'single-path'
    selectedRoutes?: number[]
    /** Routes that are enabled but not currently carrying traffic. */
    degradedRoutes?: number[]
    /** The route used by the live GamePath relay-probe measurement. */
    journey?: {
      route: number | null
      label: string | null
      kind: string | null
      /** RTT measured through the VPN/proxy path to the GamePath relay. */
      probeRttMs: number | null
    }
    /** Routes that are enabled but were left out of the session entirely. */
    skippedRoutes?: Array<{ route: number; label: string; reason: string }>
    /** What the chosen transports leave for payload, and how the queues fare. */
    transport?: {
      effectiveMtu: number
      overheadBytes: number | null
      queueCapacity: number | null
      queueDepth: number[]
      droppedPackets: number[]
    }
    pathMetrics?: PathMetric[]
    capture?: {
      state: string
      backend: string
      adapterIndex?: number
      splitTunneling?: boolean
      trafficMode?: string
      targetCount?: number
      effectiveMtu?: number
      tcpMss?: number
      transportOverhead?: number
      /**
       * GamePath carries IPv4. `systemHasRoute` says whether this machine also
       * has a working IPv6 route, which keeps using the normal connection.
       */
      ipv6?: { carried: boolean; systemHasRoute: boolean }
      diagnostics?: {
        matchedSockets: number
        captureFilterCount: number
        /** `destinations` when the kernel filter admits only selected targets. */
        captureScope?: 'all-outbound' | 'destinations'
        captureScopeReason?: string
        captureFilter?: string
        tcpMss?: number
        capturedPackets: number
        capturedBytes: number
        relayedPackets: number
        bypassedPackets: number
        handledConnections?: HandledConnection[]
        captureLoopHistogram?: Array<{ upperBoundUs: number | null; count: number }>
        captureReceiveErrors?: number
        pendingSynDepth?: number
        pendingSynPeak?: number
        pendingSynOverflow?: number
        driverQueueTimeMs?: number
      }
    }
    metrics?: {
      userToNodeMs: number | null
      nodeToRelayMs: number | null
      relayToServerMs: number | null
      endToEndMs: number | null
      benchmarkServer: string
      bytesSent: number
      bytesReceived: number
      packetsSent: number
      packetsReceived: number
      packetLossPercent: number
    }
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
      interception?: {
        backend: string
        libraryAvailable: boolean
        libraryLoaded: boolean
        driverAvailable: boolean
        administratorRequired: boolean
        message: string
      }
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

export type AddRuleInput = Pick<SplitRule, 'kind' | 'value' | 'label' | 'groupId'>

export type GamePathApi = {
  bootstrap: () => Promise<AppState>
  lookupIpCountry: (target: string) => Promise<IpCountry | null>
  importWireGuard: () => Promise<{ canceled: boolean; state?: AppState; errors?: string[] }>
  chooseOpenVpnFiles: () => Promise<OpenVpnChoice>
  addOpenVpnNodes: (input: { filePaths: string[]; username?: string; password?: string }) => Promise<OpenVpnAddResult>
  addSocks5Node: (input: Socks5NodeInput) => Promise<{ state: AppState; nodeId: string }>
  testSocks5Node: (input: Socks5NodeInput) => Promise<Socks5ProbeResult>
  testSavedSocks5Node: (id: string) => Promise<Socks5ProbeResult>
  addL2tpNode: (input: L2tpNodeInput) => Promise<{ state: AppState; nodeId: string }>
  testL2tpNode: (input: L2tpNodeInput) => Promise<L2tpProbeResult>
  testSavedL2tpNode: (id: string) => Promise<L2tpProbeResult>
  setTunnelEnabled: (id: string, enabled: boolean) => Promise<AppState>
  setTunnelGroup: (id: string, groupId: string | null) => Promise<AppState>
  removeTunnel: (id: string) => Promise<AppState>
  addNodeGroup: (name: string) => Promise<{ state: AppState; groupId: string }>
  renameNodeGroup: (id: string, name: string) => Promise<AppState>
  setNodeGroupEnabled: (id: string, enabled: boolean) => Promise<AppState>
  removeNodeGroup: (id: string) => Promise<AppState>
  browseRuleTarget: (kind: RuleKind) => Promise<{ canceled: boolean; value?: string; label?: string }>
  addRule: (input: AddRuleInput) => Promise<AppState>
  setRuleEnabled: (id: string, enabled: boolean) => Promise<AppState>
  setRuleGroup: (id: string, groupId: string | null) => Promise<AppState>
  removeRule: (id: string) => Promise<AppState>
  addRuleGroup: (name: string) => Promise<AppState>
  renameRuleGroup: (id: string, name: string) => Promise<AppState>
  setRuleGroupEnabled: (id: string, enabled: boolean) => Promise<AppState>
  removeRuleGroup: (id: string) => Promise<AppState>
  setTrafficMode: (mode: 'all' | 'split') => Promise<AppState>
  setRemoteDns: (enabled: boolean) => Promise<AppState>
  setConnectionMode: (mode: ConnectionMode) => Promise<AppState>
  setRoutingStrategy: (strategy: 'smart' | 'manual') => Promise<AppState>
  setRelay: (id: string) => Promise<AppState>
  addRelay: (input: { city: string; country: string }) => Promise<{ state: AppState; relayId: string }>
  removeRelayLocal: (id: string) => Promise<AppState>
  configureRelay: (id: string, input: { address: string; port: number; enrollmentToken?: string }) => Promise<AppState>
  importRelayEnrollment: (id: string) => Promise<{ canceled: boolean; state?: AppState }>
  testRelay: (
    id: string,
  ) => Promise<{ state: AppState; result: { reachable: boolean; latencyMs: number; virtualIpv4: string } }>
  provisionRelayVps: (id: string, input: VpsCredentials & { relayPort: number }) => Promise<AppState>
  removeRelayVps: (id: string, input: VpsCredentials) => Promise<AppState>
  onRelayVpsProgress: (
    callback: (update: { relayId: string; stage: string; percent: number; message: string }) => void,
  ) => () => void
  refreshService: () => Promise<AppState>
  installService: () => Promise<AppState>
  startSession: () => Promise<AppState>
  stopSession: () => Promise<AppState>
  refreshSession: () => Promise<AppState>
}

export type VpsCredentials = { host: string; sshPort: number; username: string; password: string }
