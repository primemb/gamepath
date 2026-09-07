import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity,
  AppWindow,
  ArrowDownRight,
  ArrowUpRight,
  Check,
  ChevronDown,
  ChevronRight,
  CircleGauge,
  FolderOpen,
  Gamepad2,
  Globe2,
  HardDrive,
  Import,
  Info,
  Layers,
  LayoutDashboard,
  Link2,
  ListChecks,
  MapPin,
  Network,
  Plus,
  Power,
  Radio,
  Route,
  Server,
  Settings,
  Share2,
  ShieldCheck,
  Sparkles,
  Trash2,
  Waypoints,
  X,
  Zap,
} from 'lucide-react'
import { mockApi } from './mockApi'
import type {
  AddRuleInput,
  AppState,
  ConnectionMode,
  GamePathApi,
  PathMetric,
  Relay,
  RuleKind,
  Socks5NodeInput,
  Socks5ProbeResult,
  Tunnel,
} from './types'

type View = 'dashboard' | 'routes' | 'split' | 'relays' | 'settings'

const api: GamePathApi = window.gamepath ?? mockApi

const navItems: { id: View; label: string; icon: typeof LayoutDashboard }[] = [
  { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
  { id: 'routes', label: 'Routes and nodes', icon: Route },
  { id: 'split', label: 'Split tunnel', icon: Network },
  { id: 'relays', label: 'Connection', icon: Server },
]

const connectionModes = [
  {
    id: 'relay' as const,
    icon: Layers,
    title: 'Relay mode',
    tagline: 'Lowest loss',
    body: 'Every node you enable carries the same packets to a relay you run. When one hop stumbles, the copy that took the other path still arrives on time.',
    needs: 'Needs a VPS running the GamePath relay.',
  },
  {
    id: 'direct' as const,
    icon: Waypoints,
    title: 'Direct mode',
    tagline: 'No server needed',
    body: 'Your selected traffic goes through one WireGuard node and out to the game from there. A plain split tunnel, with nothing else to run.',
    needs: 'Needs one WireGuard node. SOCKS5 proxies can only be used with a relay.',
  },
]

/**
 * Picks how traffic leaves this PC.
 *
 * The two modes are not better and worse versions of each other — one is
 * faster, the other needs nothing to be set up — so both are shown side by
 * side with what each costs, and the one that suits what the user already has
 * is marked. The trade-off of the chosen mode is stated under it rather than
 * saved for the moment a session fails to start.
 */
function ConnectionModes({
  mode,
  recommended,
  onSelect,
  onSetUpRelay,
}: {
  mode: ConnectionMode
  recommended: ConnectionMode | null
  onSelect: (next: ConnectionMode) => void
  onSetUpRelay: () => void
}) {
  return (
    <div className="mode-picker">
      <div className="mode-grid" role="radiogroup" aria-label="Connection mode">
        {connectionModes.map((option) => {
          const Icon = option.icon
          const active = mode === option.id
          return (
            <button
              type="button"
              role="radio"
              aria-checked={active}
              key={option.id}
              className={`mode-card ${active ? 'is-active' : ''}`}
              onClick={() => onSelect(option.id)}
            >
              <span className="mode-icon">
                <Icon size={19} />
              </span>
              <span className="mode-head">
                <strong>{option.title}</strong>
                <em>{option.tagline}</em>
                {recommended === option.id && <span className="mode-tip">Suits your setup</span>}
              </span>
              <span className="mode-body">{option.body}</span>
              <small>{option.needs}</small>
            </button>
          )
        })}
      </div>
      {mode === 'direct' && (
        <p className="mode-tradeoff">
          <Info size={14} />
          <span>
            One path means a lost packet is simply lost. Combining nodes at a relay is what makes GamePath steadier than
            a plain VPN.
          </span>
          <button className="text-button" onClick={onSetUpRelay}>
            Switch to relay mode <ChevronRight size={14} />
          </button>
        </p>
      )}
    </div>
  )
}

function Toggle({
  checked,
  onChange,
  label,
  disabled = false,
}: {
  checked: boolean
  onChange: (next: boolean) => void
  label: string
  disabled?: boolean
}) {
  return (
    <button
      className={`toggle ${checked ? 'is-on' : ''}`}
      onClick={() => onChange(!checked)}
      aria-label={label}
      aria-pressed={checked}
      disabled={disabled}
    >
      <span />
    </button>
  )
}

function Endpoint({
  tunnel,
  direct,
  onToggle,
  onRemove,
}: {
  tunnel: Tunnel
  direct: boolean
  onToggle: (enabled: boolean) => void
  onRemove: () => void
}) {
  const isProxy = tunnel.kind === 'socks5'
  // A proxy has no way to route on its own, so in direct mode it stays in the
  // list with the reason attached rather than quietly refusing to switch on.
  const unusable = direct && isProxy
  const stateLabel = tunnel.enabled ? (direct ? 'Carrying traffic' : 'Enabled') : 'Disabled'
  return (
    <article className={`route-card ${tunnel.enabled ? 'is-enabled' : ''} ${unusable ? 'is-unusable' : ''}`}>
      <div className="route-state-icon">{isProxy ? <Share2 size={18} /> : <Radio size={18} />}</div>
      <div className="route-copy">
        <div className="route-title-row">
          <h3>{tunnel.name}</h3>
          <span className="kind-pill">{isProxy ? 'SOCKS5' : 'WireGuard'}</span>
          {unusable ? (
            <span className="status-pill">
              <i /> Needs a relay
            </span>
          ) : (
            <span className={`status-pill ${tunnel.enabled ? 'online' : ''}`}>
              <i /> {stateLabel}
            </span>
          )}
        </div>
        <p>{tunnel.endpoint}</p>
        <div className="route-meta">
          {isProxy ? (
            <>
              <span>
                Transport <strong>UDP associate</strong>
              </span>
              <span>
                Auth <strong>{tunnel.hasCredentials ? 'Username and password' : 'None'}</strong>
              </span>
              <span title="Frames are encrypted by GamePath, but the proxy hop itself is not">
                <Info size={13} /> No outer encryption
              </span>
            </>
          ) : (
            <>
              <span>
                Address <strong>{tunnel.address}</strong>
              </span>
              <span>
                DNS <strong>{tunnel.dns}</strong>
              </span>
              <span>
                <ShieldCheck size={13} /> Key protected
              </span>
            </>
          )}
        </div>
        {unusable && (
          <p className="route-note">
            <Info size={13} /> A SOCKS5 proxy forwards connections, it does not route packets, so it needs a relay on
            the other side. Switch to relay mode to use this node.
          </p>
        )}
      </div>
      <div className="route-actions">
        <Toggle
          checked={tunnel.enabled}
          disabled={unusable}
          onChange={onToggle}
          label={
            unusable
              ? `${tunnel.name} cannot be used in direct mode`
              : direct
                ? `Carry traffic through ${tunnel.name}`
                : `${tunnel.enabled ? 'Disable' : 'Enable'} ${tunnel.name}`
          }
        />
        <button className="icon-button danger" onClick={onRemove} aria-label={`Remove ${tunnel.name}`}>
          <Trash2 size={16} />
        </button>
      </div>
    </article>
  )
}

function SetupStep({
  done,
  number,
  title,
  detail,
  action,
  onClick,
}: {
  done: boolean
  number: number
  title: string
  detail: string
  action: string
  onClick: () => void
}) {
  return (
    <button className={`setup-step ${done ? 'complete' : ''}`} onClick={onClick}>
      <span className="step-number">{done ? <Check size={15} /> : number}</span>
      <span className="step-copy">
        <strong>{title}</strong>
        <small>{detail}</small>
      </span>
      <span className="step-action">
        {done ? 'Ready' : action}
        <ChevronRight size={15} />
      </span>
    </button>
  )
}

const formatMetric = (value: number | null | undefined) => (value == null ? '—' : `${Math.round(value)} ms`)
const formatBytes = (bytes: number | undefined) => {
  const value = bytes ?? 0
  if (value < 1024) return `${value} B`
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`
  return `${(value / 1024 ** 2).toFixed(2)} MB`
}

type PathSample = { latency: number; probe: number }
type PathHistory = Record<number, PathSample[]>
type PathRate = { sent: number; received: number }

const pathColors = ['#26e6cd', '#8a7cff', '#ffb35c', '#5ca8ff', '#ef6fae', '#8fdb62']
const jitter = (samples: PathSample[]) =>
  samples.length < 2
    ? 0
    : samples.slice(1).reduce((total, sample, index) => total + Math.abs(sample.latency - samples[index].latency), 0) /
      (samples.length - 1)
const pathLoss = (path: PathMetric) => {
  const completed = (path.probesReceived ?? 0) + (path.probesLost ?? 0)
  return completed ? ((path.probesLost ?? 0) / completed) * 100 : 0
}
const formatRate = (bytesPerSecond: number | undefined) => `${formatBytes(bytesPerSecond)}/s`
const histogramPercentile = (
  buckets: Array<{ upperBoundUs: number | null; count: number }> | undefined,
  percentile: number,
) => {
  if (!buckets?.length) return null
  const total = buckets.reduce((sum, bucket) => sum + bucket.count, 0)
  if (!total) return null
  const target = total * percentile
  let seen = 0
  for (const bucket of buckets) {
    seen += bucket.count
    if (seen >= target) return bucket.upperBoundUs
  }
  return null
}

const CHART_WIDTH = 600
const CHART_HEIGHT = 160
const CHART_TOP = 4
const CHART_BOTTOM = 156

function LatencyChart({ histories, paths }: { histories: PathHistory; paths: PathMetric[] }) {
  const series = paths.map((path, index) => ({
    path,
    color: pathColors[index % pathColors.length],
    samples: histories[path.route] ?? [],
  }))
  const allValues = series.flatMap((item) => item.samples.map((sample) => sample.latency))
  const maximum = allValues.length ? Math.max(...allValues) : 10
  const minimum = allValues.length ? Math.min(...allValues) : 0
  const padding = Math.max((maximum - minimum) * 0.15, 4)
  const low = Math.max(0, minimum - padding)
  const high = maximum + padding
  const range = Math.max(high - low, 1)
  const project = (latency: number) => CHART_BOTTOM - ((latency - low) / range) * (CHART_BOTTOM - CHART_TOP)
  const line = (samples: PathSample[]) => {
    const values = samples.length === 1 ? [samples[0], samples[0]] : samples
    return values
      .map((sample, index) => `${(index / Math.max(values.length - 1, 1)) * CHART_WIDTH},${project(sample.latency)}`)
      .join(' ')
  }
  if (!series.length) return <p className="chart-empty">Route latency appears here as soon as a session is running.</p>
  return (
    <>
      <div className="chart-body">
        <div className="chart-axis">
          <span>{Math.round(high)} ms</span>
          <span>{Math.round((high + low) / 2)} ms</span>
          <span>{Math.round(low)} ms</span>
        </div>
        <svg
          className="latency-chart"
          viewBox={`0 0 ${CHART_WIDTH} ${CHART_HEIGHT}`}
          preserveAspectRatio="none"
          role="img"
          aria-label="Latency history for every WireGuard route"
        >
          <defs>
            {series.map((item) => (
              <linearGradient key={item.path.route} id={`route-fill-${item.path.route}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={item.color} stopOpacity="0.26" />
                <stop offset="100%" stopColor={item.color} stopOpacity="0" />
              </linearGradient>
            ))}
          </defs>
          <g className="chart-grid">
            <line x1="0" y1={CHART_TOP} x2={CHART_WIDTH} y2={CHART_TOP} />
            <line x1="0" y1={(CHART_TOP + CHART_BOTTOM) / 2} x2={CHART_WIDTH} y2={(CHART_TOP + CHART_BOTTOM) / 2} />
            <line x1="0" y1={CHART_BOTTOM} x2={CHART_WIDTH} y2={CHART_BOTTOM} />
          </g>
          {series.map((item) => {
            if (!item.samples.length) return null
            const points = line(item.samples)
            return (
              <g key={item.path.route}>
                <polygon
                  points={`0,${CHART_HEIGHT} ${points} ${CHART_WIDTH},${CHART_HEIGHT}`}
                  fill={`url(#route-fill-${item.path.route})`}
                />
                <polyline
                  points={points}
                  fill="none"
                  stroke={item.color}
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                />
              </g>
            )
          })}
        </svg>
      </div>
      <div className="chart-legend">
        {series.map((item) => (
          <span key={item.path.route}>
            <i style={{ background: item.color }} />
            {item.path.label}
            <strong>{formatMetric(item.path.latencyMs)}</strong>
          </span>
        ))}
      </div>
    </>
  )
}

function TelemetryPanel({
  state,
  histories,
  rates,
}: {
  state: AppState
  histories: PathHistory
  rates: Record<number, PathRate>
}) {
  const [showConnections, setShowConnections] = useState(true)
  const metrics = state.session.metrics
  const capture = state.session.capture?.diagnostics
  const connections = capture?.handledConnections ?? []
  const captureP99 = histogramPercentile(capture?.captureLoopHistogram, 0.99)
  const paths = state.session.pathMetrics ?? []
  const live = state.session.status === 'connected'
  const bestPath = paths
    .filter((path) => path.reachable && path.latencyMs != null)
    .sort((a, b) => (a.latencyMs ?? Infinity) - (b.latencyMs ?? Infinity))[0]
  // A direct session's node is the last hop, so its journey has one leg fewer
  // and the middle stage would only ever read as an empty measurement. Before
  // a session starts there is no session mode, so the chosen one stands in.
  const direct = (state.session.mode ?? state.connectionMode) === 'direct'
  const bestNodeToRelay =
    bestPath?.nodeLatencyMs != null && bestPath.latencyMs != null
      ? Math.max(0, bestPath.latencyMs - bestPath.nodeLatencyMs)
      : null
  const serverStage = [
    direct ? 'VPN node → server' : 'Relay → server',
    metrics?.relayToServerMs,
    metrics?.benchmarkServer ? `Benchmark ${metrics.benchmarkServer}` : 'Awaiting target',
  ] as const
  const stages = direct
    ? ([
        ['You → VPN node', bestPath?.nodeLatencyMs, bestPath ? `${bestPath.label} handshake` : 'Awaiting node'],
        serverStage,
      ] as const)
    : ([
        ['User → VPN node', bestPath?.nodeLatencyMs, bestPath ? `${bestPath.label} handshake` : 'Awaiting route'],
        ['VPN node → relay', bestNodeToRelay, bestPath ? `${bestPath.label} estimate` : 'Awaiting route'],
        serverStage,
      ] as const)
  return (
    <section className="telemetry-panel">
      <div className="telemetry-head">
        <div>
          <span className="eyebrow">Live telemetry</span>
          <h2>Network journey</h2>
        </div>
        <span className={`status-pill ${live ? 'online' : ''}`}>
          <i />
          {live ? (capture ? `${capture.relayedPackets} game packets routed` : 'Live') : 'Waiting'}
        </span>
      </div>

      <div className="telemetry-charts">
        <div className="chart-card">
          <div className="card-head">
            <div>
              <span className="eyebrow">Route latency history</span>
              <h3>{bestPath ? `Best ${formatMetric(bestPath.latencyMs)}` : 'Waiting for probes'}</h3>
            </div>
            <small>Last 60 probes · one probe per route every 10s</small>
          </div>
          <LatencyChart histories={histories} paths={paths} />
        </div>
        <div className="telemetry-side">
          <div className="journey-card">
            <span className="eyebrow">Journey breakdown</span>
            <div className="journey-grid">
              {stages.map(([label, value, detail], index) => (
                <div className="journey-stage" key={label}>
                  <span>{index + 1}</span>
                  <div>
                    <small>{label}</small>
                    <strong>{formatMetric(value)}</strong>
                    <em>{detail}</em>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="transfer-grid">
            <div>
              <ArrowUpRight size={15} />
              <span>
                Data sent<strong>{formatBytes(metrics?.bytesSent)}</strong>
              </span>
            </div>
            <div>
              <ArrowDownRight size={15} />
              <span>
                Data received<strong>{formatBytes(metrics?.bytesReceived)}</strong>
              </span>
            </div>
            <div>
              <Activity size={15} />
              <span>
                Packet loss<strong>{metrics ? `${metrics.packetLossPercent.toFixed(1)}%` : '—'}</strong>
              </span>
            </div>
            <div>
              <Radio size={15} />
              <span>
                Packets<strong>{metrics ? `${metrics.packetsReceived} / ${metrics.packetsSent}` : '—'}</strong>
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="node-heading">
        <div>
          <span className="eyebrow">{direct ? 'Your VPN node' : 'All VPN nodes'}</span>
          <h3>{direct ? 'Node quality' : 'Route quality'}</h3>
        </div>
        <small>
          {direct ? 'One node, no duplication' : `${paths.length} active route${paths.length === 1 ? '' : 's'}`}
        </small>
      </div>
      {paths.length ? (
        <div className="node-grid">
          {paths.map((path, index) => {
            const samples = histories[path.route] ?? []
            const carryingTraffic = state.session.selectedRoutes?.includes(path.route) ?? path.reachable
            const nodeToRelay =
              path.nodeLatencyMs != null && path.latencyMs != null
                ? Math.max(0, path.latencyMs - path.nodeLatencyMs)
                : null
            const rate = rates[path.route]
            return (
              <article
                className={`node-card ${path.reachable ? 'healthy' : 'unhealthy'} ${carryingTraffic ? 'carrying' : ''}`}
                key={path.route}
              >
                <div className="node-card-head">
                  <span className="node-color" style={{ background: pathColors[index % pathColors.length] }} />
                  <div>
                    <strong>{path.label}</strong>
                    <small>{path.endpoint}</small>
                  </div>
                  <span className={`route-health ${path.reachable ? 'online' : ''}`}>
                    <i />
                    {path.reachable ? (carryingTraffic ? 'Active' : 'Standby') : 'Offline'}
                  </span>
                </div>
                <div className="node-primary">
                  <span>
                    <small>{direct ? 'Node RTT' : 'Relay RTT'}</small>
                    <strong>{formatMetric(path.latencyMs)}</strong>
                  </span>
                  <span>
                    <small>Jitter</small>
                    <strong>{samples.length ? `${jitter(samples).toFixed(1)} ms` : '—'}</strong>
                  </span>
                  <span>
                    <small>Probe loss</small>
                    <strong>{`${pathLoss(path).toFixed(1)}%`}</strong>
                  </span>
                </div>
                <div className="node-secondary">
                  <span>
                    User → node <strong>{formatMetric(path.nodeLatencyMs)}</strong>
                  </span>
                  {!direct && (
                    <span>
                      Node → relay <strong>{formatMetric(nodeToRelay)}</strong>
                    </span>
                  )}
                  <span>
                    Probes{' '}
                    <strong>
                      {path.probesReceived ?? 0}/{path.probesSent ?? 0}
                    </strong>
                  </span>
                </div>
                <div className="node-traffic">
                  <span>
                    <ArrowUpRight size={13} />
                    {formatRate(rate?.sent)}
                    <small>{formatBytes(path.bytesSent)} total</small>
                  </span>
                  <span>
                    <ArrowDownRight size={13} />
                    {formatRate(rate?.received)}
                    <small>{formatBytes(path.bytesReceived)} total</small>
                  </span>
                </div>
                {path.lastError && <p className="node-error">{path.lastError}</p>}
              </article>
            )
          })}
        </div>
      ) : (
        <p className="node-empty">Start a session to measure every enabled WireGuard route.</p>
      )}

      <div className={`connections-card ${showConnections ? 'is-open' : ''}`}>
        <button
          className="connections-head"
          onClick={() => setShowConnections((current) => !current)}
          aria-expanded={showConnections}
        >
          <div>
            <span className="eyebrow">Handled connections</span>
            <h3>Traffic currently routed</h3>
          </div>
          <small>
            {connections.length} active connection{connections.length === 1 ? '' : 's'}
          </small>
          <ChevronDown size={15} />
        </button>
        {showConnections && (
          <>
            {connections.length ? (
              <div className="connections-table">
                <div className="connection-header">
                  <span>Application</span>
                  <span>Destination</span>
                  <span>Protocol</span>
                  <span>Connected</span>
                </div>
                {connections.map((connection, index) => (
                  <div
                    className="connection-row"
                    key={`${connection.application}-${connection.destinationIp}-${connection.destinationPort}-${index}`}
                  >
                    <span>
                      <AppWindow size={14} />
                      <strong>{connection.application}</strong>
                    </span>
                    <code>
                      {connection.destinationIp}
                      {connection.destinationPort ? `:${connection.destinationPort}` : ''}
                    </code>
                    <em>{connection.protocol}</em>
                    <time>
                      {new Date(connection.startedAt * 1000).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                      })}
                    </time>
                  </div>
                ))}
              </div>
            ) : (
              <p className="connections-empty">
                Start the game to see each executable and destination IP handled by GamePath.
              </p>
            )}
            {capture && (
              <div className="capture-health">
                <span>
                  Capture p99 <strong>{captureP99 == null ? '—' : `≤ ${captureP99} µs`}</strong>
                </span>
                <span>
                  Pending SYN <strong>{capture.pendingSynDepth ?? 0}</strong>
                </span>
                <span>
                  Queue peak <strong>{capture.pendingSynPeak ?? 0}</strong>
                </span>
                <span>
                  Overflow <strong>{capture.pendingSynOverflow ?? 0}</strong>
                </span>
              </div>
            )}
          </>
        )}
      </div>
    </section>
  )
}

function RuleModal({ onClose, onSave }: { onClose: () => void; onSave: (input: AddRuleInput) => Promise<void> }) {
  const [kind, setKind] = useState<RuleKind>('application')
  const [value, setValue] = useState('')
  const [label, setLabel] = useState('')
  const kinds: { id: RuleKind; label: string; icon: typeof AppWindow }[] = [
    { id: 'application', label: 'Application', icon: AppWindow },
    { id: 'folder', label: 'Folder', icon: FolderOpen },
    { id: 'hostname', label: 'Hostname', icon: Globe2 },
    { id: 'ip', label: 'IP address', icon: Network },
  ]

  const browse = async () => {
    const result = await api.browseRuleTarget(kind)
    if (!result.canceled && result.value) {
      setValue(result.value)
      setLabel(result.label ?? result.value)
    }
  }

  const placeholder = kind === 'hostname' ? 'game.example.com or *.example.com' : '203.0.113.20 or 203.0.113.0/24'

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section
        className="modal"
        onMouseDown={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Add split tunnel target"
      >
        <div className="modal-head">
          <div>
            <span className="eyebrow">Traffic rule</span>
            <h2>Add a split-tunnel target</h2>
          </div>
          <button className="icon-button" onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <p className="modal-intro">
          Only matching traffic will use GamePath. Everything else stays on your normal connection.
        </p>
        <div className="kind-grid">
          {kinds.map((item) => {
            const Icon = item.icon
            return (
              <button
                key={item.id}
                className={kind === item.id ? 'active' : ''}
                onClick={() => {
                  setKind(item.id)
                  setValue('')
                  setLabel('')
                }}
              >
                <Icon size={17} />
                {item.label}
              </button>
            )
          })}
        </div>
        {kind === 'application' || kind === 'folder' ? (
          <button className="file-drop" onClick={browse}>
            <span className="file-drop-icon">
              <FolderOpen size={22} />
            </span>
            <strong>{value ? label : `Choose ${kind === 'application' ? 'an executable' : 'a folder'}`}</strong>
            <small>
              {value || (kind === 'application' ? 'Select the game .exe file' : 'All applications inside will match')}
            </small>
          </button>
        ) : (
          <label className="field-label">
            {kind === 'hostname' ? 'Hostname' : 'IP or CIDR range'}
            <input
              autoFocus
              value={value}
              onChange={(event) => {
                setValue(event.target.value)
                setLabel(event.target.value)
              }}
              placeholder={placeholder}
            />
          </label>
        )}
        <div className="modal-actions">
          <button className="button secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            className="button primary"
            disabled={!value.trim()}
            onClick={() => onSave({ kind, value, label: label || value })}
          >
            <Plus size={16} />
            Add target
          </button>
        </div>
      </section>
    </div>
  )
}

function RelayModal({
  relay,
  onClose,
  onSave,
  onImport,
}: {
  relay: Relay
  onClose: () => void
  onSave: (input: { address: string; port: number; enrollmentToken?: string }) => Promise<void>
  onImport: () => Promise<void>
}) {
  const [address, setAddress] = useState(relay.address)
  const [port, setPort] = useState(String(relay.port || 51821))
  const [enrollmentToken, setEnrollmentToken] = useState('')
  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section
        className="modal relay-modal"
        onMouseDown={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Configure relay"
      >
        <div className="modal-head">
          <div>
            <span className="eyebrow">
              {relay.city}, {relay.country}
            </span>
            <h2>Configure relay endpoint</h2>
          </div>
          <button className="icon-button" onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <p className="modal-intro">
          Set the public endpoint and its unique client credential. The credential is encrypted by Windows and is never
          shown again after saving.
        </p>
        <div className="relay-fields">
          <label className="field-label">
            Hostname or IP address
            <input
              autoFocus
              value={address}
              onChange={(event) => setAddress(event.target.value)}
              placeholder="relay.example.com"
            />
          </label>
          <label className="field-label port-field">
            UDP port
            <input
              value={port}
              onChange={(event) => setPort(event.target.value.replace(/\D/g, '').slice(0, 5))}
              placeholder="51821"
            />
          </label>
        </div>
        <label className="field-label enrollment-field">
          Enrollment token
          <input
            type="password"
            value={enrollmentToken}
            onChange={(event) => setEnrollmentToken(event.target.value)}
            placeholder={
              relay.hasEnrollmentToken ? 'Credential already protected — leave blank to keep it' : 'Paste gpe1_… token'
            }
          />
        </label>
        <button className="file-import-button" onClick={onImport}>
          <ShieldCheck size={15} />
          Import a .enroll file<span>{relay.hasEnrollmentToken ? 'Credential protected' : 'Recommended'}</span>
        </button>
        <div className="modal-actions">
          <button className="button secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            className="button primary"
            disabled={!address.trim() || !port || (!relay.hasEnrollmentToken && !enrollmentToken.trim())}
            onClick={() =>
              onSave({
                address: address.trim(),
                port: Number(port),
                enrollmentToken: enrollmentToken.trim() || undefined,
              })
            }
          >
            <Check size={16} />
            Save relay
          </button>
        </div>
      </section>
    </div>
  )
}

function Socks5Modal({
  onClose,
  onAdd,
  onTest,
}: {
  onClose: () => void
  onAdd: (input: Socks5NodeInput) => Promise<void>
  onTest: (input: Socks5NodeInput) => Promise<Socks5ProbeResult>
}) {
  const [address, setAddress] = useState('')
  const [label, setLabel] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState<'idle' | 'testing' | 'saving'>('idle')
  const [result, setResult] = useState<string | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  const input = (): Socks5NodeInput => ({
    address: address.trim(),
    label: label.trim() || undefined,
    username: username.trim() || undefined,
    password: password || undefined,
  })

  const runTest = async () => {
    setBusy('testing')
    setResult(null)
    setFailure(null)
    try {
      const probe = await onTest(input())
      setResult(
        `UDP works through ${probe.proxy}: relay answered in ${Math.round(probe.latencyMs)} ms ` +
          `(${Math.round(probe.setupLatencyMs)} ms to open the association).`,
      )
    } catch (error) {
      setFailure((error as Error).message)
    } finally {
      setBusy('idle')
    }
  }

  const save = async () => {
    setBusy('saving')
    setFailure(null)
    try {
      await onAdd(input())
    } catch (error) {
      setFailure((error as Error).message)
      setBusy('idle')
    }
  }

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section
        className="modal relay-modal"
        onMouseDown={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Add a SOCKS5 node"
      >
        <div className="modal-head">
          <div>
            <span className="eyebrow">SOCKS5 proxy</span>
            <h2>Add a proxy node</h2>
          </div>
          <button className="icon-button" onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <p className="modal-intro">
          GamePath carries game traffic as UDP, so the proxy has to support <strong>UDP ASSOCIATE</strong>. Test the
          node before saving: some proxies accept the association and then never forward a datagram.
        </p>
        <label className="field-label">
          Proxy address
          <input
            autoFocus
            value={address}
            onChange={(event) => setAddress(event.target.value)}
            placeholder="127.0.0.1:2080 or socks5://user:password@proxy.example:1080"
          />
        </label>
        <label className="field-label">
          Name (optional)
          <input value={label} onChange={(event) => setLabel(event.target.value)} placeholder="Local proxy" />
        </label>
        <div className="relay-fields">
          <label className="field-label">
            Username (optional)
            <input value={username} onChange={(event) => setUsername(event.target.value)} placeholder="Leave blank" />
          </label>
          <label className="field-label">
            Password (optional)
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Leave blank"
            />
          </label>
        </div>
        {result && (
          <div className="info-banner">
            <Check size={18} />
            <div>
              <strong>This proxy can carry GamePath traffic</strong>
              <p>{result}</p>
            </div>
          </div>
        )}
        {failure && (
          <div className="info-banner">
            <Info size={18} />
            <div>
              <strong>This proxy cannot be used yet</strong>
              <p>{failure}</p>
            </div>
          </div>
        )}
        <div className="modal-actions">
          <button className="button secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="button secondary" disabled={!address.trim() || busy !== 'idle'} onClick={runTest}>
            <Zap size={16} />
            {busy === 'testing' ? 'Testing…' : 'Test UDP'}
          </button>
          <button className="button primary" disabled={!address.trim() || busy !== 'idle'} onClick={save}>
            <Check size={16} />
            {busy === 'saving' ? 'Saving…' : 'Add node'}
          </button>
        </div>
      </section>
    </div>
  )
}

function AddRelayModal({
  onClose,
  onAdd,
}: {
  onClose: () => void
  onAdd: (input: { city: string; country: string }) => Promise<void>
}) {
  const [city, setCity] = useState('Istanbul')
  const [country, setCountry] = useState('Turkey')
  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section className="modal relay-modal" onMouseDown={(event) => event.stopPropagation()}>
        <div className="modal-head">
          <div>
            <span className="eyebrow">New location</span>
            <h2>Add relay server</h2>
          </div>
          <button className="icon-button" onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <div className="relay-fields">
          <label className="field-label">
            City or label
            <input autoFocus value={city} onChange={(event) => setCity(event.target.value)} />
          </label>
          <label className="field-label">
            Country
            <input value={country} onChange={(event) => setCountry(event.target.value)} />
          </label>
        </div>
        <div className="modal-actions">
          <button className="button secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            className="button primary"
            disabled={!city.trim() || !country.trim()}
            onClick={() => onAdd({ city: city.trim(), country: country.trim() })}
          >
            <Plus size={16} />
            Add relay
          </button>
        </div>
      </section>
    </div>
  )
}

function VpsModal({
  relay,
  action,
  onClose,
  onSubmit,
}: {
  relay: Relay
  action: 'provision' | 'remove'
  onClose: () => void
  onSubmit: (input: {
    host: string
    sshPort: number
    username: string
    password: string
    relayPort: number
  }) => Promise<void>
}) {
  const [host, setHost] = useState(relay.address)
  const [sshPort, setSshPort] = useState('22')
  const [username, setUsername] = useState('root')
  const [password, setPassword] = useState('')
  const [relayPort, setRelayPort] = useState(String(relay.port || 51821))
  const [busy, setBusy] = useState(false)
  const [progress, setProgress] = useState({ percent: 0, message: 'Preparing deployment' })
  useEffect(
    () =>
      api.onRelayVpsProgress((update) => {
        if (update.relayId === relay.id) setProgress(update)
      }),
    [relay.id],
  )
  return (
    <div className="modal-backdrop" onMouseDown={busy ? undefined : onClose}>
      <section className="modal relay-modal" onMouseDown={(event) => event.stopPropagation()}>
        <div className="modal-head">
          <div>
            <span className="eyebrow">Secure SSH setup</span>
            <h2>{action === 'provision' ? 'Configure Debian VPS' : 'Remove relay from VPS'}</h2>
          </div>
          <button className="icon-button" disabled={busy} onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <p className="modal-intro">
          {action === 'provision'
            ? 'GamePath uploads its relay source, installs dependencies, configures the service and firewall, then imports this PC’s enrollment automatically.'
            : 'This removes the GamePath service, firewall tables, configuration, clients, and binary from this server.'}{' '}
          The SSH password is used only for this operation and is never saved.
        </p>
        <div className="relay-fields">
          <label className="field-label">
            VPS hostname or IP
            <input
              autoFocus
              value={host}
              onChange={(event) => setHost(event.target.value)}
              placeholder="203.0.113.10"
            />
          </label>
          <label className="field-label port-field">
            SSH port
            <input
              value={sshPort}
              onChange={(event) => setSshPort(event.target.value.replace(/\D/g, '').slice(0, 5))}
            />
          </label>
        </div>
        <div className="relay-fields">
          <label className="field-label">
            SSH username
            <input value={username} onChange={(event) => setUsername(event.target.value)} />
          </label>
          <label className="field-label">
            SSH password
            <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} />
          </label>
        </div>
        {action === 'provision' && (
          <label className="field-label enrollment-field">
            Relay UDP port
            <input
              value={relayPort}
              onChange={(event) => setRelayPort(event.target.value.replace(/\D/g, '').slice(0, 5))}
            />
          </label>
        )}
        {busy && (
          <div className="vps-progress">
            <div>
              <strong>{progress.message}</strong>
              <span>{progress.percent}%</span>
            </div>
            <i>
              <b style={{ width: `${progress.percent}%` }} />
            </i>
            <small>Keep GamePath open. A first-time Rust build can take several minutes.</small>
          </div>
        )}
        <div className="modal-actions">
          <button className="button secondary" disabled={busy} onClick={onClose}>
            Cancel
          </button>
          <button
            className={`button ${action === 'remove' ? 'danger' : 'primary'}`}
            disabled={busy || !host.trim() || !username.trim() || !password || !sshPort || !relayPort}
            onClick={async () => {
              setProgress({ percent: 1, message: 'Preparing deployment' })
              setBusy(true)
              try {
                await onSubmit({
                  host: host.trim(),
                  sshPort: Number(sshPort),
                  username: username.trim(),
                  password,
                  relayPort: Number(relayPort),
                })
              } finally {
                setBusy(false)
              }
            }}
          >
            {busy
              ? action === 'provision'
                ? 'Configuring VPS…'
                : 'Removing…'
              : action === 'provision'
                ? 'Configure VPS'
                : 'Remove from VPS'}
          </button>
        </div>
      </section>
    </div>
  )
}

type SetupItem = { done: boolean; title: string; detail: string; action: string; onClick: () => void }

function SetupDrawer({
  open,
  onToggle,
  steps,
  routes,
  destination,
  direct,
  onManageRoutes,
}: {
  open: boolean
  onToggle: () => void
  steps: SetupItem[]
  routes: string[]
  destination: string
  direct: boolean
  onManageRoutes: () => void
}) {
  const readyCount = steps.filter((step) => step.done).length
  const complete = readyCount === steps.length
  const stack = routes.length
    ? routes.map((name) => ({ name, enabled: true }))
    : [{ name: direct ? 'WireGuard node' : 'WireGuard pool', enabled: false }]
  return (
    <section className={`setup-drawer ${open ? 'is-open' : ''} ${complete ? 'is-complete' : ''}`}>
      <button className="drawer-head" onClick={onToggle} aria-expanded={open}>
        <span className="drawer-icon">{complete ? <Check size={15} /> : <ListChecks size={15} />}</span>
        <span className="drawer-copy">
          <strong>{complete ? 'Setup complete' : `Setup — ${readyCount} of ${steps.length} ready`}</strong>
          <small>
            {direct
              ? 'Node, traffic mode and the current path'
              : 'Routes, traffic mode, relay and the current path chain'}
          </small>
        </span>
        <span className="drawer-pips" aria-hidden="true">
          {steps.map((step) => (
            <i key={step.title} className={step.done ? 'done' : ''} />
          ))}
        </span>
        <span className="drawer-toggle">
          {open ? 'Hide' : 'Show'}
          <ChevronDown size={15} />
        </span>
      </button>
      {open && (
        <div className="drawer-body">
          <div className="setup-list">
            {steps.map((step, index) => (
              <SetupStep
                key={step.title}
                done={step.done}
                number={index + 1}
                title={step.title}
                detail={step.detail}
                action={step.action}
                onClick={step.onClick}
              />
            ))}
          </div>
          <div className="route-preview">
            <div className="section-heading">
              <div>
                <span className="eyebrow">Path overview</span>
                <h2>{direct ? 'Current path' : 'Current route chain'}</h2>
              </div>
              <button className="text-button" onClick={onManageRoutes}>
                Manage <ChevronRight size={14} />
              </button>
            </div>
            <div className="route-map">
              <div className="map-node origin">
                <Gamepad2 size={19} />
                <span>Your game</span>
              </div>
              <div className="map-lines">
                <i />
                <i />
              </div>
              <div className="path-stack">
                {stack.map((item, index) => (
                  <div key={item.name}>
                    <span className={item.enabled ? 'active' : ''}>{index + 1}</span>
                    <p>{item.name}</p>
                    <small>
                      {item.enabled ? (direct ? 'Carrying your traffic' : 'VPN path available') : 'Not configured'}
                    </small>
                  </div>
                ))}
              </div>
              <div className="map-lines inbound">
                <i />
                <i />
              </div>
              <div className="map-node relay">
                {direct ? <Globe2 size={19} /> : <MapPin size={19} />}
                <span>{destination}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
function App() {
  const [state, setState] = useState<AppState | null>(null)
  const [view, setView] = useState<View>('dashboard')
  const [showRuleModal, setShowRuleModal] = useState(false)
  const [showRelayModal, setShowRelayModal] = useState(false)
  const [showAddRelay, setShowAddRelay] = useState(false)
  const [showSocks5Modal, setShowSocks5Modal] = useState(false)
  const [vpsTarget, setVpsTarget] = useState<{ id: string; action: 'provision' | 'remove' } | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [installingService, setInstallingService] = useState(false)
  const [setupOpen, setSetupOpen] = useState<boolean | null>(null)
  const [pathHistories, setPathHistories] = useState<PathHistory>({})
  const [pathRates, setPathRates] = useState<Record<number, PathRate>>({})
  const previousPathCounters = useRef<{ at: number; paths: Record<number, { sent: number; received: number }> } | null>(
    null,
  )

  useEffect(() => {
    api.bootstrap().then(setState)
  }, [])
  useEffect(() => {
    if (state?.session.status !== 'connected') return
    const timer = window.setInterval(() => api.refreshSession().then(setState), 2000)
    return () => window.clearInterval(timer)
  }, [state?.session.status])
  useEffect(() => {
    if (state?.session.status === 'idle') {
      setPathHistories({})
      setPathRates({})
      previousPathCounters.current = null
      return
    }
    const paths = state?.session.pathMetrics
    if (!paths?.length) return
    setPathHistories((current) => {
      const next = { ...current }
      for (const path of paths) {
        if (path.latencyMs == null) continue
        const probe = path.probesReceived ?? 0
        const samples = next[path.route] ?? []
        if (samples.at(-1)?.probe !== probe)
          next[path.route] = [...samples.slice(-59), { latency: path.latencyMs, probe }]
      }
      return next
    })
    const now = performance.now()
    const previous = previousPathCounters.current
    if (previous) {
      const elapsed = Math.max((now - previous.at) / 1000, 0.001)
      setPathRates(
        Object.fromEntries(
          paths.map((path) => {
            const old = previous.paths[path.route]
            return [
              path.route,
              {
                sent: old ? Math.max(0, path.bytesSent - old.sent) / elapsed : 0,
                received: old ? Math.max(0, path.bytesReceived - old.received) / elapsed : 0,
              },
            ]
          }),
        ),
      )
    }
    previousPathCounters.current = {
      at: now,
      paths: Object.fromEntries(
        paths.map((path) => [path.route, { sent: path.bytesSent, received: path.bytesReceived }]),
      ),
    }
  }, [state?.session.pathMetrics, state?.session.status])

  const enabledNodes = state?.tunnels.filter((item) => item.enabled) ?? []
  const enabledRoutes = enabledNodes.length
  const enabledRules = state?.rules.filter((item) => item.enabled).length ?? 0
  const relay = state?.relays.find((item) => item.id === state.activeRelayId)
  const trafficMode = state?.trafficMode ?? 'split'
  const connectionMode = state?.connectionMode ?? 'relay'
  const direct = connectionMode === 'direct'
  const wireguardNodes = state?.tunnels.filter((item) => item.kind === 'wireguard').length ?? 0
  // Direct mode is ready when exactly one node is chosen and that node can
  // actually route, which is the same rule the engine enforces.
  const directNode = enabledRoutes === 1 && enabledNodes[0].kind === 'wireguard' ? enabledNodes[0] : null
  const bestRouteLatency = state?.session.routeLatencies?.length ? Math.min(...state.session.routeLatencies) : null
  const readiness = useMemo(
    () => ({
      routes: direct ? directNode != null : enabledRoutes >= 1,
      rules: trafficMode === 'all' || enabledRules >= 1,
      ...(direct ? {} : { relay: relay?.status === 'ready' }),
    }),
    [direct, directNode, enabledRoutes, enabledRules, relay, trafficMode],
  )
  const readyCount = Object.values(readiness).filter(Boolean).length
  const stepCount = Object.keys(readiness).length
  // Point at the mode the user's current setup can actually start in.
  const recommendedMode: ConnectionMode | null =
    relay?.status === 'ready' ? 'relay' : wireguardNodes > 0 ? 'direct' : null

  if (!state)
    return (
      <div className="loading">
        <div className="brand-mark">
          <Zap size={22} />
        </div>
        <span>Loading GamePath…</span>
      </div>
    )
  const engineState = state.engine ?? {
    status: 'offline' as const,
    version: '',
    message: 'Native engine is starting',
    capabilities: null,
  }
  const serviceState = state.service ?? {
    status: 'not-installed' as const,
    version: '',
    message: 'Network service is not installed',
    elevated: false,
  }

  const activeRouteNames = enabledNodes.map((tunnel) => tunnel.name)
  const setupSteps: SetupItem[] = [
    {
      done: readiness.routes,
      title: direct ? 'Choose a WireGuard node' : 'Add a WireGuard route',
      detail: direct
        ? directNode
          ? `${directNode.name} will carry your traffic`
          : `${wireguardNodes} WireGuard node${wireguardNodes === 1 ? '' : 's'} added; pick exactly one`
        : `${state.tunnels.length} node${state.tunnels.length === 1 ? '' : 's'} added; the relay is reached only through enabled nodes`,
      action: 'Configure',
      onClick: () => setView('routes'),
    },
    {
      done: readiness.rules,
      title: 'Choose traffic mode',
      detail:
        state.trafficMode === 'all'
          ? 'All system traffic'
          : `${enabledRules} active split-tunnel target${enabledRules === 1 ? '' : 's'}`,
      action: 'Configure',
      onClick: () => setView('split'),
    },
    // Direct mode has no relay to set up, so the step is not shown greyed out
    // and unreachable — it simply is not part of this setup.
    ...(direct
      ? []
      : [
          {
            done: readiness.relay === true,
            title: 'Configure a relay',
            detail: relay ? `${relay.city}, ${relay.country}` : 'No relay selected',
            action: 'Set up',
            onClick: () => setView('relays'),
          },
        ]),
  ]

  const importTunnels = async () => {
    const result = await api.importWireGuard()
    if (result.state) setState(result.state)
    if (result.errors?.length) setNotice(result.errors.join('\n'))
  }

  const addSocks5Node = async (input: Socks5NodeInput) => {
    const result = await api.addSocks5Node(input)
    setState(result.state)
    setShowSocks5Modal(false)
  }

  const toggleSession = async () => {
    if (state.session.status !== 'connected') {
      setState({ ...state, session: { status: 'starting' } })
    }
    const next = state.session.status === 'connected' ? await api.stopSession() : await api.startSession()
    setState(next)
    if (next.session.message) setNotice(next.session.message)
  }

  const title: Record<View, [string, string]> = {
    dashboard: ['Overview', 'Session control and live route telemetry.'],
    routes: ['Routes and nodes', 'Import WireGuard configurations and add SOCKS5 proxies GamePath can use.'],
    split: ['Split tunnel', 'Choose exactly which traffic should enter the multipath tunnel.'],
    relays: ['Connection', 'Choose how your traffic leaves this PC.'],
    settings: ['Settings', 'Control startup, diagnostics, and client behavior.'],
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">
            <Zap size={19} fill="currentColor" />
          </span>
          <span>
            GAME<strong>PATH</strong>
          </span>
          <em>ALPHA</em>
        </div>
        <nav>
          <span className="nav-caption">Workspace</span>
          {navItems.map((item) => {
            const Icon = item.icon
            return (
              <button key={item.id} className={view === item.id ? 'active' : ''} onClick={() => setView(item.id)}>
                <Icon size={18} />
                <span>{item.label}</span>
                {item.id === 'routes' && state.tunnels.length > 0 && <b>{state.tunnels.length}</b>}
              </button>
            )
          })}
        </nav>
        <div className="sidebar-bottom">
          <button className={view === 'settings' ? 'active' : ''} onClick={() => setView('settings')}>
            <Settings size={18} />
            Settings
          </button>
          <div className="client-card">
            <span>
              <ShieldCheck size={16} />
            </span>
            <div>
              <strong>Local protection</strong>
              <small>Keys secured by Windows</small>
            </div>
          </div>
          <div className="version">
            Client {state.clientVersion ?? 'development'} <i /> Alpha build
          </div>
        </div>
      </aside>

      <main>
        <header className="topbar">
          <div>
            <span className="eyebrow">GamePath client</span>
            <h1>{title[view][0]}</h1>
            <p>{title[view][1]}</p>
          </div>
          <div className={`topbar-status ${engineState.status}`}>
            <span className="pulse-dot" />{' '}
            {engineState.status === 'ready' ? `Engine ${engineState.version} ready` : engineState.message}
          </div>
        </header>

        <div className="content">
          {view === 'dashboard' && (
            <div className="dashboard-grid">
              <section className={`command-bar ${state.session.status === 'connected' ? 'is-live' : ''}`}>
                <div className="command-identity">
                  <span className="command-core">
                    <Zap size={22} fill="currentColor" />
                  </span>
                  <div>
                    <span className="eyebrow">{direct ? 'Direct session' : 'Multipath session'}</span>
                    <h2>
                      {state.session.status === 'connected'
                        ? direct
                          ? 'Traffic is routing'
                          : 'Paths connected'
                        : readyCount === stepCount
                          ? 'Ready to accelerate'
                          : 'Complete your setup'}
                    </h2>
                    <p>
                      {state.session.status === 'connected'
                        ? direct
                          ? `Selected traffic is going through ${directNode?.name ?? 'your node'}.`
                          : `${enabledRoutes} encrypted paths active through ${relay?.city ?? 'the relay'}.`
                        : readyCount === stepCount
                          ? direct
                            ? `${directNode?.name ?? 'Your node'} will carry your selected traffic.`
                            : `${enabledRoutes} routes will carry game traffic through ${relay?.city ?? 'the relay'}.`
                          : `${readyCount} of ${stepCount} requirements ready — open Setup below.`}
                    </p>
                  </div>
                </div>
                <div className="command-stats">
                  <div>
                    <span className="stat-icon cyan">
                      <Route size={16} />
                    </span>
                    <p>{direct ? 'Active node' : 'Active routes'}</p>
                    <strong>
                      {enabledRoutes}
                      <small> / {state.tunnels.length}</small>
                    </strong>
                  </div>
                  <div>
                    <span className="stat-icon violet">
                      <CircleGauge size={16} />
                    </span>
                    <p>{direct ? 'Node latency' : 'Best route'}</p>
                    <strong>
                      {bestRouteLatency ?? '—'}
                      <small> ms</small>
                    </strong>
                  </div>
                  <div>
                    <span className="stat-icon green">
                      <Activity size={16} />
                    </span>
                    <p>Packet loss</p>
                    <strong>
                      {state.session.metrics ? state.session.metrics.packetLossPercent.toFixed(1) : '—'}
                      <small> %</small>
                    </strong>
                  </div>
                </div>
                <div className="command-action">
                  <button
                    className={`connect-button ${state.session.status === 'connected' ? 'connected' : ''}`}
                    disabled={state.session.status === 'starting'}
                    onClick={toggleSession}
                  >
                    <Power size={17} />
                    <span>
                      {state.session.status === 'starting'
                        ? 'Starting…'
                        : state.session.status === 'connected'
                          ? 'Stop session'
                          : 'Start session'}
                    </span>
                  </button>
                  {/* Which mode is live, and the way back to changing it. */}
                  <button className="session-mode" onClick={() => setView('relays')}>
                    {direct ? <Waypoints size={12} /> : <Sparkles size={12} />}
                    {direct ? 'Direct · one node' : 'Relay · adaptive duplication'}
                    <ChevronRight size={12} />
                  </button>
                </div>
              </section>

              <SetupDrawer
                open={setupOpen ?? readyCount < stepCount}
                onToggle={() => setSetupOpen(!(setupOpen ?? readyCount < stepCount))}
                steps={setupSteps}
                routes={activeRouteNames}
                destination={direct ? 'Game server' : (relay?.city ?? 'Relay')}
                direct={direct}
                onManageRoutes={() => setView('routes')}
              />

              <TelemetryPanel state={state} histories={pathHistories} rates={pathRates} />
            </div>
          )}

          {view === 'routes' && (
            <section className="page-section">
              <div className="toolbar">
                <div>
                  <span className="count-badge">
                    {direct ? (directNode ? '1 chosen' : 'None chosen') : `${enabledRoutes} active`}
                  </span>
                  <span className="muted">
                    {direct
                      ? 'Direct mode sends your traffic through one WireGuard node, which routes it onward. SOCKS5 proxies need a relay on the other side.'
                      : 'Each active node carries relay traffic through its own hop, a WireGuard tunnel or a SOCKS5 proxy. Direct ISP relay access is disabled.'}
                  </span>
                </div>
                <div className="toolbar-actions">
                  {/* Adding a proxy in direct mode would only produce a node
                      that cannot be started, so it is offered in relay mode. */}
                  {!direct && (
                    <button className="button secondary" onClick={() => setShowSocks5Modal(true)}>
                      <Share2 size={16} />
                      Add SOCKS5
                    </button>
                  )}
                  <button className="button primary" onClick={importTunnels}>
                    <Import size={16} />
                    Import .conf
                  </button>
                </div>
              </div>
              {state.tunnels.length ? (
                <div className="route-list">
                  {state.tunnels.map((tunnel) => (
                    <Endpoint
                      key={tunnel.id}
                      tunnel={tunnel}
                      direct={direct}
                      onToggle={async (enabled) => setState(await api.setTunnelEnabled(tunnel.id, enabled))}
                      onRemove={async () => setState(await api.removeTunnel(tunnel.id))}
                    />
                  ))}
                </div>
              ) : (
                <div className="empty-state">
                  <span>
                    <HardDrive size={28} />
                  </span>
                  <h2>No nodes yet</h2>
                  <p>
                    {direct
                      ? 'Import the WireGuard configuration file from your VPN provider. Direct mode routes through it, so it is all you need. Private keys are encrypted using Windows secure storage.'
                      : 'Import your purchased WireGuard configuration files, or add a SOCKS5 proxy that supports UDP. Private keys and proxy passwords are encrypted using Windows secure storage.'}
                  </p>
                  <div className="empty-actions">
                    <button className="button primary" onClick={importTunnels}>
                      <Import size={16} />
                      Import configurations
                    </button>
                    {/* A proxy cannot carry a direct session, so offering one
                        here would only lead to a node that will not start. */}
                    {!direct && (
                      <button className="button secondary" onClick={() => setShowSocks5Modal(true)}>
                        <Share2 size={16} />
                        Add a SOCKS5 proxy
                      </button>
                    )}
                  </div>
                </div>
              )}
              <div className="info-banner">
                <ShieldCheck size={18} />
                <div>
                  <strong>Your private keys stay on this PC</strong>
                  <p>GamePath only decrypts a configuration when the local routing engine needs it.</p>
                </div>
              </div>
            </section>
          )}

          {view === 'split' && (
            <section className="page-section">
              <div className="traffic-mode-card">
                <div>
                  <span className="eyebrow">Routing scope</span>
                  <h2>Choose what enters GamePath</h2>
                  <p>Switch modes at any time before starting a session.</p>
                </div>
                <div className="segmented-control" role="group" aria-label="Traffic routing mode">
                  <button
                    className={state.trafficMode === 'split' ? 'active' : ''}
                    onClick={async () => setState(await api.setTrafficMode('split'))}
                  >
                    <Gamepad2 size={15} />
                    <span>
                      Split tunnel<small>Selected targets</small>
                    </span>
                  </button>
                  <button
                    className={state.trafficMode === 'all' ? 'active' : ''}
                    onClick={async () => setState(await api.setTrafficMode('all'))}
                  >
                    <Globe2 size={15} />
                    <span>
                      All traffic<small>Whole system</small>
                    </span>
                  </button>
                </div>
              </div>
              {state.trafficMode === 'all' && (
                <div className="all-traffic-banner">
                  <Globe2 size={19} />
                  <div>
                    <strong>All-traffic mode is active</strong>
                    <p>
                      Every compatible connection on this PC will use the multipath relay. The rules below are saved but
                      ignored.
                    </p>
                  </div>
                </div>
              )}
              <div className="toolbar">
                <div>
                  <span className="count-badge">{enabledRules} active</span>
                  <span className="muted">Rules are matched from most specific to least specific.</span>
                </div>
                <button className="button primary" onClick={() => setShowRuleModal(true)}>
                  <Plus size={16} />
                  Add target
                </button>
              </div>
              <div className={state.trafficMode === 'all' ? 'rules-disabled' : ''}>
                {state.rules.length ? (
                  <div className="rules-table">
                    <div className="table-head">
                      <span>Target</span>
                      <span>Type</span>
                      <span>Destination</span>
                      <span>Status</span>
                      <span />
                    </div>
                    {state.rules.map((rule) => {
                      const Icon =
                        rule.kind === 'application'
                          ? AppWindow
                          : rule.kind === 'folder'
                            ? FolderOpen
                            : rule.kind === 'hostname'
                              ? Globe2
                              : Network
                      return (
                        <div className="table-row" key={rule.id}>
                          <span className="target-cell">
                            <i>
                              <Icon size={16} />
                            </i>
                            <strong>{rule.label}</strong>
                          </span>
                          <span className="kind-label">{rule.kind}</span>
                          <span className="truncate">{rule.value}</span>
                          <span>
                            <Toggle
                              checked={rule.enabled}
                              onChange={async (enabled) => setState(await api.setRuleEnabled(rule.id, enabled))}
                              label={`${rule.enabled ? 'Disable' : 'Enable'} ${rule.label}`}
                            />
                          </span>
                          <button
                            className="icon-button danger"
                            onClick={async () => setState(await api.removeRule(rule.id))}
                          >
                            <Trash2 size={16} />
                          </button>
                        </div>
                      )
                    })}
                  </div>
                ) : (
                  <div className="empty-state">
                    <span>
                      <Network size={28} />
                    </span>
                    <h2>No traffic targets</h2>
                    <p>Add a game executable, installation folder, hostname, or IP range.</p>
                    <button className="button primary" onClick={() => setShowRuleModal(true)}>
                      <Plus size={16} />
                      Add first target
                    </button>
                  </div>
                )}
              </div>
            </section>
          )}

          {view === 'relays' && (
            <section className="page-section">
              <ConnectionModes
                mode={connectionMode}
                recommended={recommendedMode}
                onSelect={async (next) => {
                  if (next === connectionMode) return
                  setState(await api.setConnectionMode(next))
                }}
                onSetUpRelay={async () => setState(await api.setConnectionMode('relay'))}
              />
              <div className={`relay-section ${direct ? 'is-inactive' : ''}`}>
                {direct && (
                  <p className="relay-section-note">
                    <Info size={14} /> Relays are kept here for when you switch back. Direct mode does not use them.
                  </p>
                )}
                <div className="relay-intro">
                  <div>
                    <span className="eyebrow">Relay fleet</span>
                    <h2>
                      {state.relays.length} server{state.relays.length === 1 ? '' : 's'}
                    </h2>
                    <p>Add your VPS locations and enable one relay at a time.</p>
                    <button className="button primary" onClick={() => setShowAddRelay(true)}>
                      <Plus size={16} />
                      Add VPS relay
                    </button>
                  </div>
                  <div className="flag-orb">{relay?.code ?? 'GP'}</div>
                </div>
                <div className="relay-grid">
                  {state.relays.map((item) => (
                    <article
                      key={item.id}
                      className={`relay-card ${state.activeRelayId === item.id ? 'selected' : ''}`}
                    >
                      <button className="relay-choice" onClick={async () => setState(await api.setRelay(item.id))}>
                        <span className="relay-radio">{state.activeRelayId === item.id && <Check size={14} />}</span>
                        <div className="relay-location">
                          <span>
                            <MapPin size={19} />
                          </span>
                          <div>
                            <strong>{item.city}</strong>
                            <small>
                              {item.address ? `${item.address}:${item.port}` : `${item.country} · VPS not configured`}
                            </small>
                          </div>
                        </div>
                        <div className="relay-stat">
                          <small>Latency</small>
                          <strong>
                            {item.latency ?? '—'}
                            <em> ms</em>
                          </strong>
                        </div>
                        <div className={`relay-status ${item.status}`}>
                          <i />
                          {state.activeRelayId === item.id
                            ? 'Enabled'
                            : item.status === 'ready'
                              ? 'Disabled'
                              : 'Setup required'}
                        </div>
                      </button>
                      <div className="relay-actions">
                        {item.status === 'ready' && (
                          <button
                            className="button secondary"
                            onClick={async () => {
                              try {
                                const tested = await api.testRelay(item.id)
                                setState(tested.state)
                                setNotice(
                                  `Authenticated relay ready · ${Math.round(tested.result.latencyMs)} ms · ${tested.result.virtualIpv4}`,
                                )
                              } catch (error) {
                                setNotice(error instanceof Error ? error.message : String(error))
                              }
                            }}
                          >
                            Test
                          </button>
                        )}
                        <button
                          className="button primary"
                          onClick={() => setVpsTarget({ id: item.id, action: 'provision' })}
                        >
                          {item.status === 'ready' ? 'Update VPS' : 'Auto-configure VPS'}
                        </button>
                        <button
                          className="button secondary relay-configure"
                          onClick={() => {
                            setState({ ...state, activeRelayId: item.id })
                            setShowRelayModal(true)
                          }}
                        >
                          Manual
                        </button>
                        {item.status === 'ready' && (
                          <button
                            className="button secondary"
                            onClick={() => setVpsTarget({ id: item.id, action: 'remove' })}
                          >
                            Remove VPS
                          </button>
                        )}
                        <button
                          className="icon-button danger"
                          aria-label={`Delete ${item.city}`}
                          onClick={async () => setState(await api.removeRelayLocal(item.id))}
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </article>
                  ))}
                </div>
                <div className="coming-regions">
                  <span>More regions are planned</span>
                  <div>
                    <i>DE</i>
                    <i>NL</i>
                    <i>AE</i>
                  </div>
                </div>
              </div>
            </section>
          )}

          {view === 'settings' && (
            <section className="page-section settings-list">
              <div className="settings-card">
                <div>
                  <span className="setting-icon">
                    <Zap size={18} />
                  </span>
                  <div>
                    <strong>Adaptive duplication</strong>
                    <p>
                      {direct
                        ? 'Needs relay mode: duplicating a packet only helps when a second path can carry the copy.'
                        : 'Duplicate latency-sensitive packets when route quality becomes unstable.'}
                    </p>
                  </div>
                </div>
                <Toggle checked={!direct} disabled={direct} onChange={() => undefined} label="Adaptive duplication" />
              </div>
              <div className="settings-card">
                <div>
                  <span className="setting-icon">
                    <Link2 size={18} />
                  </span>
                  <div>
                    <strong>Start with Windows</strong>
                    <p>Open GamePath in the background after signing in.</p>
                  </div>
                </div>
                <Toggle checked={false} onChange={() => undefined} label="Start with Windows" />
              </div>
              <div className="settings-card">
                <div>
                  <span className="setting-icon">
                    <Activity size={18} />
                  </span>
                  <div>
                    <strong>Local diagnostics</strong>
                    <p>Keep route latency and packet-loss history for troubleshooting.</p>
                  </div>
                </div>
                <Toggle checked={true} onChange={() => undefined} label="Local diagnostics" />
              </div>
              <div className="settings-card capability-card">
                <div>
                  <span className="setting-icon">
                    <ShieldCheck size={18} />
                  </span>
                  <div>
                    <strong>Windows network capabilities</strong>
                    <p>
                      WireGuard {engineState.capabilities?.wireGuardInstalled ? 'detected' : 'not found'} · Wintun
                      library {engineState.capabilities?.packetAdapter?.libraryLoaded ? 'ready' : 'missing'} · Driver{' '}
                      {engineState.capabilities?.packetAdapterInstalled ? 'active' : 'not created'}
                    </p>
                  </div>
                </div>
                <span className={`status-pill ${engineState.status === 'ready' ? 'online' : ''}`}>
                  <i />
                  {engineState.status}
                </span>
              </div>
              <div className="settings-card capability-card">
                <div>
                  <span className="setting-icon">
                    <Network size={18} />
                  </span>
                  <div>
                    <strong>Split-tunnel interception</strong>
                    <p>
                      WFP backend{' '}
                      {engineState.capabilities?.interception?.libraryLoaded &&
                      engineState.capabilities?.interception?.driverAvailable
                        ? 'ready'
                        : 'missing'}{' '}
                      · Winsock transport · Administrator service required to activate
                    </p>
                  </div>
                </div>
                <span
                  className={`status-pill ${engineState.capabilities?.interception?.libraryLoaded ? 'online' : ''}`}
                >
                  <i />
                  WFP
                </span>
              </div>
              <div className="settings-card capability-card">
                <div>
                  <span className="setting-icon">
                    <Server size={18} />
                  </span>
                  <div>
                    <strong>GamePath Network Service</strong>
                    <p>
                      {serviceState.message}
                      {serviceState.version ? ` · Version ${serviceState.version}` : ''}
                    </p>
                  </div>
                </div>
                <div className="service-actions">
                  <button
                    className={serviceState.status === 'ready' ? 'button secondary' : 'button primary'}
                    disabled={installingService}
                    onClick={async () => {
                      setInstallingService(true)
                      try {
                        setState(await api.installService())
                        setNotice('GamePath Network Service installed and running.')
                      } catch (error) {
                        setNotice(error instanceof Error ? error.message : String(error))
                      } finally {
                        setInstallingService(false)
                      }
                    }}
                  >
                    {installingService
                      ? 'Installing…'
                      : serviceState.status === 'ready'
                        ? 'Reinstall service'
                        : 'Install service'}
                  </button>
                  <button
                    className="button secondary"
                    disabled={installingService}
                    onClick={async () => setState(await api.refreshService())}
                  >
                    Refresh status
                  </button>
                  <span className={`status-pill ${serviceState.status === 'ready' ? 'online' : ''}`}>
                    <i />
                    {serviceState.status}
                  </span>
                </div>
              </div>
            </section>
          )}
        </div>
      </main>

      {showRuleModal && (
        <RuleModal
          onClose={() => setShowRuleModal(false)}
          onSave={async (input) => {
            setState(await api.addRule(input))
            setShowRuleModal(false)
          }}
        />
      )}
      {showSocks5Modal && (
        <Socks5Modal
          onClose={() => setShowSocks5Modal(false)}
          onAdd={addSocks5Node}
          onTest={(input) => api.testSocks5Node(input)}
        />
      )}
      {showRelayModal && relay && (
        <RelayModal
          relay={relay}
          onClose={() => setShowRelayModal(false)}
          onImport={async () => {
            try {
              const result = await api.importRelayEnrollment(relay.id)
              if (result.state) setState(result.state)
            } catch (error) {
              setNotice(error instanceof Error ? error.message : String(error))
            }
          }}
          onSave={async (input) => {
            try {
              setState(await api.configureRelay(relay.id, input))
              setShowRelayModal(false)
            } catch (error) {
              setNotice(error instanceof Error ? error.message : String(error))
            }
          }}
        />
      )}
      {showAddRelay && (
        <AddRelayModal
          onClose={() => setShowAddRelay(false)}
          onAdd={async (input) => {
            const result = await api.addRelay(input)
            setState(result.state)
            setShowAddRelay(false)
            setVpsTarget({ id: result.relayId, action: 'provision' })
          }}
        />
      )}
      {vpsTarget &&
        (() => {
          const target = state.relays.find((item) => item.id === vpsTarget.id)
          return target ? (
            <VpsModal
              relay={target}
              action={vpsTarget.action}
              onClose={() => setVpsTarget(null)}
              onSubmit={async (input) => {
                try {
                  const next =
                    vpsTarget.action === 'provision'
                      ? await api.provisionRelayVps(target.id, input)
                      : await api.removeRelayVps(target.id, input)
                  setState(next)
                  setNotice(
                    vpsTarget.action === 'provision'
                      ? 'VPS configured and enrollment protected by Windows.'
                      : 'GamePath was removed from the VPS.',
                  )
                  setVpsTarget(null)
                } catch (error) {
                  setNotice(error instanceof Error ? error.message : String(error))
                }
              }}
            />
          ) : null
        })()}
      {notice && (
        <div className="toast">
          <Info size={17} />
          <span>{notice}</span>
          <button onClick={() => setNotice(null)}>
            <X size={15} />
          </button>
        </div>
      )}
    </div>
  )
}

export default App
