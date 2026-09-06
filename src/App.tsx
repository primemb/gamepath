import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  AppWindow,
  ArrowDownRight,
  ArrowUpRight,
  Check,
  ChevronRight,
  CircleGauge,
  FolderOpen,
  Gamepad2,
  Globe2,
  HardDrive,
  Import,
  Info,
  LayoutDashboard,
  Link2,
  MapPin,
  Network,
  Plus,
  Radio,
  Route,
  Server,
  Settings,
  ShieldCheck,
  Sparkles,
  Trash2,
  X,
  Zap,
} from 'lucide-react'
import { mockApi } from './mockApi'
import type { AddRuleInput, AppState, GamePathApi, Relay, RuleKind, Tunnel } from './types'

type View = 'dashboard' | 'routes' | 'split' | 'relays' | 'settings'

const api: GamePathApi = window.gamepath ?? mockApi

const navItems: { id: View; label: string; icon: typeof LayoutDashboard }[] = [
  { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
  { id: 'routes', label: 'WireGuard routes', icon: Route },
  { id: 'split', label: 'Split tunnel', icon: Network },
  { id: 'relays', label: 'Relay servers', icon: Server },
]

function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (next: boolean) => void; label: string }) {
  return (
    <button className={`toggle ${checked ? 'is-on' : ''}`} onClick={() => onChange(!checked)} aria-label={label} aria-pressed={checked}>
      <span />
    </button>
  )
}

function Endpoint({ tunnel, onToggle, onRemove }: { tunnel: Tunnel; onToggle: (enabled: boolean) => void; onRemove: () => void }) {
  return (
    <article className={`route-card ${tunnel.enabled ? 'is-enabled' : ''}`}>
      <div className="route-state-icon"><Radio size={18} /></div>
      <div className="route-copy">
        <div className="route-title-row">
          <h3>{tunnel.name}</h3>
          <span className={`status-pill ${tunnel.enabled ? 'online' : ''}`}>
            <i /> {tunnel.enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>
        <p>{tunnel.endpoint}</p>
        <div className="route-meta">
          <span>Address <strong>{tunnel.address}</strong></span>
          <span>DNS <strong>{tunnel.dns}</strong></span>
          <span><ShieldCheck size={13} /> Key protected</span>
        </div>
      </div>
      <div className="route-actions">
        <Toggle checked={tunnel.enabled} onChange={onToggle} label={`${tunnel.enabled ? 'Disable' : 'Enable'} ${tunnel.name}`} />
        <button className="icon-button danger" onClick={onRemove} aria-label={`Remove ${tunnel.name}`}><Trash2 size={16} /></button>
      </div>
    </article>
  )
}

function SetupStep({ done, number, title, detail, action, onClick }: { done: boolean; number: number; title: string; detail: string; action: string; onClick: () => void }) {
  return (
    <button className={`setup-step ${done ? 'complete' : ''}`} onClick={onClick}>
      <span className="step-number">{done ? <Check size={15} /> : number}</span>
      <span className="step-copy"><strong>{title}</strong><small>{detail}</small></span>
      <span className="step-action">{done ? 'Ready' : action}<ChevronRight size={15} /></span>
    </button>
  )
}

const formatMetric = (value: number | null | undefined) => value == null ? '—' : `${Math.round(value)} ms`
const formatBytes = (bytes: number | undefined) => {
  const value = bytes ?? 0
  if (value < 1024) return `${value} B`
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`
  return `${(value / 1024 ** 2).toFixed(2)} MB`
}

function LatencyChart({ values }: { values: number[] }) {
  const samples = values.length > 1 ? values : [values[0] ?? 0, values[0] ?? 0]
  const maximum = Math.max(...samples, 1)
  const minimum = Math.min(...samples)
  const spread = Math.max(maximum - minimum, 8)
  const points = samples.map((value, index) => {
    const x = (index / (samples.length - 1)) * 300
    const y = 62 - ((value - minimum) / spread) * 48
    return `${x},${y}`
  }).join(' ')
  return <svg className="latency-chart" viewBox="0 0 300 70" preserveAspectRatio="none" role="img" aria-label="End-to-end ping history"><defs><linearGradient id="latencyFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#26e6cd" stopOpacity=".25" /><stop offset="1" stopColor="#26e6cd" stopOpacity="0" /></linearGradient></defs><polygon points={`0,70 ${points} 300,70`} fill="url(#latencyFill)" /><polyline points={points} fill="none" stroke="#26e6cd" strokeWidth="2" vectorEffect="non-scaling-stroke" /></svg>
}

function TelemetryPanel({ state, history }: { state: AppState; history: number[] }) {
  const metrics = state.session.metrics
  const stages = [
    ['User → VPN node', metrics?.userToNodeMs, 'WireGuard handshake RTT'],
    ['Node → relay', metrics?.nodeToRelayMs, 'Tunnel segment estimate'],
    ['Relay → server', metrics?.relayToServerMs, metrics?.benchmarkServer ? `Benchmark ${metrics.benchmarkServer}` : 'Awaiting target'],
  ] as const
  return <section className="telemetry-panel">
    <div className="telemetry-head"><div><span className="eyebrow">Live telemetry</span><h2>Network journey</h2></div><span className={`status-pill ${state.session.status === 'connected' ? 'online' : ''}`}><i />{state.session.status === 'connected' ? 'Live' : 'Waiting'}</span></div>
    <div className="journey-grid">{stages.map(([label, value, detail], index) => <div className="journey-stage" key={label}><span>{index + 1}</span><div><small>{label}</small><strong>{formatMetric(value)}</strong><em>{detail}</em></div></div>)}</div>
    <div className="telemetry-lower">
      <div className="chart-card"><div><span>End-to-end ping</span><strong>{formatMetric(metrics?.endToEndMs)}</strong></div><LatencyChart values={history} /></div>
      <div className="transfer-grid"><div><ArrowUpRight size={16} /><span>Data sent<strong>{formatBytes(metrics?.bytesSent)}</strong></span></div><div><ArrowDownRight size={16} /><span>Data received<strong>{formatBytes(metrics?.bytesReceived)}</strong></span></div><div><Activity size={16} /><span>Packet loss<strong>{metrics ? `${metrics.packetLossPercent.toFixed(1)}%` : '—'}</strong></span></div><div><Radio size={16} /><span>Packets<strong>{metrics ? `${metrics.packetsReceived} / ${metrics.packetsSent}` : '—'}</strong></span></div></div>
    </div>
  </section>
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
      <section className="modal" onMouseDown={(event) => event.stopPropagation()} role="dialog" aria-modal="true" aria-label="Add split tunnel target">
        <div className="modal-head">
          <div><span className="eyebrow">Traffic rule</span><h2>Add a split-tunnel target</h2></div>
          <button className="icon-button" onClick={onClose}><X size={18} /></button>
        </div>
        <p className="modal-intro">Only matching traffic will use GamePath. Everything else stays on your normal connection.</p>
        <div className="kind-grid">
          {kinds.map((item) => {
            const Icon = item.icon
            return <button key={item.id} className={kind === item.id ? 'active' : ''} onClick={() => { setKind(item.id); setValue(''); setLabel('') }}><Icon size={17} />{item.label}</button>
          })}
        </div>
        {(kind === 'application' || kind === 'folder') ? (
          <button className="file-drop" onClick={browse}>
            <span className="file-drop-icon"><FolderOpen size={22} /></span>
            <strong>{value ? label : `Choose ${kind === 'application' ? 'an executable' : 'a folder'}`}</strong>
            <small>{value || (kind === 'application' ? 'Select the game .exe file' : 'All applications inside will match')}</small>
          </button>
        ) : (
          <label className="field-label">{kind === 'hostname' ? 'Hostname' : 'IP or CIDR range'}
            <input autoFocus value={value} onChange={(event) => { setValue(event.target.value); setLabel(event.target.value) }} placeholder={placeholder} />
          </label>
        )}
        <div className="modal-actions">
          <button className="button secondary" onClick={onClose}>Cancel</button>
          <button className="button primary" disabled={!value.trim()} onClick={() => onSave({ kind, value, label: label || value })}><Plus size={16} />Add target</button>
        </div>
      </section>
    </div>
  )
}

function RelayModal({ relay, onClose, onSave, onImport }: { relay: Relay; onClose: () => void; onSave: (input: { address: string; port: number; enrollmentToken?: string }) => Promise<void>; onImport: () => Promise<void> }) {
  const [address, setAddress] = useState(relay.address)
  const [port, setPort] = useState(String(relay.port || 51821))
  const [enrollmentToken, setEnrollmentToken] = useState('')
  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section className="modal relay-modal" onMouseDown={(event) => event.stopPropagation()} role="dialog" aria-modal="true" aria-label="Configure relay">
        <div className="modal-head">
          <div><span className="eyebrow">{relay.city}, {relay.country}</span><h2>Configure relay endpoint</h2></div>
          <button className="icon-button" onClick={onClose}><X size={18} /></button>
        </div>
        <p className="modal-intro">Set the public endpoint and its unique client credential. The credential is encrypted by Windows and is never shown again after saving.</p>
        <div className="relay-fields">
          <label className="field-label">Hostname or IP address<input autoFocus value={address} onChange={(event) => setAddress(event.target.value)} placeholder="relay.example.com" /></label>
          <label className="field-label port-field">UDP port<input value={port} onChange={(event) => setPort(event.target.value.replace(/\D/g, '').slice(0, 5))} placeholder="51821" /></label>
        </div>
        <label className="field-label enrollment-field">Enrollment token
          <input type="password" value={enrollmentToken} onChange={(event) => setEnrollmentToken(event.target.value)} placeholder={relay.hasEnrollmentToken ? 'Credential already protected — leave blank to keep it' : 'Paste gpe1_… token'} />
        </label>
        <button className="file-import-button" onClick={onImport}><ShieldCheck size={15} />Import a .enroll file<span>{relay.hasEnrollmentToken ? 'Credential protected' : 'Recommended'}</span></button>
        <div className="modal-actions">
          <button className="button secondary" onClick={onClose}>Cancel</button>
          <button className="button primary" disabled={!address.trim() || !port || (!relay.hasEnrollmentToken && !enrollmentToken.trim())} onClick={() => onSave({ address: address.trim(), port: Number(port), enrollmentToken: enrollmentToken.trim() || undefined })}><Check size={16} />Save relay</button>
        </div>
      </section>
    </div>
  )
}

function AddRelayModal({ onClose, onAdd }: { onClose: () => void; onAdd: (input: { city: string; country: string }) => Promise<void> }) {
  const [city, setCity] = useState('Istanbul')
  const [country, setCountry] = useState('Turkey')
  return <div className="modal-backdrop" onMouseDown={onClose}><section className="modal relay-modal" onMouseDown={(event) => event.stopPropagation()}><div className="modal-head"><div><span className="eyebrow">New location</span><h2>Add relay server</h2></div><button className="icon-button" onClick={onClose}><X size={18} /></button></div><div className="relay-fields"><label className="field-label">City or label<input autoFocus value={city} onChange={(event) => setCity(event.target.value)} /></label><label className="field-label">Country<input value={country} onChange={(event) => setCountry(event.target.value)} /></label></div><div className="modal-actions"><button className="button secondary" onClick={onClose}>Cancel</button><button className="button primary" disabled={!city.trim() || !country.trim()} onClick={() => onAdd({ city: city.trim(), country: country.trim() })}><Plus size={16} />Add relay</button></div></section></div>
}

function VpsModal({ relay, action, onClose, onSubmit }: { relay: Relay; action: 'provision' | 'remove'; onClose: () => void; onSubmit: (input: { host: string; sshPort: number; username: string; password: string; relayPort: number }) => Promise<void> }) {
  const [host, setHost] = useState(relay.address)
  const [sshPort, setSshPort] = useState('22')
  const [username, setUsername] = useState('root')
  const [password, setPassword] = useState('')
  const [relayPort, setRelayPort] = useState(String(relay.port || 51821))
  const [busy, setBusy] = useState(false)
  const [progress, setProgress] = useState({ percent: 0, message: 'Preparing deployment' })
  useEffect(() => api.onRelayVpsProgress((update) => { if (update.relayId === relay.id) setProgress(update) }), [relay.id])
  return <div className="modal-backdrop" onMouseDown={busy ? undefined : onClose}><section className="modal relay-modal" onMouseDown={(event) => event.stopPropagation()}><div className="modal-head"><div><span className="eyebrow">Secure SSH setup</span><h2>{action === 'provision' ? 'Configure Debian VPS' : 'Remove relay from VPS'}</h2></div><button className="icon-button" disabled={busy} onClick={onClose}><X size={18} /></button></div><p className="modal-intro">{action === 'provision' ? 'GamePath uploads its relay source, installs dependencies, configures the service and firewall, then imports this PC’s enrollment automatically.' : 'This removes the GamePath service, firewall tables, configuration, clients, and binary from this server.'} The SSH password is used only for this operation and is never saved.</p><div className="relay-fields"><label className="field-label">VPS hostname or IP<input autoFocus value={host} onChange={(event) => setHost(event.target.value)} placeholder="203.0.113.10" /></label><label className="field-label port-field">SSH port<input value={sshPort} onChange={(event) => setSshPort(event.target.value.replace(/\D/g, '').slice(0, 5))} /></label></div><div className="relay-fields"><label className="field-label">SSH username<input value={username} onChange={(event) => setUsername(event.target.value)} /></label><label className="field-label">SSH password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label></div>{action === 'provision' && <label className="field-label enrollment-field">Relay UDP port<input value={relayPort} onChange={(event) => setRelayPort(event.target.value.replace(/\D/g, '').slice(0, 5))} /></label>}{busy && <div className="vps-progress"><div><strong>{progress.message}</strong><span>{progress.percent}%</span></div><i><b style={{ width: `${progress.percent}%` }} /></i><small>Keep GamePath open. A first-time Rust build can take several minutes.</small></div>}<div className="modal-actions"><button className="button secondary" disabled={busy} onClick={onClose}>Cancel</button><button className={`button ${action === 'remove' ? 'danger' : 'primary'}`} disabled={busy || !host.trim() || !username.trim() || !password || !sshPort || !relayPort} onClick={async () => { setProgress({ percent: 1, message: 'Preparing deployment' }); setBusy(true); try { await onSubmit({ host: host.trim(), sshPort: Number(sshPort), username: username.trim(), password, relayPort: Number(relayPort) }) } finally { setBusy(false) } }}>{busy ? action === 'provision' ? 'Configuring VPS…' : 'Removing…' : action === 'provision' ? 'Configure VPS' : 'Remove from VPS'}</button></div></section></div>
}

function App() {
  const [state, setState] = useState<AppState | null>(null)
  const [view, setView] = useState<View>('dashboard')
  const [showRuleModal, setShowRuleModal] = useState(false)
  const [showRelayModal, setShowRelayModal] = useState(false)
  const [showAddRelay, setShowAddRelay] = useState(false)
  const [vpsTarget, setVpsTarget] = useState<{ id: string; action: 'provision' | 'remove' } | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [installingService, setInstallingService] = useState(false)
  const [latencyHistory, setLatencyHistory] = useState<number[]>([])

  useEffect(() => { api.bootstrap().then(setState) }, [])
  useEffect(() => {
    if (state?.session.status !== 'connected') return
    const timer = window.setInterval(() => api.refreshSession().then(setState), 2000)
    return () => window.clearInterval(timer)
  }, [state?.session.status])
  useEffect(() => {
    const latency = state?.session.metrics?.endToEndMs
    if (latency != null) setLatencyHistory((values) => [...values.slice(-29), latency])
    else if (state?.session.status === 'idle') setLatencyHistory([])
  }, [state?.session.metrics?.endToEndMs])

  const enabledRoutes = state?.tunnels.filter((item) => item.enabled).length ?? 0
  const enabledRules = state?.rules.filter((item) => item.enabled).length ?? 0
  const relay = state?.relays.find((item) => item.id === state.activeRelayId)
  const trafficMode = state?.trafficMode ?? 'split'
  const bestRouteLatency = state?.session.routeLatencies?.length ? Math.min(...state.session.routeLatencies) : null
  const readiness = useMemo(() => ({ routes: enabledRoutes >= 1, rules: trafficMode === 'all' || enabledRules >= 1, relay: relay?.status === 'ready' }), [enabledRoutes, enabledRules, relay, trafficMode])
  const readyCount = Object.values(readiness).filter(Boolean).length

  if (!state) return <div className="loading"><div className="brand-mark"><Zap size={22} /></div><span>Loading GamePath…</span></div>
  const engineState = state.engine ?? { status: 'offline' as const, version: '', message: 'Native engine is starting', capabilities: null }
  const serviceState = state.service ?? { status: 'not-installed' as const, version: '', message: 'Network service is not installed', elevated: false }

  const importTunnels = async () => {
    const result = await api.importWireGuard()
    if (result.state) setState(result.state)
    if (result.errors?.length) setNotice(result.errors.join('\n'))
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
    dashboard: ['Command center', 'Configure your routes, targets, and relay before starting a session.'],
    routes: ['WireGuard routes', 'Import and choose the VPN paths GamePath can use.'],
    split: ['Split tunnel', 'Choose exactly which traffic should enter the multipath tunnel.'],
    relays: ['Relay servers', 'Select the destination that combines your active routes.'],
    settings: ['Settings', 'Control startup, diagnostics, and client behavior.'],
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark"><Zap size={19} fill="currentColor" /></span><span>GAME<strong>PATH</strong></span><em>ALPHA</em></div>
        <nav>
          <span className="nav-caption">Workspace</span>
          {navItems.map((item) => {
            const Icon = item.icon
            return <button key={item.id} className={view === item.id ? 'active' : ''} onClick={() => setView(item.id)}><Icon size={18} /><span>{item.label}</span>{item.id === 'routes' && state.tunnels.length > 0 && <b>{state.tunnels.length}</b>}</button>
          })}
        </nav>
        <div className="sidebar-bottom">
          <button className={view === 'settings' ? 'active' : ''} onClick={() => setView('settings')}><Settings size={18} />Settings</button>
          <div className="client-card"><span><ShieldCheck size={16} /></span><div><strong>Local protection</strong><small>Keys secured by Windows</small></div></div>
          <div className="version">Client 0.1.7 <i /> Alpha build</div>
        </div>
      </aside>

      <main>
        <header className="topbar">
          <div><span className="eyebrow">GamePath client</span><h1>{title[view][0]}</h1><p>{title[view][1]}</p></div>
          <div className={`topbar-status ${engineState.status}`}><span className="pulse-dot" /> {engineState.status === 'ready' ? `Engine ${engineState.version} ready` : engineState.message}</div>
        </header>

        <div className="content">
          {view === 'dashboard' && (
            <div className="dashboard-grid">
              <section className="connect-panel">
                <div className="panel-glow" />
                <div className="connection-orbit">
                  <span className="orbit orbit-one" /><span className="orbit orbit-two" />
                  <div className="connection-core"><Zap size={28} fill="currentColor" /></div>
                </div>
                <span className="eyebrow">Multipath session</span>
                <h2>{state.session.status === 'connected' ? 'Paths connected' : readyCount === 3 ? 'Ready to accelerate' : 'Complete your setup'}</h2>
                <p>{state.session.status === 'connected' ? `${enabledRoutes} encrypted paths are connected through ${relay?.city}.` : readyCount === 3 ? `${enabledRoutes} routes will carry matching game traffic through ${relay?.city}.` : `${readyCount} of 3 requirements ready. Configure the remaining items below.`}</p>
                <button className={`connect-button ${state.session.status === 'connected' ? 'connected' : ''}`} disabled={state.session.status === 'starting'} onClick={toggleSession}><span>{state.session.status === 'starting' ? 'Starting…' : state.session.status === 'connected' ? 'Stop session' : 'Start session'}</span>{state.session.status === 'connected' ? <Check size={18} /> : <ArrowUpRight size={18} />}</button>
                <div className="session-mode"><Sparkles size={14} /> Adaptive duplication <Info size={13} /></div>
              </section>

              <section className="stats-strip">
                <div><span className="stat-icon cyan"><Route size={18} /></span><p>Active routes</p><strong>{enabledRoutes}<small> / {state.tunnels.length}</small></strong></div>
                <div><span className="stat-icon violet"><CircleGauge size={18} /></span><p>Best route</p><strong>{bestRouteLatency ?? '—'}<small> ms</small></strong></div>
                <div><span className="stat-icon green"><Activity size={18} /></span><p>Packet loss</p><strong>{state.session.metrics ? state.session.metrics.packetLossPercent.toFixed(1) : '—'}<small> %</small></strong></div>
              </section>

              <section className="setup-panel">
                <div className="section-heading"><div><span className="eyebrow">Quick setup</span><h2>Get ready to play</h2></div><span className="progress-label">{readyCount}/3 complete</span></div>
                <div className="progress-track"><span style={{ width: `${(readyCount / 3) * 100}%` }} /></div>
                <div className="setup-list">
                  <SetupStep done={readiness.routes} number={1} title="Add a WireGuard route" detail={`${state.tunnels.length} WireGuard configuration${state.tunnels.length === 1 ? '' : 's'} imported; direct ISP is automatic`} action="Configure" onClick={() => setView('routes')} />
                  <SetupStep done={readiness.rules} number={2} title="Choose traffic mode" detail={state.trafficMode === 'all' ? 'All system traffic' : `${enabledRules} active split-tunnel target${enabledRules === 1 ? '' : 's'}`} action="Configure" onClick={() => setView('split')} />
                  <SetupStep done={readiness.relay} number={3} title="Configure a relay" detail={relay ? `${relay.city}, ${relay.country}` : 'No relay selected'} action="Set up" onClick={() => setView('relays')} />
                </div>
              </section>

              <section className="route-preview">
                <div className="section-heading"><div><span className="eyebrow">Path overview</span><h2>Current route chain</h2></div><button className="text-button" onClick={() => setView('routes')}>Manage <ChevronRight size={14} /></button></div>
                <div className="route-map">
                  <div className="map-node origin"><Gamepad2 size={19} /><span>Your game</span></div>
                  <div className="map-lines"><i /><i /></div>
                  <div className="path-stack">
                    {[{ name: 'Direct ISP', enabled: true }, { name: enabledRoutes ? `${enabledRoutes} WireGuard route${enabledRoutes === 1 ? '' : 's'}` : 'WireGuard pool', enabled: enabledRoutes > 0 }].map((item, index) => <div key={item.name}><span className={item.enabled ? 'active' : ''}>{index + 1}</span><p>{item.name}</p><small>{item.enabled ? 'Available' : 'Not configured'}</small></div>)}
                  </div>
                  <div className="map-lines inbound"><i /><i /></div>
                  <div className="map-node relay"><MapPin size={19} /><span>{relay?.city ?? 'Relay'}</span></div>
                </div>
              </section>

              <TelemetryPanel state={state} history={latencyHistory} />
            </div>
          )}

          {view === 'routes' && (
            <section className="page-section">
              <div className="toolbar"><div><span className="count-badge">{enabledRoutes} active</span><span className="muted">One provider route pairs with Direct ISP; distinct configs add more paths.</span></div><button className="button primary" onClick={importTunnels}><Import size={16} />Import .conf</button></div>
              {state.tunnels.length ? <div className="route-list">{state.tunnels.map((tunnel) => <Endpoint key={tunnel.id} tunnel={tunnel} onToggle={async (enabled) => setState(await api.setTunnelEnabled(tunnel.id, enabled))} onRemove={async () => setState(await api.removeTunnel(tunnel.id))} />)}</div> : (
                <div className="empty-state"><span><HardDrive size={28} /></span><h2>No WireGuard routes yet</h2><p>Import your purchased VPN configuration files. Private keys are encrypted using Windows secure storage.</p><button className="button primary" onClick={importTunnels}><Import size={16} />Import configurations</button></div>
              )}
              <div className="info-banner"><ShieldCheck size={18} /><div><strong>Your private keys stay on this PC</strong><p>GamePath only decrypts a configuration when the local routing engine needs it.</p></div></div>
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
                  <button className={state.trafficMode === 'split' ? 'active' : ''} onClick={async () => setState(await api.setTrafficMode('split'))}><Gamepad2 size={15} /><span>Split tunnel<small>Selected targets</small></span></button>
                  <button className={state.trafficMode === 'all' ? 'active' : ''} onClick={async () => setState(await api.setTrafficMode('all'))}><Globe2 size={15} /><span>All traffic<small>Whole system</small></span></button>
                </div>
              </div>
              {state.trafficMode === 'all' && <div className="all-traffic-banner"><Globe2 size={19} /><div><strong>All-traffic mode is active</strong><p>Every compatible connection on this PC will use the multipath relay. The rules below are saved but ignored.</p></div></div>}
              <div className="toolbar"><div><span className="count-badge">{enabledRules} active</span><span className="muted">Rules are matched from most specific to least specific.</span></div><button className="button primary" onClick={() => setShowRuleModal(true)}><Plus size={16} />Add target</button></div>
              <div className={state.trafficMode === 'all' ? 'rules-disabled' : ''}>{state.rules.length ? <div className="rules-table">
                <div className="table-head"><span>Target</span><span>Type</span><span>Destination</span><span>Status</span><span /></div>
                {state.rules.map((rule) => {
                  const Icon = rule.kind === 'application' ? AppWindow : rule.kind === 'folder' ? FolderOpen : rule.kind === 'hostname' ? Globe2 : Network
                  return <div className="table-row" key={rule.id}><span className="target-cell"><i><Icon size={16} /></i><strong>{rule.label}</strong></span><span className="kind-label">{rule.kind}</span><span className="truncate">{rule.value}</span><span><Toggle checked={rule.enabled} onChange={async (enabled) => setState(await api.setRuleEnabled(rule.id, enabled))} label={`${rule.enabled ? 'Disable' : 'Enable'} ${rule.label}`} /></span><button className="icon-button danger" onClick={async () => setState(await api.removeRule(rule.id))}><Trash2 size={16} /></button></div>
                })}
              </div> : <div className="empty-state"><span><Network size={28} /></span><h2>No traffic targets</h2><p>Add a game executable, installation folder, hostname, or IP range.</p><button className="button primary" onClick={() => setShowRuleModal(true)}><Plus size={16} />Add first target</button></div>}</div>
            </section>
          )}

          {view === 'relays' && (
            <section className="page-section">
              <div className="relay-intro"><div><span className="eyebrow">Relay fleet</span><h2>{state.relays.length} server{state.relays.length === 1 ? '' : 's'}</h2><p>Add your VPS locations and enable one relay at a time.</p><button className="button primary" onClick={() => setShowAddRelay(true)}><Plus size={16} />Add VPS relay</button></div><div className="flag-orb">{relay?.code ?? 'GP'}</div></div>
              <div className="relay-grid">{state.relays.map((item) => <article key={item.id} className={`relay-card ${state.activeRelayId === item.id ? 'selected' : ''}`}><button className="relay-choice" onClick={async () => setState(await api.setRelay(item.id))}><span className="relay-radio">{state.activeRelayId === item.id && <Check size={14} />}</span><div className="relay-location"><span><MapPin size={19} /></span><div><strong>{item.city}</strong><small>{item.address ? `${item.address}:${item.port}` : `${item.country} · VPS not configured`}</small></div></div><div className="relay-stat"><small>Latency</small><strong>{item.latency ?? '—'}<em> ms</em></strong></div><div className={`relay-status ${item.status}`}><i />{state.activeRelayId === item.id ? 'Enabled' : item.status === 'ready' ? 'Disabled' : 'Setup required'}</div></button><div className="relay-actions">{item.status === 'ready' && <button className="button secondary" onClick={async () => { try { const tested = await api.testRelay(item.id); setState(tested.state); setNotice(`Authenticated relay ready · ${Math.round(tested.result.latencyMs)} ms · ${tested.result.virtualIpv4}`) } catch (error) { setNotice(error instanceof Error ? error.message : String(error)) } }}>Test</button>}<button className="button primary" onClick={() => setVpsTarget({ id: item.id, action: 'provision' })}>{item.status === 'ready' ? 'Update VPS' : 'Auto-configure VPS'}</button><button className="button secondary relay-configure" onClick={() => { setState({ ...state, activeRelayId: item.id }); setShowRelayModal(true) }}>Manual</button>{item.status === 'ready' && <button className="button secondary" onClick={() => setVpsTarget({ id: item.id, action: 'remove' })}>Remove VPS</button>}<button className="icon-button danger" aria-label={`Delete ${item.city}`} onClick={async () => setState(await api.removeRelayLocal(item.id))}><Trash2 size={16} /></button></div></article>)}</div>
              <div className="coming-regions"><span>More regions are planned</span><div><i>DE</i><i>NL</i><i>AE</i></div></div>
            </section>
          )}

          {view === 'settings' && (
            <section className="page-section settings-list">
              <div className="settings-card"><div><span className="setting-icon"><Zap size={18} /></span><div><strong>Adaptive duplication</strong><p>Duplicate latency-sensitive packets when route quality becomes unstable.</p></div></div><Toggle checked={true} onChange={() => undefined} label="Adaptive duplication" /></div>
              <div className="settings-card"><div><span className="setting-icon"><Link2 size={18} /></span><div><strong>Start with Windows</strong><p>Open GamePath in the background after signing in.</p></div></div><Toggle checked={false} onChange={() => undefined} label="Start with Windows" /></div>
              <div className="settings-card"><div><span className="setting-icon"><Activity size={18} /></span><div><strong>Local diagnostics</strong><p>Keep route latency and packet-loss history for troubleshooting.</p></div></div><Toggle checked={true} onChange={() => undefined} label="Local diagnostics" /></div>
              <div className="settings-card capability-card"><div><span className="setting-icon"><ShieldCheck size={18} /></span><div><strong>Windows network capabilities</strong><p>WireGuard {engineState.capabilities?.wireGuardInstalled ? 'detected' : 'not found'} · Wintun library {engineState.capabilities?.packetAdapter?.libraryLoaded ? 'ready' : 'missing'} · Driver {engineState.capabilities?.packetAdapterInstalled ? 'active' : 'not created'}</p></div></div><span className={`status-pill ${engineState.status === 'ready' ? 'online' : ''}`}><i />{engineState.status}</span></div>
              <div className="settings-card capability-card"><div><span className="setting-icon"><Network size={18} /></span><div><strong>Split-tunnel interception</strong><p>WFP backend {engineState.capabilities?.interception?.libraryLoaded && engineState.capabilities?.interception?.driverAvailable ? 'ready' : 'missing'} · Winsock transport · Administrator service required to activate</p></div></div><span className={`status-pill ${engineState.capabilities?.interception?.libraryLoaded ? 'online' : ''}`}><i />WFP</span></div>
              <div className="settings-card capability-card"><div><span className="setting-icon"><Server size={18} /></span><div><strong>GamePath Network Service</strong><p>{serviceState.message}{serviceState.version ? ` · Version ${serviceState.version}` : ''}</p></div></div><div className="service-actions"><button className={serviceState.status === 'ready' ? 'button secondary' : 'button primary'} disabled={installingService} onClick={async () => { setInstallingService(true); try { setState(await api.installService()); setNotice('GamePath Network Service installed and running.') } catch (error) { setNotice(error instanceof Error ? error.message : String(error)) } finally { setInstallingService(false) } }}>{installingService ? 'Installing…' : serviceState.status === 'ready' ? 'Reinstall service' : 'Install service'}</button><button className="button secondary" disabled={installingService} onClick={async () => setState(await api.refreshService())}>Refresh status</button><span className={`status-pill ${serviceState.status === 'ready' ? 'online' : ''}`}><i />{serviceState.status}</span></div></div>
            </section>
          )}
        </div>
      </main>

      {showRuleModal && <RuleModal onClose={() => setShowRuleModal(false)} onSave={async (input) => { setState(await api.addRule(input)); setShowRuleModal(false) }} />}
      {showRelayModal && relay && <RelayModal relay={relay} onClose={() => setShowRelayModal(false)} onImport={async () => { try { const result = await api.importRelayEnrollment(relay.id); if (result.state) setState(result.state) } catch (error) { setNotice(error instanceof Error ? error.message : String(error)) } }} onSave={async (input) => { try { setState(await api.configureRelay(relay.id, input)); setShowRelayModal(false) } catch (error) { setNotice(error instanceof Error ? error.message : String(error)) } }} />}
      {showAddRelay && <AddRelayModal onClose={() => setShowAddRelay(false)} onAdd={async (input) => { const result = await api.addRelay(input); setState(result.state); setShowAddRelay(false); setVpsTarget({ id: result.relayId, action: 'provision' }) }} />}
      {vpsTarget && (() => { const target = state.relays.find((item) => item.id === vpsTarget.id); return target ? <VpsModal relay={target} action={vpsTarget.action} onClose={() => setVpsTarget(null)} onSubmit={async (input) => { try { const next = vpsTarget.action === 'provision' ? await api.provisionRelayVps(target.id, input) : await api.removeRelayVps(target.id, input); setState(next); setNotice(vpsTarget.action === 'provision' ? 'VPS configured and enrollment protected by Windows.' : 'GamePath was removed from the VPS.'); setVpsTarget(null) } catch (error) { setNotice(error instanceof Error ? error.message : String(error)) } }} /> : null })()}
      {notice && <div className="toast"><Info size={17} /><span>{notice}</span><button onClick={() => setNotice(null)}><X size={15} /></button></div>}
    </div>
  )
}

export default App
