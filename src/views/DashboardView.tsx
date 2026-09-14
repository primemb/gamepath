import { useState } from 'react'
import { Activity, ChevronRight, CircleGauge, Power, Route, Sparkles, Waypoints, Zap } from 'lucide-react'
import { SetupDrawer, type SetupItem } from '../components/SetupDrawer'
import { TelemetryPanel } from '../components/TelemetryPanel'
import type { PathHistory, PathRate } from '../lib/format'
import { deriveReadiness } from '../lib/readiness'
import type { AppState } from '../types'
import type { View } from '../lib/views'

export function DashboardView({
  state,
  histories,
  rates,
  onNavigate,
  onToggleSession,
}: {
  state: AppState
  histories: PathHistory
  rates: Record<number, PathRate>
  onNavigate: (view: View) => void
  onToggleSession: () => void
}) {
  // Null until the user has an opinion, so the drawer opens itself while the
  // setup is unfinished and closes once it is — without fighting the user.
  const [setupOpen, setSetupOpen] = useState<boolean | null>(null)

  const { carrying, directNode, enabledRules, readyCount, stepCount, direct, routesReady, rulesReady, relayReady } =
    deriveReadiness(state)
  const relay = state.relays.find((item) => item.id === state.activeRelayId)
  const routingNodes = state.tunnels.filter((item) => item.kind !== 'socks5').length
  const bestRouteLatency = state.session.routeLatencies?.length ? Math.min(...state.session.routeLatencies) : null
  const connected = state.session.status === 'connected'
  const complete = readyCount === stepCount

  const setupSteps: SetupItem[] = [
    {
      done: routesReady,
      title: direct ? 'Choose a tunnelling node' : 'Add a VPN route',
      detail: direct
        ? directNode
          ? `${directNode.name} will carry your traffic`
          : `${routingNodes} routing node${routingNodes === 1 ? '' : 's'} added; pick exactly one`
        : `${state.tunnels.length} node${state.tunnels.length === 1 ? '' : 's'} added; the relay is reached only through carrying nodes`,
      action: 'Configure',
      onClick: () => onNavigate('routes'),
    },
    {
      done: rulesReady,
      title: 'Choose traffic mode',
      detail:
        state.trafficMode === 'all'
          ? 'All IPv4 system traffic'
          : `${enabledRules} active split-tunnel target${enabledRules === 1 ? '' : 's'}`,
      action: 'Configure',
      onClick: () => onNavigate('split'),
    },
    // Direct mode has no relay to set up, so the step is not shown greyed out
    // and unreachable — it simply is not part of this setup.
    ...(direct
      ? []
      : [
          {
            done: relayReady === true,
            title: 'Configure a relay',
            detail: relay ? `${relay.city}, ${relay.country}` : 'No relay selected',
            action: 'Set up',
            onClick: () => onNavigate('relays'),
          },
        ]),
  ]

  const headline = connected
    ? direct
      ? 'Traffic is routing'
      : 'Paths connected'
    : complete
      ? 'Ready to accelerate'
      : 'Complete your setup'

  const subline = connected
    ? direct
      ? `Selected traffic is going through ${directNode?.name ?? 'your node'}.`
      : `${carrying.length} encrypted paths active through ${relay?.city ?? 'the relay'}.`
    : complete
      ? direct
        ? `${directNode?.name ?? 'Your node'} will carry your selected traffic.`
        : `${carrying.length} routes will carry game traffic through ${relay?.city ?? 'the relay'}.`
      : `${readyCount} of ${stepCount} requirements ready — open Setup below.`

  return (
    <div className="dashboard-grid">
      <section className={`command-bar ${connected ? 'is-live' : ''}`}>
        <div className="command-identity">
          <span className="command-core">
            <Zap size={22} fill="currentColor" />
          </span>
          <div>
            <span className="eyebrow">{direct ? 'Direct session' : 'Multipath session'}</span>
            <h2>{headline}</h2>
            <p>{subline}</p>
          </div>
        </div>
        <div className="command-stats">
          <div>
            <span className="stat-icon cyan">
              <Route size={16} />
            </span>
            <p>{direct ? 'Active node' : 'Active routes'}</p>
            <strong>
              {carrying.length}
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
            className={`connect-button ${connected ? 'connected' : ''}`}
            disabled={state.session.status === 'starting'}
            onClick={onToggleSession}
          >
            <Power size={17} />
            <span>
              {state.session.status === 'starting' ? 'Starting…' : connected ? 'Stop session' : 'Start session'}
            </span>
          </button>
          {/* Which mode is live, and the way back to changing it. */}
          <button className="session-mode" onClick={() => onNavigate('relays')}>
            {direct ? <Waypoints size={12} /> : <Sparkles size={12} />}
            {direct ? 'Direct · one node' : 'Relay · adaptive duplication'}
            <ChevronRight size={12} />
          </button>
        </div>
      </section>

      <SetupDrawer
        open={setupOpen ?? !complete}
        onToggle={() => setSetupOpen(!(setupOpen ?? !complete))}
        steps={setupSteps}
        routes={carrying.map((tunnel) => tunnel.name)}
        destination={direct ? 'Game server' : (relay?.city ?? 'Relay')}
        direct={direct}
        onManageRoutes={() => onNavigate('routes')}
      />

      <TelemetryPanel state={state} histories={histories} rates={rates} />
    </div>
  )
}
