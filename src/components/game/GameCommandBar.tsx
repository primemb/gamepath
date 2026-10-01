import { Activity, ChevronRight, CircleGauge, Power, Route, Sparkles, Waypoints, Zap } from 'lucide-react'
import { deriveReadiness } from '../../lib/readiness'
import type { AppState } from '../../types'

/** The game session at a glance, and its one switch — above every Game tab. */
export function GameCommandBar({
  state,
  onToggleSession,
  onOpenConnection,
}: {
  state: AppState
  onToggleSession: () => void
  onOpenConnection: () => void
}) {
  const { carrying, directNode, readyCount, stepCount, direct } = deriveReadiness(state)
  const relay = state.relays.find((item) => item.id === state.activeRelayId)
  const bestRouteLatency = state.session.routeLatencies?.length ? Math.min(...state.session.routeLatencies) : null
  const connected = state.session.status === 'connected'
  // A failover can move a running session off the active relay.
  const sessionRelay = (connected && state.relays.find((item) => item.id === state.session.relayId)) || relay
  const failover = connected ? state.session.failover : undefined
  const complete = readyCount === stepCount

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
      : failover
        ? `Moved to ${failover.toCity} after ${failover.fromCity} stopped answering.`
        : `${carrying.length} encrypted paths active through ${sessionRelay?.city ?? 'the relay'}.`
    : complete
      ? direct
        ? `${directNode?.name ?? 'Your node'} will carry your selected traffic.`
        : `${carrying.length} routes will carry game traffic through ${relay?.city ?? 'the relay'}.`
      : `${readyCount} of ${stepCount} requirements ready — finish Setup in Overview.`

  return (
    <section className={`command-bar ${connected ? 'is-live' : ''}`} aria-labelledby="game-headline">
      <div className="command-identity">
        <span className="command-core">
          <Zap size={22} fill="currentColor" />
        </span>
        <div>
          <span className="eyebrow">{direct ? 'Direct session' : 'Multipath session'}</span>
          <h2 id="game-headline">{headline}</h2>
          <p aria-live="polite">{subline}</p>
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
          aria-busy={state.session.status === 'starting'}
          onClick={onToggleSession}
        >
          <Power size={17} />
          <span>
            {state.session.status === 'starting' ? 'Starting…' : connected ? 'Stop session' : 'Start session'}
          </span>
        </button>
        {/* Which mode is live, and the way back to changing it. */}
        <button className="session-mode" onClick={onOpenConnection}>
          {direct ? <Waypoints size={12} /> : <Sparkles size={12} />}
          {direct ? 'Direct · one node' : 'Relay · adaptive duplication'}
          <ChevronRight size={12} />
        </button>
      </div>
    </section>
  )
}
