import type { ReactNode } from 'react'
import { Activity, ArrowDownRight, ArrowUpRight, Radio } from 'lucide-react'
import { AddressWithCountry } from '../IpLocation'
import {
  formatBytes,
  formatMetric,
  formatRate,
  jitter,
  pathColors,
  pathLoss,
  type PathHistory,
  type PathRate,
} from '../lib/format'
import { HandledConnections } from './HandledConnections'
import { LatencyChart } from './LatencyChart'
import type { AppState, PathMetric } from '../types'

/** One leg of the journey: what was measured, the reading, and where it came from. */
type JourneyStage = [label: string, value: number | null | undefined, detail: ReactNode]

function JourneyBreakdown({ stages }: { stages: JourneyStage[] }) {
  return (
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
  )
}

function NodeQualityCard({
  path,
  color,
  carryingTraffic,
  samples,
  rate,
  direct,
}: {
  path: PathMetric
  color: string
  carryingTraffic: boolean
  samples: PathHistory[number]
  rate: PathRate | undefined
  direct: boolean
}) {
  return (
    <article className={`node-card ${path.reachable ? 'healthy' : 'unhealthy'} ${carryingTraffic ? 'carrying' : ''}`}>
      <div className="node-card-head">
        <span className="node-color" style={{ background: color }} />
        <div>
          <strong>{path.label}</strong>
          <small>
            <AddressWithCountry value={path.endpoint} />
          </small>
        </div>
        <span className={`route-health ${path.reachable ? 'online' : ''}`}>
          <i />
          {path.reachable ? (carryingTraffic ? 'Active' : 'Standby') : 'Offline'}
        </span>
      </div>
      <div className="node-primary">
        <span>
          <small>{direct ? 'Benchmark RTT' : 'Relay probe RTT'}</small>
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
          Setup time <strong>{formatMetric(path.handshakeMs)}</strong>
        </span>
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
}

export function TelemetryPanel({
  state,
  histories,
  rates,
}: {
  state: AppState
  histories: PathHistory
  rates: Record<number, PathRate>
}) {
  const metrics = state.session.metrics
  const capture = state.session.capture?.diagnostics
  const paths = state.session.pathMetrics ?? []
  const degradedRoutes = state.session.degradedRoutes ?? []
  const live = state.session.status === 'connected'
  // Derived once in the main process from the route carrying traffic. Its RTT
  // is an actual GamePath probe, not a VPN/WireGuard setup duration.
  const journey = state.session.journey
  // Separate from the journey's pinned route on purpose: this heading reports
  // the best latency on offer, which is a different question from which route
  // the breakdown below describes.
  const bestPath = paths
    .filter((path) => path.reachable && path.latencyMs != null)
    .sort((a, b) => (a.latencyMs ?? Infinity) - (b.latencyMs ?? Infinity))[0]
  const direct = (state.session.mode ?? state.connectionMode) === 'direct'
  const stages: JourneyStage[] = [
    [
      direct ? 'You → benchmark via VPN node' : 'You → relay via VPN node',
      journey?.probeRttMs,
      journey?.label ? `${journey.label} · measured GamePath probe` : 'Awaiting route',
    ],
    [
      'You → benchmark through route',
      metrics?.endToEndMs,
      metrics?.benchmarkServer ? (
        <span className="journey-endpoint">
          One-time packet test · <AddressWithCountry value={metrics.benchmarkServer} />
        </span>
      ) : (
        'Awaiting target'
      ),
    ],
  ]

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
            <small>Last 60 received probe samples · refreshed every 2s</small>
          </div>
          <LatencyChart histories={histories} paths={paths} />
        </div>
        <div className="telemetry-side">
          <JourneyBreakdown stages={stages} />
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
          {direct
            ? 'One node, no duplication'
            : degradedRoutes.length
              ? // The session runs on the routes that answered rather than
                // failing outright, so say which ones it is running without.
                `${paths.length - degradedRoutes.length} of ${paths.length} routes carrying traffic`
              : `${paths.length} active route${paths.length === 1 ? '' : 's'}`}
        </small>
      </div>
      {paths.length ? (
        <div className="node-grid">
          {paths.map((path, index) => (
            <NodeQualityCard
              key={path.route}
              path={path}
              color={pathColors[index % pathColors.length]}
              carryingTraffic={state.session.selectedRoutes?.includes(path.route) ?? path.reachable}
              samples={histories[path.route] ?? []}
              rate={rates[path.route]}
              direct={direct}
            />
          ))}
        </div>
      ) : (
        <p className="node-empty">Start a session to measure every enabled WireGuard route.</p>
      )}

      <HandledConnections capture={capture} />
    </section>
  )
}
