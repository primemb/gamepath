import { Gauge } from 'lucide-react'
import { Toggle } from './Toggle'
import type { AppState, DnsCacheStats } from '../types'

type SessionCapture = AppState['session']['capture']

type Row = { name: 'Game' | 'VPN'; stats: DnsCacheStats }

const count = new Intl.NumberFormat('en-US')

/** A live session's polled capture always carries the key, `null` when it runs with the cache off. */
function reportsCache(capture: SessionCapture): capture is NonNullable<SessionCapture> {
  return capture != null && 'dnsCache' in capture
}

export function OptimisticDnsCard({ state, onChange }: { state: AppState; onChange: (enabled: boolean) => void }) {
  const enabled = state.optimisticDns !== false
  const vpnStatus = state.vpn.session.status
  const live = [
    { name: 'Game' as const, capture: state.session.status === 'connected' ? state.session.capture : undefined },
    {
      name: 'VPN' as const,
      capture: vpnStatus === 'connected' || vpnStatus === 'degraded' ? state.vpn.session.capture : undefined,
    },
  ].filter((session) => reportsCache(session.capture))
  const rows: Row[] = live.flatMap(({ name, capture }) =>
    capture?.dnsCache ? [{ name, stats: capture.dnsCache }] : [],
  )
  // A running session keeps the choice it connected with.
  const needsReconnect = live.some(({ capture }) => (capture?.dnsCache != null) !== enabled)

  return (
    <div className="settings-card settings-card-stacked">
      <div className="settings-card-row">
        <div>
          <span className="setting-icon">
            <Gauge size={18} aria-hidden="true" />
          </span>
          <div>
            <strong>Optimistic DNS</strong>
            <p>
              Answers repeated lookups instantly from names your tunnel already resolved, and refreshes them in the
              background. Sites and launchers open faster and keep resolving through a brief reconnect. Only answers
              that came through your tunnel are reused.
            </p>
          </div>
        </div>
        <Toggle checked={enabled} onChange={onChange} label="Optimistic DNS" />
      </div>

      <div className="dns-cache-panel">
        {needsReconnect ? (
          <p className="dns-cache-note is-pending">Reconnect to apply this to the running session.</p>
        ) : (
          <p className="dns-cache-note">Applies when a session connects. Game and VPN each keep their own answers.</p>
        )}
        {rows.length ? (
          <div className="dns-cache-rows">
            {rows.map((row) => (
              <DnsCacheRow key={row.name} row={row} />
            ))}
          </div>
        ) : (
          <p className="dns-cache-empty">
            {enabled
              ? 'Connect the game or VPN to see how many lookups it answers instantly.'
              : 'Off: every lookup waits for the resolver through the tunnel.'}
          </p>
        )}
      </div>
    </div>
  )
}

function DnsCacheRow({ row }: { row: Row }) {
  const { answered, staleAnswered, forwarded, entries } = row.stats
  const instant = answered + staleAnswered
  const total = instant + forwarded
  const share = total ? Math.round((instant / total) * 100) : 0
  return (
    <div className="dns-cache-row">
      <span className="dns-cache-session">{row.name}</span>
      <div className="dns-cache-share">
        <div
          className="dns-cache-meter"
          role="meter"
          aria-label="Lookups answered from cache"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={share}
        >
          <i style={{ transform: `scaleX(${share / 100})` }} />
        </div>
        <span>
          <b>{share}%</b> <span>from cache</span>
        </span>
      </div>
      <dl className="dns-cache-figures">
        <div>
          <dt>Answered instantly</dt>
          <dd>{count.format(instant)}</dd>
        </div>
        <div>
          <dt>Kept working while refreshing</dt>
          <dd>{count.format(staleAnswered)}</dd>
        </div>
        <div>
          <dt>Names remembered</dt>
          <dd>{count.format(entries)}</dd>
        </div>
      </dl>
    </div>
  )
}
