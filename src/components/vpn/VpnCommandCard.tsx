import {
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  CircleGauge,
  Clock3,
  LoaderCircle,
  Power,
  ShieldCheck,
} from 'lucide-react'
import { formatRate } from '../../lib/format'
import { formatUptime, useTicker, useVpnRates, vpnBusy, vpnLive, vpnOn, vpnStatusText } from '../../lib/vpn'
import type { VpnState } from '../../types'

/** The VPN's state at a glance, and its one switch. */
export function VpnCommandCard({ vpn, onToggle, busy }: { vpn: VpnState; onToggle: () => void; busy: boolean }) {
  const { session } = vpn
  const live = vpnLive(session.status)
  const now = useTicker(live)
  const rates = useVpnRates(session)
  const text = vpnStatusText[session.status]
  const on = vpnOn(session.status)
  const working = busy || vpnBusy(session.status)
  const latency = live ? session.metrics?.latencyMs : null

  return (
    <section className={`command-bar vpn-command is-${session.status}`} aria-labelledby="vpn-headline">
      <div className="command-identity">
        <span className="command-core">
          <ShieldCheck size={22} />
        </span>
        <div>
          <span className="eyebrow">VPN · one node, direct</span>
          <h2 id="vpn-headline">{text.headline}</h2>
          {/* Announced, so a status change is heard as well as seen. */}
          <p aria-live="polite">
            {session.message ??
              (vpn.node ? `${vpn.node.name} is ready to connect.` : 'Add a node in the Node tab to get started.')}
          </p>
        </div>
      </div>
      <div className="command-stats">
        <div>
          <span className="stat-icon violet">
            <CircleGauge size={16} />
          </span>
          <p>Latency</p>
          <strong>
            {latency == null ? '—' : Math.round(latency)}
            <small> ms</small>
          </strong>
        </div>
        <div>
          <span className="stat-icon cyan">
            <Activity size={16} />
          </span>
          <p>Traffic</p>
          <strong className="vpn-rates">
            <span>
              <ArrowDownLeft size={12} aria-label="Download" /> {formatRate(Math.round(rates.received))}
            </span>
            <span>
              <ArrowUpRight size={12} aria-label="Upload" /> {formatRate(Math.round(rates.sent))}
            </span>
          </strong>
        </div>
        <div>
          <span className="stat-icon green">
            <Clock3 size={16} />
          </span>
          <p>Connected for</p>
          <strong>{live && session.startedAt ? formatUptime(now - session.startedAt) : '—'}</strong>
        </div>
      </div>
      <div className="command-action">
        <button
          className={`connect-button vpn-connect ${on ? 'connected' : ''}`}
          disabled={working || !vpn.node}
          aria-busy={working}
          onClick={onToggle}
        >
          {working ? <LoaderCircle size={17} className="vpn-spin" aria-hidden="true" /> : <Power size={17} />}
          <span>{working ? 'Connecting…' : on ? 'Turn off VPN' : 'Turn on VPN'}</span>
        </button>
        <span className={`vpn-status-pill is-${session.status}`}>
          <i aria-hidden="true" />
          {text.pill}
        </span>
      </div>
    </section>
  )
}
