import { ArrowDownLeft, ArrowUpRight, ChevronRight, ShieldCheck } from 'lucide-react'
import { formatRate } from '../lib/format'
import { useVpnRates, vpnLive, vpnStatusText } from '../lib/vpn'
import type { AppState } from '../types'

/** The VPN at a glance on the overview, and the way into its screen. */
export function VpnStatusCard({ state, onOpen }: { state: AppState; onOpen: () => void }) {
  const { node, session } = state.vpn
  const rates = useVpnRates(session)
  const live = vpnLive(session.status)
  const detail = !node
    ? 'Add a node to use it beside your game'
    : live
      ? `Through ${node.name}${session.metrics?.latencyMs != null ? ` · ${Math.round(session.metrics.latencyMs)} ms` : ''}`
      : (session.message ?? `${node.name} is ready to connect`)

  return (
    <button type="button" className={`lan-proxy-card vpn-status-card is-${session.status}`} onClick={onOpen}>
      <span className="lan-proxy-card-icon vpn-status-card-icon" aria-hidden="true">
        <ShieldCheck size={18} />
      </span>
      <span className="lan-proxy-card-copy">
        <span className="eyebrow">VPN</span>
        <strong>{vpnStatusText[session.status].headline}</strong>
        <small>{detail}</small>
      </span>
      {live && (
        <span className="lan-proxy-card-rates">
          <span>
            <ArrowUpRight size={12} aria-label="Upload" /> {formatRate(Math.round(rates.sent))}
          </span>
          <span>
            <ArrowDownLeft size={12} aria-label="Download" /> {formatRate(Math.round(rates.received))}
          </span>
        </span>
      )}
      <ChevronRight size={16} aria-hidden="true" />
    </button>
  )
}
