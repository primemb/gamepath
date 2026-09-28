import { ArrowDownLeft, ArrowUpRight, ChevronRight, Gamepad2 } from 'lucide-react'
import { formatRate } from '../lib/format'
import { connectedDevices, primaryLanAddress, useLanProxyRates } from '../lib/lanProxy'
import type { AppState } from '../types'

/** The proxy at a glance on the overview, and the way into its screen. */
export function LanProxyCard({ state, onOpen }: { state: AppState; onOpen: () => void }) {
  const status = state.session.status === 'connected' ? state.session.lanProxy : undefined
  const rates = useLanProxyRates(status)
  const listening = status?.state === 'listening'
  const address = primaryLanAddress(status) ?? state.lanAddresses?.[0]
  const port = listening ? status?.port : state.lanProxy.port
  const devices = connectedDevices(status).length
  const total = Object.values(rates).reduce(
    (sum, rate) => ({ sent: sum.sent + rate.sent, received: sum.received + rate.received }),
    { sent: 0, received: 0 },
  )
  const detail = listening
    ? `${devices} device${devices === 1 ? '' : 's'} connected`
    : status?.state === 'error'
      ? 'The proxy did not start'
      : 'Opens with the next session'

  return (
    <button type="button" className={`lan-proxy-card ${listening ? 'is-live' : ''}`} onClick={onOpen}>
      <span className="lan-proxy-card-icon" aria-hidden="true">
        <Gamepad2 size={18} />
      </span>
      <span className="lan-proxy-card-copy">
        <span className="eyebrow">Console sharing</span>
        <strong data-no-translate>{address ? `${address}:${port}` : `Port ${port}`}</strong>
        <small>{detail}</small>
      </span>
      {listening && (
        <span className="lan-proxy-card-rates">
          <span>
            <ArrowUpRight size={12} aria-label="Upload" /> {formatRate(Math.round(total.sent))}
          </span>
          <span>
            <ArrowDownLeft size={12} aria-label="Download" /> {formatRate(Math.round(total.received))}
          </span>
        </span>
      )}
      <ChevronRight size={16} aria-hidden="true" />
    </button>
  )
}
