import { formatBytes } from '../../lib/format'
import { vpnLive } from '../../lib/vpn'
import type { VpnSession } from '../../types'

export function VpnSessionUsage({ session }: { session: VpnSession }) {
  const metrics = vpnLive(session.status) ? session.metrics : undefined

  return (
    <div className="vpn-session-usage" role="group" aria-label="Current session usage">
      <div>
        <span>Session total</span>
        <strong>{metrics ? formatBytes(metrics.bytesSent + metrics.bytesReceived) : '—'}</strong>
      </div>
      <div>
        <span>Uploaded</span>
        <strong>{metrics ? formatBytes(metrics.bytesSent) : '—'}</strong>
      </div>
      <div>
        <span>Downloaded</span>
        <strong>{metrics ? formatBytes(metrics.bytesReceived) : '—'}</strong>
      </div>
    </div>
  )
}
