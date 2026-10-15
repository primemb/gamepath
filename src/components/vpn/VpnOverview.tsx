import { AppWindow, ChevronRight, Globe2, Lock, ShieldCheck } from 'lucide-react'
import type { ReactNode } from 'react'
import { HandledConnections } from '../HandledConnections'
import { nodeKindLabels } from '../../lib/nodes'
import type { VpnTab } from '../../lib/views'
import { nodeNames, vpnLive } from '../../lib/vpn'
import type { VpnState } from '../../types'
import { VpnRoutingMap } from './VpnRoutingMap'

function SummaryTile({
  icon,
  eyebrow,
  title,
  detail,
  onOpen,
}: {
  icon: ReactNode
  eyebrow: string
  title: string
  detail: string
  onOpen: () => void
}) {
  return (
    <button type="button" className="lan-proxy-card vpn-status-card vpn-summary-tile" onClick={onOpen}>
      <span className="lan-proxy-card-icon vpn-status-card-icon" aria-hidden="true">
        {icon}
      </span>
      <span className="lan-proxy-card-copy">
        <span className="eyebrow">{eyebrow}</span>
        <strong>{title}</strong>
        <small>{detail}</small>
      </span>
      <ChevronRight size={16} aria-hidden="true" />
    </button>
  )
}

/** The VPN's setup in three lines, and the traffic it is carrying right now. */
export function VpnOverview({ vpn, onOpenTab }: { vpn: VpnState; onOpenTab: (tab: VpnTab) => void }) {
  const live = vpnLive(vpn.session.status)
  const split = vpn.trafficMode === 'split'
  const targets = vpn.rules.filter((rule) => rule.enabled).length
  const latency = live ? vpn.session.metrics?.latencyMs : null
  const inUse = live && vpn.session.nodes?.length ? vpn.session.nodes : vpn.node ? [vpn.node] : []
  const latencyText = latency != null ? ` · ${Math.round(latency)} ms` : ''

  // All-traffic mode captures nothing per app, so there is no list to show.
  const emptyText = !live
    ? 'Turn on the VPN to see the apps and destinations it carries.'
    : split
      ? 'Open an app you selected for the VPN to see its connections here.'
      : 'In all-traffic mode the VPN carries everything except your game, so connections are not listed per app.'

  return (
    <div className="vpn-overview">
      <div className="vpn-summary-grid">
        <SummaryTile
          icon={<ShieldCheck size={18} />}
          eyebrow={inUse.length > 1 ? 'Nodes' : 'Node'}
          title={inUse.length ? nodeNames(inUse) : 'No node yet'}
          detail={
            !vpn.node
              ? 'Add a node in the Nodes tab to get started.'
              : inUse.length > 1
                ? `${inUse.length} nodes in use${latencyText}`
                : `${nodeKindLabels[vpn.node.kind]}${latencyText}`
          }
          onOpen={() => onOpenTab('node')}
        />
        <SummaryTile
          icon={split ? <AppWindow size={18} /> : <Globe2 size={18} />}
          eyebrow="Routing scope"
          title={split ? 'Selected apps' : 'All traffic'}
          detail={split ? `${targets} target${targets === 1 ? '' : 's'} selected` : 'Except your game'}
          onOpen={() => onOpenTab('split')}
        />
        <SummaryTile
          icon={<Lock size={18} />}
          eyebrow="Protection"
          title={vpn.killSwitch ? 'Kill switch on' : 'Kill switch off'}
          detail={vpn.remoteDns ? 'Names resolved through the VPN' : 'Names resolved by this PC'}
          onOpen={() => onOpenTab('split')}
        />
      </div>
      <VpnRoutingMap vpn={vpn} onEdit={() => onOpenTab('split')} />
      <HandledConnections
        capture={live && split ? vpn.session.capture?.diagnostics : undefined}
        emptyText={emptyText}
        nodeOf={
          (vpn.session.nodes?.length ?? 0) > 1
            ? (connection) => vpn.session.nodes?.[connection.node ?? 0]?.name
            : undefined
        }
      />
    </div>
  )
}
