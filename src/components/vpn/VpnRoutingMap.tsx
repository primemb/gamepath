import { AppWindow, FolderOpen, Globe2, Network, Pencil } from 'lucide-react'
import { AppIcon } from '../AppIcon'
import { nodeKindLabels } from '../../lib/nodes'
import { describeNodeLive, nodeLive, targetNode, type NodeLive } from '../../lib/vpn'
import type { RuleKind, VpnNode, VpnRule, VpnState } from '../../types'

const kindIcons: Record<RuleKind, typeof AppWindow> = {
  application: AppWindow,
  folder: FolderOpen,
  hostname: Globe2,
  ip: Network,
}

function TargetChip({ rule }: { rule: VpnRule }) {
  const Icon = kindIcons[rule.kind]
  return (
    <li className="vpn-route-chip" title={rule.value}>
      {rule.kind === 'application' ? <AppIcon path={rule.value} size={14} /> : <Icon size={12} aria-hidden="true" />}
      <span data-no-translate>{rule.label}</span>
    </li>
  )
}

function LiveStatus({ live }: { live: NodeLive | undefined }) {
  if (!live) return <span className="vpn-route-live is-idle">Not connected</span>
  return (
    <span className={`vpn-route-live is-${live.state}`} aria-live="polite">
      <span className="vpn-route-dot" aria-hidden="true" />
      {describeNodeLive(live)}
    </span>
  )
}

function RouteRow({
  node,
  isDefault,
  rules,
  live,
  note,
}: {
  node: VpnNode
  isDefault: boolean
  rules: VpnRule[]
  live: NodeLive | undefined
  note?: string
}) {
  return (
    <li className={`vpn-route${live?.state === 'down' ? ' is-down' : ''}`}>
      <div className="vpn-route-head">
        <span className="vpn-route-name">
          <strong data-no-translate>{node.name}</strong>
          <span className="kind-pill vpn-kind-pill">{nodeKindLabels[node.kind]}</span>
          {isDefault && <span className="kind-pill vpn-default-pill">Default</span>}
        </span>
        <LiveStatus live={live} />
      </div>
      {rules.length > 0 && (
        <ul className="vpn-route-chips" aria-label={`Targets through ${node.name}`}>
          {rules.map((rule) => (
            <TargetChip key={rule.id} rule={rule} />
          ))}
        </ul>
      )}
      {note && <small className="vpn-route-note">{note}</small>}
    </li>
  )
}

/**
 * Which node carries which app or website, at a glance. The default node is
 * listed first with every target that has no node of its own, then each other
 * node with the targets assigned to it.
 */
export function VpnRoutingMap({ vpn, onEdit }: { vpn: VpnState; onEdit: () => void }) {
  if (!vpn.node) return null
  const live = nodeLive(vpn)
  const split = vpn.trafficMode === 'split'
  const enabled = vpn.rules.filter((rule) => rule.enabled)
  const byNode = new Map<string, VpnRule[]>()
  for (const rule of split ? enabled : []) {
    const id = targetNode(vpn, rule)?.id ?? vpn.node.id
    byNode.set(id, [...(byNode.get(id) ?? []), rule])
  }
  const others = vpn.nodes.filter((node) => node.id !== vpn.node!.id && (byNode.has(node.id) || live.has(node.id)))
  const defaultNote = !split
    ? 'Carries all traffic except your game.'
    : byNode.get(vpn.node.id)?.length
      ? 'Also looks up names for apps that use Windows’ resolver.'
      : 'No targets of its own. It looks up names for apps that use Windows’ resolver.'

  return (
    <section className="vpn-card vpn-routing-map" aria-labelledby="vpn-routing-map-title">
      <div className="card-head">
        <div>
          <h3 id="vpn-routing-map-title">Which node carries what</h3>
          <small>
            {split
              ? 'Apps and websites that are not listed here keep your normal connection.'
              : 'All traffic mode sends everything through the default node.'}
          </small>
        </div>
        {split && (
          <button className="button secondary" onClick={onEdit}>
            <Pencil size={14} aria-hidden="true" />
            Change
          </button>
        )}
      </div>
      <ul className="vpn-route-list">
        <RouteRow
          node={vpn.node}
          isDefault
          rules={byNode.get(vpn.node.id) ?? []}
          live={live.get(vpn.node.id)}
          note={defaultNote}
        />
        {others.map((node) => (
          <RouteRow
            key={node.id}
            node={node}
            isDefault={false}
            rules={byNode.get(node.id) ?? []}
            live={live.get(node.id)}
          />
        ))}
      </ul>
    </section>
  )
}
