import { AlertTriangle, AppWindow, FolderOpen, Gamepad2, Globe2, Network, Plus, Trash2, WifiOff } from 'lucide-react'
import { AppIcon } from '../AppIcon'
import { Toggle } from '../Toggle'
import { downNodes, targetNode } from '../../lib/vpn'
import type { RuleKind, VpnNodeHealth, VpnRule, VpnState } from '../../types'
import { VpnNodePicker } from './VpnNodePicker'

const kindIcons: Record<RuleKind, typeof AppWindow> = {
  application: AppWindow,
  folder: FolderOpen,
  hostname: Globe2,
  ip: Network,
}

const kindLabels: Record<RuleKind, string> = {
  application: 'Application',
  folder: 'Folder',
  hostname: 'Website',
  ip: 'IP range',
}

function TargetRow({
  rule,
  vpn,
  conflict,
  limitation,
  down,
  onToggle,
  onNode,
  onRemove,
}: {
  rule: VpnRule
  vpn: VpnState
  conflict: boolean
  limitation: string | undefined
  /** Its node, when the running VPN reports it is not answering. */
  down: VpnNodeHealth | undefined
  onToggle: (enabled: boolean) => void
  onNode: (nodeId: string | null) => void
  onRemove: () => void
}) {
  const Icon = kindIcons[rule.kind]
  // One node means there is nothing to choose between.
  const choosesNode = vpn.nodes.length > 1 && vpn.trafficMode === 'split'
  return (
    <li className={`vpn-target ${rule.enabled ? '' : 'is-paused'}`}>
      <span className="vpn-target-icon" aria-hidden="true">
        {rule.kind === 'application' ? <AppIcon path={rule.value} size={18} /> : <Icon size={16} />}
      </span>
      <div className="vpn-target-copy">
        <strong data-no-translate>{rule.label}</strong>
        <small data-no-translate title={rule.value}>
          {rule.value}
        </small>
        {(conflict || limitation || down) && (
          <span className="vpn-target-notes">
            {conflict && (
              <span className="vpn-note is-game">
                <Gamepad2 size={11} aria-hidden="true" /> Game rule wins
              </span>
            )}
            {limitation && (
              <span className="vpn-note is-warning" title={limitation}>
                <AlertTriangle size={11} aria-hidden="true" /> Not routable by this node
              </span>
            )}
            {down && (
              <span className="vpn-note is-warning" title={down.error ?? undefined}>
                <WifiOff size={11} aria-hidden="true" /> <span data-no-translate>{down.name}</span> not answering
              </span>
            )}
          </span>
        )}
      </div>
      {choosesNode ? (
        <VpnNodePicker vpn={vpn} value={rule.nodeId} label={`Node for ${rule.label}`} compact onChange={onNode} />
      ) : (
        <span className="vpn-target-kind">{kindLabels[rule.kind]}</span>
      )}
      <Toggle
        checked={rule.enabled}
        onChange={onToggle}
        label={`${rule.enabled ? 'Stop sending' : 'Send'} ${rule.label} through the VPN`}
      />
      <button className="icon-button danger" aria-label={`Remove ${rule.label}`} onClick={onRemove}>
        <Trash2 size={15} aria-hidden="true" />
      </button>
    </li>
  )
}

/** The apps and sites that use the VPN in split mode, each through its node. */
export function VpnTargetList({
  vpn,
  onAdd,
  onToggle,
  onNode,
  onRemove,
}: {
  vpn: VpnState
  onAdd: (kind: RuleKind) => void
  onToggle: (id: string, enabled: boolean) => void
  onNode: (id: string, nodeId: string | null) => void
  onRemove: (id: string) => void
}) {
  const conflicts = new Set(vpn.conflicts)
  const allTraffic = vpn.trafficMode === 'all'
  const down = downNodes(vpn.session)

  return (
    <section className={`vpn-card vpn-targets ${allTraffic ? 'is-inactive' : ''}`}>
      <div className="card-head">
        <h3>Apps and websites</h3>
        <small>
          {allTraffic
            ? 'All traffic uses the default node, so this list is not needed right now.'
            : `${vpn.rules.filter((rule) => rule.enabled).length} selected`}
        </small>
      </div>
      {!allTraffic && vpn.nodes.length > 1 && (
        <p className="vpn-node-hint">
          Pick a node for any target, or leave it on the default node. A website rule applies in every app, and its
          names are looked up through its own node.
        </p>
      )}
      <div className="vpn-target-actions">
        <button className="button secondary" disabled={!vpn.canSelectApps} onClick={() => onAdd('application')}>
          <AppWindow size={14} aria-hidden="true" /> Add app
        </button>
        <button className="button secondary" disabled={!vpn.canSelectApps} onClick={() => onAdd('folder')}>
          <FolderOpen size={14} aria-hidden="true" /> Add folder
        </button>
        <button className="button secondary" onClick={() => onAdd('hostname')}>
          <Plus size={14} aria-hidden="true" /> Add website or IP
        </button>
      </div>
      {!vpn.canSelectApps && (
        <p className="vpn-hint">
          <AlertTriangle size={13} aria-hidden="true" /> An L2TP/IPsec node routes by address, so it can carry websites
          and IP ranges but not individual apps. Use all-traffic mode, or a WireGuard, OpenVPN or SOCKS5 node, for apps.
        </p>
      )}
      {vpn.nodeLimitation && (
        <p className="vpn-hint" role="alert">
          <AlertTriangle size={13} aria-hidden="true" /> {vpn.nodeLimitation}
        </p>
      )}
      {vpn.rules.length ? (
        <ul className="vpn-target-list">
          {vpn.rules.map((rule) => (
            <TargetRow
              key={rule.id}
              rule={rule}
              vpn={vpn}
              conflict={conflicts.has(rule.id)}
              limitation={vpn.limitations[rule.id]}
              down={rule.enabled ? down.get(targetNode(vpn, rule)?.id ?? '') : undefined}
              onToggle={(enabled) => onToggle(rule.id, enabled)}
              onNode={(nodeId) => onNode(rule.id, nodeId)}
              onRemove={() => onRemove(rule.id)}
            />
          ))}
        </ul>
      ) : (
        <div className="vpn-empty-targets">
          <Globe2 size={20} aria-hidden="true" />
          <strong>Nothing selected yet</strong>
          <p>Add the apps and websites that should use the VPN. Everything else keeps your normal connection.</p>
        </div>
      )}
    </section>
  )
}
