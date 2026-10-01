import { AlertTriangle, AppWindow, FolderOpen, Gamepad2, Globe2, Network, Plus, Trash2 } from 'lucide-react'
import { AppIcon } from '../AppIcon'
import { Toggle } from '../Toggle'
import type { RuleKind, VpnRule, VpnState } from '../../types'

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
  conflict,
  limitation,
  onToggle,
  onRemove,
}: {
  rule: VpnRule
  conflict: boolean
  limitation: string | undefined
  onToggle: (enabled: boolean) => void
  onRemove: () => void
}) {
  const Icon = kindIcons[rule.kind]
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
        {(conflict || limitation) && (
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
          </span>
        )}
      </div>
      <span className="vpn-target-kind">{kindLabels[rule.kind]}</span>
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

/** The apps and sites that use the VPN in split mode. */
export function VpnTargetList({
  vpn,
  onAdd,
  onToggle,
  onRemove,
}: {
  vpn: VpnState
  onAdd: (kind: RuleKind) => void
  onToggle: (id: string, enabled: boolean) => void
  onRemove: (id: string) => void
}) {
  const conflicts = new Set(vpn.conflicts)
  const allTraffic = vpn.trafficMode === 'all'

  return (
    <section className={`vpn-card vpn-targets ${allTraffic ? 'is-inactive' : ''}`}>
      <div className="card-head">
        <h3>Apps and websites</h3>
        <small>
          {allTraffic
            ? 'All traffic uses the VPN, so this list is not needed right now.'
            : `${vpn.rules.filter((rule) => rule.enabled).length} selected`}
        </small>
      </div>
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
      {vpn.rules.length ? (
        <ul className="vpn-target-list">
          {vpn.rules.map((rule) => (
            <TargetRow
              key={rule.id}
              rule={rule}
              conflict={conflicts.has(rule.id)}
              limitation={vpn.limitations[rule.id]}
              onToggle={(enabled) => onToggle(rule.id, enabled)}
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
