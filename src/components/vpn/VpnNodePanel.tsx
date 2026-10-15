import { useState } from 'react'
import { FileKey2, KeyRound, Network, Plus, Server, ShieldCheck, Trash2, Zap } from 'lucide-react'
import { AddressWithCountry } from '../../IpLocation'
import { nodeKindLabels } from '../../lib/nodes'
import { describeNodeLive, vpnNodeKinds, type NodeLive } from '../../lib/vpn'
import type { NodeKind, VpnNode } from '../../types'
import { AppIllustration } from '../AppIllustration'

const kindIcons: Record<NodeKind, typeof Server> = {
  wireguard: FileKey2,
  openvpn: ShieldCheck,
  socks5: Network,
  l2tp: KeyRound,
}

function KindChooser({ onChoose, disabled }: { onChoose: (kind: NodeKind) => void; disabled: boolean }) {
  return (
    <div className="vpn-kind-grid" role="group" aria-label="Choose the kind of VPN node">
      {vpnNodeKinds.map(({ kind, label, hint }) => {
        const Icon = kindIcons[kind]
        return (
          <button key={kind} type="button" disabled={disabled} onClick={() => onChoose(kind)}>
            <span className="vpn-kind-icon" aria-hidden="true">
              <Icon size={18} />
            </span>
            <strong>{label}</strong>
            <small>{hint}</small>
          </button>
        )
      })}
    </div>
  )
}

export function VpnNodePanel({
  nodes,
  selectedNodeId,
  live,
  assigned,
  busy,
  onChoose,
  onSelect,
  onTest,
  onRemove,
}: {
  nodes: VpnNode[]
  selectedNodeId: string | null
  /** The nodes the VPN is connecting or connected through. */
  live: Map<string, NodeLive>
  /** Enabled targets assigned to each node other than the default. */
  assigned: Map<string, number>
  busy: boolean
  onChoose: (kind: NodeKind) => void
  onSelect: (id: string) => Promise<void>
  onTest: (node: VpnNode) => Promise<void>
  onRemove: (id: string) => Promise<void>
}) {
  const [adding, setAdding] = useState(false)
  const [confirmRemove, setConfirmRemove] = useState<string | null>(null)
  const [pending, setPending] = useState<{ id: string; action: 'select' | 'test' | 'remove' } | null>(null)
  const working = busy || pending !== null
  const run = async (id: string, action: 'select' | 'test' | 'remove', work: () => Promise<void>) => {
    setPending({ id, action })
    try {
      await work()
    } finally {
      setPending(null)
      setConfirmRemove(null)
    }
  }

  return (
    <section className="vpn-card">
      <div className="card-head">
        <div>
          <h3>{nodes.length ? 'VPN nodes' : 'Add your first VPN node'}</h3>
          <small>The default node carries everything you have not assigned to another node.</small>
        </div>
        {nodes.length > 0 && (
          <button
            className="button secondary"
            disabled={working}
            aria-expanded={adding}
            onClick={() => setAdding(!adding)}
          >
            <Plus size={14} aria-hidden="true" />
            {adding ? 'Cancel' : 'Add node'}
          </button>
        )}
      </div>
      {nodes.length > 0 && (
        <>
          <p className="vpn-node-hint">
            Changing the default node reconnects a running VPN. To send an app or website through another node, pick it
            beside that target in Split tunnel.
          </p>
          <fieldset className="vpn-node-list" disabled={working} aria-busy={working}>
            <legend className="sr-only">Default VPN node</legend>
            {nodes.map((node) => {
              const Icon = kindIcons[node.kind]
              const selected = node.id === selectedNodeId
              const targets = assigned.get(node.id) ?? 0
              const status = live.get(node.id)
              const selecting = pending?.id === node.id && pending.action === 'select'
              const testing = pending?.id === node.id && pending.action === 'test'
              return (
                <div
                  className={`vpn-node${selected ? ' is-selected' : ''}${status && !selected ? ' is-in-use' : ''}`}
                  key={node.id}
                >
                  <label className="vpn-node-choice">
                    <input
                      type="radio"
                      name="vpn-node"
                      value={node.id}
                      checked={selected}
                      aria-label={`Make ${node.name} the default node`}
                      onChange={() => void run(node.id, 'select', () => onSelect(node.id))}
                    />
                    <span className="vpn-node-avatar" aria-hidden="true">
                      <Icon size={20} />
                    </span>
                    <span className="vpn-node-copy">
                      <span className="vpn-node-title">
                        <strong data-no-translate>{node.name}</strong>
                        <span className="kind-pill vpn-kind-pill">{nodeKindLabels[node.kind]}</span>
                      </span>
                      <span className="vpn-node-endpoint" data-no-translate>
                        <AddressWithCountry value={node.endpoint} />
                      </span>
                      {status && (
                        <span className={`vpn-route-live is-${status.state}`}>
                          <span className="vpn-route-dot" aria-hidden="true" />
                          {describeNodeLive(status)}
                        </span>
                      )}
                    </span>
                  </label>
                  <span className="vpn-node-selection" aria-live="polite">
                    {selecting
                      ? 'Switching…'
                      : selected
                        ? 'Default'
                        : targets
                          ? `Carries ${targets} target${targets === 1 ? '' : 's'}`
                          : 'Saved'}
                  </span>
                  <div className="vpn-node-actions">
                    {(node.kind === 'socks5' || node.kind === 'l2tp') && (
                      <button
                        className="button secondary"
                        aria-label={`Test ${node.name}`}
                        aria-busy={testing}
                        onClick={() => void run(node.id, 'test', () => onTest(node))}
                      >
                        <Zap size={14} aria-hidden="true" />
                        {testing ? 'Testing…' : 'Test'}
                      </button>
                    )}
                    {confirmRemove === node.id ? (
                      <>
                        <button
                          className="button danger-text"
                          onClick={() => void run(node.id, 'remove', () => onRemove(node.id))}
                        >
                          <Trash2 size={14} aria-hidden="true" />
                          Confirm remove
                        </button>
                        <button className="button secondary" onClick={() => setConfirmRemove(null)}>
                          Cancel
                        </button>
                      </>
                    ) : (
                      <button
                        className="icon-button danger"
                        aria-label={`Remove ${node.name}`}
                        onClick={() => setConfirmRemove(node.id)}
                      >
                        <Trash2 size={15} aria-hidden="true" />
                      </button>
                    )}
                  </div>
                  {confirmRemove === node.id && selected && (
                    <p className="vpn-node-remove-hint">Removing the default node turns the VPN off.</p>
                  )}
                  {confirmRemove === node.id && !selected && targets > 0 && (
                    <p className="vpn-node-remove-hint">Its targets move to the default node.</p>
                  )}
                </div>
              )
            })}
          </fieldset>
        </>
      )}
      {(!nodes.length || adding) && (
        <div className={!nodes.length ? 'vpn-first-node' : undefined}>
          {!nodes.length && <AppIllustration variant="vpn-girl" />}
          <KindChooser
            disabled={working}
            onChoose={(kind) => {
              setAdding(false)
              onChoose(kind)
            }}
          />
        </div>
      )}
    </section>
  )
}
