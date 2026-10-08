import { useState } from 'react'
import { FileKey2, KeyRound, Network, Plus, Server, ShieldCheck, Trash2, Zap } from 'lucide-react'
import { AddressWithCountry } from '../../IpLocation'
import { nodeKindLabels } from '../../lib/nodes'
import { vpnNodeKinds } from '../../lib/vpn'
import type { NodeKind, VpnNode, VpnSession } from '../../types'
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
  session,
  busy,
  onChoose,
  onSelect,
  onTest,
  onRemove,
}: {
  nodes: VpnNode[]
  selectedNodeId: string | null
  session: VpnSession
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
          <small>Save multiple nodes. Only the selected node connects.</small>
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
            Switching nodes reconnects a running VPN. Adding a node keeps your current connection.
          </p>
          <fieldset className="vpn-node-list" disabled={working} aria-busy={working}>
            <legend className="sr-only">Selected VPN node</legend>
            {nodes.map((node) => {
              const Icon = kindIcons[node.kind]
              const selected = node.id === selectedNodeId
              const carrying = node.id === session.node?.id && session.status === 'connected'
              const selecting = pending?.id === node.id && pending.action === 'select'
              const testing = pending?.id === node.id && pending.action === 'test'
              return (
                <div className={`vpn-node${selected ? ' is-selected' : ''}`} key={node.id}>
                  <label className="vpn-node-choice">
                    <input
                      type="radio"
                      name="vpn-node"
                      value={node.id}
                      checked={selected}
                      aria-label={`Select ${node.name}`}
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
                    </span>
                  </label>
                  <span className="vpn-node-selection" aria-live="polite">
                    {selecting ? 'Switching…' : carrying ? 'Active' : selected ? 'Selected' : 'Saved'}
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
                    <p className="vpn-node-remove-hint">Removing the selected node turns the VPN off.</p>
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
