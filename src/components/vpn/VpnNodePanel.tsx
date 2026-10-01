import { useState } from 'react'
import { FileKey2, KeyRound, Network, Plus, RefreshCw, Server, ShieldCheck, Trash2, Zap } from 'lucide-react'
import { AddressWithCountry } from '../../IpLocation'
import { nodeKindLabels } from '../../lib/nodes'
import { vpnNodeKinds } from '../../lib/vpn'
import type { NodeKind, VpnNode } from '../../types'

const kindIcons: Record<NodeKind, typeof Server> = {
  wireguard: FileKey2,
  openvpn: ShieldCheck,
  socks5: Network,
  l2tp: KeyRound,
}

function KindChooser({ onChoose }: { onChoose: (kind: NodeKind) => void }) {
  return (
    <div className="vpn-kind-grid" role="group" aria-label="Choose the kind of VPN node">
      {vpnNodeKinds.map(({ kind, label, hint }) => {
        const Icon = kindIcons[kind]
        return (
          <button key={kind} type="button" onClick={() => onChoose(kind)}>
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

/** The VPN's one node: added, replaced, tested or removed here. */
export function VpnNodePanel({
  node,
  connected,
  onChoose,
  onTest,
  onRemove,
}: {
  node: VpnNode | null
  connected: boolean
  onChoose: (kind: NodeKind) => void
  onTest: (() => Promise<void>) | null
  onRemove: () => Promise<void>
}) {
  const [replacing, setReplacing] = useState(false)
  const [confirmRemove, setConfirmRemove] = useState(false)
  const [testing, setTesting] = useState(false)

  if (!node) {
    return (
      <section className="vpn-card vpn-node-empty">
        <div className="card-head">
          <h3>Add your VPN node</h3>
          <small>One node, connected directly. No relay needed.</small>
        </div>
        <KindChooser onChoose={onChoose} />
      </section>
    )
  }

  const Icon = kindIcons[node.kind]
  const test = async () => {
    if (!onTest) return
    setTesting(true)
    try {
      await onTest()
    } finally {
      setTesting(false)
    }
  }

  return (
    <section className="vpn-card">
      <div className="card-head">
        <h3>VPN node</h3>
        <small>{connected ? 'Carrying your selected traffic' : 'Used the next time the VPN turns on'}</small>
      </div>
      <div className="vpn-node">
        <span className="vpn-node-avatar" aria-hidden="true">
          <Icon size={20} />
        </span>
        <div className="vpn-node-copy">
          <div className="vpn-node-title">
            <strong data-no-translate>{node.name}</strong>
            <span className="kind-pill vpn-kind-pill">{nodeKindLabels[node.kind]}</span>
          </div>
          <span className="vpn-node-endpoint" data-no-translate>
            <AddressWithCountry value={node.endpoint} />
          </span>
        </div>
        <div className="vpn-node-actions">
          {onTest && (
            <button className="button secondary" disabled={testing} aria-busy={testing} onClick={test}>
              <Zap size={14} aria-hidden="true" />
              {testing ? 'Testing…' : 'Test'}
            </button>
          )}
          <button className="button secondary" aria-expanded={replacing} onClick={() => setReplacing(!replacing)}>
            <RefreshCw size={14} aria-hidden="true" />
            Replace
          </button>
          {confirmRemove ? (
            <button
              className="button danger-text"
              onClick={() => void onRemove().finally(() => setConfirmRemove(false))}
            >
              <Trash2 size={14} aria-hidden="true" />
              Confirm remove
            </button>
          ) : (
            <button
              className="icon-button danger"
              aria-label={`Remove ${node.name}`}
              onClick={() => setConfirmRemove(true)}
            >
              <Trash2 size={15} aria-hidden="true" />
            </button>
          )}
        </div>
      </div>
      {replacing && (
        <div className="vpn-replace">
          <p>
            <Plus size={13} aria-hidden="true" />
            {connected
              ? `Choose the new node. It replaces ${node.name}, and the VPN reconnects through it.`
              : `Choose the new node. It replaces ${node.name}.`}
          </p>
          <KindChooser
            onChoose={(kind) => {
              setReplacing(false)
              onChoose(kind)
            }}
          />
        </div>
      )}
    </section>
  )
}
