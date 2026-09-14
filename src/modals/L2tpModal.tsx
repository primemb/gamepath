import { useState } from 'react'
import { Check, Info, X, Zap } from 'lucide-react'
import { errorMessage } from '../components/Toast'
import type { L2tpNodeInput, L2tpProbeResult } from '../types'

export function L2tpModal({
  onClose,
  onAdd,
  onTest,
}: {
  onClose: () => void
  onAdd: (input: L2tpNodeInput) => Promise<void>
  onTest: (input: L2tpNodeInput) => Promise<L2tpProbeResult>
}) {
  const [server, setServer] = useState('')
  const [label, setLabel] = useState('')
  const [preSharedKey, setPreSharedKey] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState<'idle' | 'testing' | 'saving'>('idle')
  const [result, setResult] = useState<string | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  const input = (): L2tpNodeInput => ({
    server: server.trim(),
    label: label.trim() || undefined,
    preSharedKey,
    username: username.trim(),
    password,
  })
  const complete = Boolean(server.trim() && preSharedKey && username.trim() && password)

  const testConnection = async () => {
    setBusy('testing')
    setResult(null)
    setFailure(null)
    try {
      const probe = await onTest(input())
      setResult(
        `Windows completed L2TP/IPsec in ${Math.round(probe.setupLatencyMs)} ms, received ${probe.assignedIpv4}, and returned data in ${Math.round(probe.dataLatencyMs)} ms.`,
      )
    } catch (error) {
      setFailure(errorMessage(error))
    } finally {
      setBusy('idle')
    }
  }

  const save = async () => {
    setBusy('saving')
    setFailure(null)
    try {
      await onAdd(input())
    } catch (error) {
      setFailure(errorMessage(error))
      setBusy('idle')
    }
  }

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section
        className="modal relay-modal"
        onMouseDown={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Add an L2TP/IPsec node"
      >
        <div className="modal-head">
          <div>
            <span className="eyebrow">Windows VPN</span>
            <h2>Add an L2TP/IPsec node</h2>
          </div>
          <button className="icon-button" onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <p className="modal-intro">
          This uses the Windows L2TP/IPsec client in both relay and direct mode. The temporary Windows profile is
          removed whenever GamePath disconnects. Direct split routing supports IPv4 ranges and exact hostnames.
        </p>
        <label className="field-label">
          Server hostname or IPv4 address
          <input
            autoFocus
            value={server}
            onChange={(event) => setServer(event.target.value)}
            placeholder="vpn.example.com"
          />
        </label>
        <label className="field-label">
          Name (optional)
          <input value={label} onChange={(event) => setLabel(event.target.value)} placeholder="Provider L2TP" />
        </label>
        <label className="field-label">
          IPsec pre-shared key
          <input
            type="password"
            value={preSharedKey}
            onChange={(event) => setPreSharedKey(event.target.value)}
            placeholder="Required"
          />
        </label>
        <div className="relay-fields">
          <label className="field-label">
            Username
            <input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" />
          </label>
          <label className="field-label">
            Password
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
            />
          </label>
        </div>
        {result && (
          <div className="info-banner">
            <Check size={18} />
            <div>
              <strong>The L2TP connection works</strong>
              <p>{result}</p>
            </div>
          </div>
        )}
        {failure && (
          <div className="info-banner">
            <Info size={18} />
            <div>
              <strong>Windows could not connect</strong>
              <p>{failure}</p>
            </div>
          </div>
        )}
        <div className="modal-actions">
          <button className="button secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="button secondary" disabled={!complete || busy !== 'idle'} onClick={testConnection}>
            <Zap size={16} />
            {busy === 'testing' ? 'Testing…' : 'Test connection'}
          </button>
          <button className="button primary" disabled={!complete || busy !== 'idle'} onClick={save}>
            <Check size={16} />
            {busy === 'saving' ? 'Saving…' : 'Add node'}
          </button>
        </div>
      </section>
    </div>
  )
}
