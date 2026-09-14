import { useState } from 'react'
import { Check, Info, X, Zap } from 'lucide-react'
import { errorMessage } from '../components/Toast'
import type { Socks5NodeInput, Socks5ProbeResult } from '../types'

export function Socks5Modal({
  onClose,
  onAdd,
  onTest,
}: {
  onClose: () => void
  onAdd: (input: Socks5NodeInput) => Promise<void>
  onTest: (input: Socks5NodeInput) => Promise<Socks5ProbeResult>
}) {
  const [address, setAddress] = useState('')
  const [label, setLabel] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState<'idle' | 'testing' | 'saving'>('idle')
  const [result, setResult] = useState<string | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  const input = (): Socks5NodeInput => ({
    address: address.trim(),
    label: label.trim() || undefined,
    username: username.trim() || undefined,
    password: password || undefined,
  })

  const runTest = async () => {
    setBusy('testing')
    setResult(null)
    setFailure(null)
    try {
      const probe = await onTest(input())
      setResult(
        `UDP works through ${probe.proxy}: relay answered in ${Math.round(probe.latencyMs)} ms ` +
          `(${Math.round(probe.setupLatencyMs)} ms to open the association).`,
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
        aria-label="Add a SOCKS5 node"
      >
        <div className="modal-head">
          <div>
            <span className="eyebrow">SOCKS5 proxy</span>
            <h2>Add a proxy node</h2>
          </div>
          <button className="icon-button" onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <p className="modal-intro">
          GamePath carries game traffic as UDP, so the proxy has to support <strong>UDP ASSOCIATE</strong>. Test the
          node before saving: some proxies accept the association and then never forward a datagram.
        </p>
        <label className="field-label">
          Proxy address
          <input
            autoFocus
            value={address}
            onChange={(event) => setAddress(event.target.value)}
            placeholder="127.0.0.1:2080 or socks5://user:password@proxy.example:1080"
          />
        </label>
        <label className="field-label">
          Name (optional)
          <input value={label} onChange={(event) => setLabel(event.target.value)} placeholder="Local proxy" />
        </label>
        <div className="relay-fields">
          <label className="field-label">
            Username (optional)
            <input value={username} onChange={(event) => setUsername(event.target.value)} placeholder="Leave blank" />
          </label>
          <label className="field-label">
            Password (optional)
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Leave blank"
            />
          </label>
        </div>
        {result && (
          <div className="info-banner">
            <Check size={18} />
            <div>
              <strong>This proxy can carry GamePath traffic</strong>
              <p>{result}</p>
            </div>
          </div>
        )}
        {failure && (
          <div className="info-banner">
            <Info size={18} />
            <div>
              <strong>This proxy cannot be used yet</strong>
              <p>{failure}</p>
            </div>
          </div>
        )}
        <div className="modal-actions">
          <button className="button secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="button secondary" disabled={!address.trim() || busy !== 'idle'} onClick={runTest}>
            <Zap size={16} />
            {busy === 'testing' ? 'Testing…' : 'Test UDP'}
          </button>
          <button className="button primary" disabled={!address.trim() || busy !== 'idle'} onClick={save}>
            <Check size={16} />
            {busy === 'saving' ? 'Saving…' : 'Add node'}
          </button>
        </div>
      </section>
    </div>
  )
}
