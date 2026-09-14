import { useEffect, useState } from 'react'
import { X } from 'lucide-react'
import { api } from '../api'
import type { Relay } from '../types'

/**
 * How far a stage can carry the bar before the next progress update arrives.
 *
 * A Rust build reports nothing for minutes, so the bar creeps toward the
 * ceiling of its stage rather than sitting still and looking hung — and never
 * past it, so it cannot claim progress the deployment has not made.
 */
const vpsProgressCeilings: Record<string, number> = {
  preparing: 1,
  connect: 6,
  verify: 9,
  upload: 31,
  install: 37,
  dependencies: 54,
  compile: 71,
  network: 83,
  service: 91,
  enrollment: 95,
  credential: 99,
  remove: 99,
  complete: 100,
}

export function VpsModal({
  relay,
  action,
  onClose,
  onSubmit,
}: {
  relay: Relay
  action: 'provision' | 'remove'
  onClose: () => void
  onSubmit: (input: {
    host: string
    sshPort: number
    username: string
    password: string
    relayPort: number
  }) => Promise<void>
}) {
  const [host, setHost] = useState(relay.address)
  const [sshPort, setSshPort] = useState('22')
  const [username, setUsername] = useState('root')
  const [password, setPassword] = useState('')
  const [relayPort, setRelayPort] = useState(String(relay.port || 51821))
  const [busy, setBusy] = useState(false)
  const [progress, setProgress] = useState({ stage: 'preparing', percent: 0, message: 'Preparing deployment' })

  useEffect(
    () =>
      api.onRelayVpsProgress((update) => {
        if (update.relayId === relay.id) {
          setProgress((current) => ({
            stage: update.stage,
            percent: Math.max(current.percent, update.percent),
            message: update.message,
          }))
        }
      }),
    [relay.id],
  )

  useEffect(() => {
    if (!busy) return undefined
    const timer = window.setInterval(() => {
      setProgress((current) => {
        const ceiling = vpsProgressCeilings[current.stage] ?? 99
        if (current.percent >= ceiling) return current
        const remaining = ceiling - current.percent
        return { ...current, percent: Math.min(ceiling, current.percent + Math.max(0.2, remaining * 0.08)) }
      })
    }, 600)
    return () => window.clearInterval(timer)
  }, [busy])

  const displayedPercent = Math.min(100, Math.round(progress.percent))
  const incomplete = !host.trim() || !username.trim() || !password || !sshPort || !relayPort

  return (
    <div className="modal-backdrop" onMouseDown={busy ? undefined : onClose}>
      <section className="modal relay-modal" onMouseDown={(event) => event.stopPropagation()}>
        <div className="modal-head">
          <div>
            <span className="eyebrow">Secure SSH setup</span>
            <h2>{action === 'provision' ? 'Configure Linux VPS' : 'Remove relay from VPS'}</h2>
          </div>
          <button className="icon-button" disabled={busy} onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <p className="modal-intro">
          {action === 'provision'
            ? "GamePath supports Debian 13+ and Ubuntu 22.04+. It uploads the relay source, installs dependencies, configures the service and firewall, then imports this PC's enrollment automatically."
            : 'This removes the GamePath service, firewall tables, configuration, clients, and binary from this server.'}{' '}
          The SSH password is used only for this operation and is never saved.
        </p>
        <div className="relay-fields">
          <label className="field-label">
            VPS hostname or IP
            <input
              autoFocus
              value={host}
              onChange={(event) => setHost(event.target.value)}
              placeholder="203.0.113.10"
            />
          </label>
          <label className="field-label port-field">
            SSH port
            <input
              value={sshPort}
              onChange={(event) => setSshPort(event.target.value.replace(/\D/g, '').slice(0, 5))}
            />
          </label>
        </div>
        <div className="relay-fields">
          <label className="field-label">
            SSH username
            <input value={username} onChange={(event) => setUsername(event.target.value)} />
          </label>
          <label className="field-label">
            SSH password
            <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} />
          </label>
        </div>
        {action === 'provision' && (
          <label className="field-label enrollment-field">
            Relay UDP port
            <input
              value={relayPort}
              onChange={(event) => setRelayPort(event.target.value.replace(/\D/g, '').slice(0, 5))}
            />
          </label>
        )}
        {busy && (
          <div className="vps-progress">
            <div>
              <strong role="status" aria-live="polite">
                {progress.message}
              </strong>
              <span>{displayedPercent}%</span>
            </div>
            <i
              role="progressbar"
              aria-label="VPS configuration progress"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={displayedPercent}
            >
              <b style={{ transform: `scaleX(${progress.percent / 100})` }} />
            </i>
            <small>Keep GamePath open. A first-time Rust build can take several minutes.</small>
          </div>
        )}
        <div className="modal-actions">
          <button className="button secondary" disabled={busy} onClick={onClose}>
            Cancel
          </button>
          <button
            className={`button ${action === 'remove' ? 'danger' : 'primary'}`}
            disabled={busy || incomplete}
            onClick={async () => {
              setProgress({ stage: 'preparing', percent: 1, message: 'Preparing deployment' })
              setBusy(true)
              try {
                await onSubmit({
                  host: host.trim(),
                  sshPort: Number(sshPort),
                  username: username.trim(),
                  password,
                  relayPort: Number(relayPort),
                })
              } finally {
                setBusy(false)
              }
            }}
          >
            {busy
              ? action === 'provision'
                ? 'Configuring VPS…'
                : 'Removing…'
              : action === 'provision'
                ? 'Configure VPS'
                : 'Remove from VPS'}
          </button>
        </div>
      </section>
    </div>
  )
}
