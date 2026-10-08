import { useEffect, useRef, useState } from 'react'
import { Check, Copy, Download, ShieldCheck, Users } from 'lucide-react'
import { api } from '../api'
import { errorMessage } from '../components/Toast'
import { RelayInviteFrame } from './RelayInviteFrame'
import type { AppState, Relay } from '../types'

export function RelayShareModal({
  relay,
  onClose,
  setState,
}: {
  relay: Relay
  onClose: () => void
  setState: (state: AppState) => void
}) {
  const [recipientName, setRecipientName] = useState('')
  const [username, setUsername] = useState('root')
  const [password, setPassword] = useState('')
  const [sshPort, setSshPort] = useState('22')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [progress, setProgress] = useState('Connecting to the VPS over SSH')
  const [share, setShare] = useState<{ shareId: string; recipientName: string } | null>(null)
  const [feedback, setFeedback] = useState('')
  const ready = useRef<HTMLDivElement>(null)

  useEffect(
    () =>
      api.onRelayVpsProgress((update) => {
        if (update.relayId === relay.id) setProgress(update.message)
      }),
    [relay.id],
  )
  useEffect(() => {
    if (share) ready.current?.focus()
  }, [share])

  const run = async (work: () => Promise<void>) => {
    setError('')
    setFeedback('')
    setBusy(true)
    try {
      await work()
    } catch (cause) {
      setError(errorMessage(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    <RelayInviteFrame title="Share with a friend" eyebrow="Relay invitation" busy={busy} onClose={onClose}>
      {!share ? (
        <form
          onSubmit={(event) => {
            event.preventDefault()
            if (busy) return
            void run(async () => {
              const result = await api.createRelayShare(relay.id, {
                host: relay.address,
                sshPort: Number(sshPort),
                username: username.trim(),
                password,
                relayPort: relay.port,
                recipientName: recipientName.trim(),
              })
              setState(result.state)
              setPassword('')
              setShare(result)
            })
          }}
        >
          <div className="relay-invite-summary">
            <span className="relay-invite-symbol">
              <Users size={22} aria-hidden="true" />
            </span>
            <div>
              <strong data-no-translate>{relay.city}</strong>
              <small data-no-translate dir="ltr">
                {relay.address}:{relay.port}
              </small>
            </div>
            <span className="relay-invite-badge">Separate access</span>
          </div>
          <p className="modal-intro">
            Create a personal invitation so your friend can use this relay with their own VPN or proxy nodes.
          </p>
          <fieldset disabled={busy} className="relay-invite-fields">
            <label className="field-label">
              Friend name
              <input
                required
                maxLength={80}
                value={recipientName}
                onChange={(event) => setRecipientName(event.target.value)}
                placeholder="e.g. Ali"
                autoComplete="off"
              />
            </label>
            <div className="relay-fields">
              <label className="field-label">
                SSH username
                <input
                  required
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  autoComplete="username"
                />
              </label>
              <label className="field-label port-field">
                SSH port
                <input
                  required
                  inputMode="numeric"
                  type="number"
                  min={1}
                  max={65535}
                  value={sshPort}
                  onChange={(event) => setSshPort(event.target.value)}
                />
              </label>
            </div>
            <label className="field-label">
              SSH password
              <input
                required
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
              />
            </label>
          </fieldset>
          <p className="relay-invite-hint">
            <ShieldCheck size={16} aria-hidden="true" />
            <span>Your SSH password is used once and never included in the invitation.</span>
          </p>
          <div className="relay-invite-note">
            <strong>Everyone stays connected</strong>
            <p>New access is picked up automatically within a few seconds. Existing relay sessions keep running.</p>
          </div>
          {busy && (
            <p className="relay-invite-progress" role="status">
              <span className="relay-invite-spinner" aria-hidden="true" />
              {progress}
            </p>
          )}
          {error && (
            <p className="relay-invite-error" role="alert">
              {error}
            </p>
          )}
          <div className="modal-actions">
            <button className="button secondary" type="button" disabled={busy} onClick={onClose}>
              Cancel
            </button>
            <button
              className="button primary"
              disabled={busy || !recipientName.trim() || !username.trim() || !password || !sshPort}
              type="submit"
            >
              {busy ? 'Creating invitation…' : 'Create invitation'}
            </button>
          </div>
        </form>
      ) : (
        <>
          <div className="relay-invite-success" tabIndex={0} ref={ready}>
            <span className="relay-invite-symbol">
              <Check size={24} aria-hidden="true" />
            </span>
            <h3>Invitation ready</h3>
            <p data-no-translate>{share.recipientName}</p>
          </div>
          <p className="modal-intro">
            Send the link or file privately to this friend. It includes the relay address, port, and their personal
            access credential.
          </p>
          <div className="relay-invite-export">
            <button
              className="button primary"
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  await api.copyRelayShare(share.shareId)
                  setFeedback('Invitation link copied')
                })
              }
            >
              <Copy size={16} aria-hidden="true" />
              Copy invitation link
            </button>
            <button
              className="button secondary"
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  const result = await api.saveRelayShare(share.shareId)
                  if (!result.canceled) setFeedback('Invitation file saved')
                })
              }
            >
              <Download size={16} aria-hidden="true" />
              Save invitation file
            </button>
          </div>
          <div className="relay-invite-instructions">
            <strong>On your friend’s PC</strong>
            <ol>
              <li>Open Game → Connection → Import shared relay.</li>
              <li>Import the copied link or invitation file.</li>
              <li>Choose the relay, add their nodes, and connect in Relay mode.</li>
            </ol>
          </div>
          <p className="relay-invite-hint">
            Anyone with this invitation can use its access. Create a separate invitation for each friend.
          </p>
          {feedback && (
            <p className="relay-invite-feedback" role="status">
              {feedback}
            </p>
          )}
          {error && (
            <p className="relay-invite-error" role="alert">
              {error}
            </p>
          )}
          <div className="modal-actions">
            <button className="button secondary" disabled={busy} onClick={onClose}>
              Done
            </button>
          </div>
        </>
      )}
    </RelayInviteFrame>
  )
}
