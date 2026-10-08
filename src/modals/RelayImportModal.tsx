import { useEffect, useRef, useState } from 'react'
import { ClipboardPaste, FileUp, ShieldCheck } from 'lucide-react'
import { api } from '../api'
import { errorMessage } from '../components/Toast'
import { RelayInviteFrame } from './RelayInviteFrame'
import type { AppState, RelayInviteDetails } from '../types'

export function RelayImportModal({
  onClose,
  onImported,
}: {
  onClose: () => void
  onImported: (state: AppState) => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [preview, setPreview] = useState<{ id: string; details: RelayInviteDetails } | null>(null)
  const details = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (preview) details.current?.focus()
  }, [preview])
  const run = async (work: () => Promise<void>) => {
    setError('')
    setBusy(true)
    try {
      await work()
    } catch (cause) {
      setError(errorMessage(cause))
    } finally {
      setBusy(false)
    }
  }
  const read = (source: 'clipboard' | 'file') =>
    run(async () => {
      const result = await api.previewRelayInvite(source)
      if (result.invitationId && result.details) setPreview({ id: result.invitationId, details: result.details })
    })

  return (
    <RelayInviteFrame title="Import shared relay" eyebrow="Invited by a friend" busy={busy} onClose={onClose}>
      <p className="modal-intro">
        Your friend’s invitation adds the relay address and your personal access. You do not need their VPS login.
      </p>
      {!preview ? (
        <div className="relay-invite-import-options">
          <button disabled={busy} onClick={() => void read('clipboard')}>
            <ClipboardPaste size={23} aria-hidden="true" />
            <strong>Import from clipboard</strong>
            <small>Copy your friend’s invitation link first.</small>
          </button>
          <button disabled={busy} onClick={() => void read('file')}>
            <FileUp size={23} aria-hidden="true" />
            <strong>Choose invitation file</strong>
            <small>Open the .gprelay file they sent you.</small>
          </button>
        </div>
      ) : (
        <div className="relay-invite-details" tabIndex={0} ref={details}>
          <div className="relay-invite-summary">
            <span className="relay-invite-symbol">
              <ShieldCheck size={22} aria-hidden="true" />
            </span>
            <div>
              <strong data-no-translate>{preview.details.city}</strong>
              <small data-no-translate>{preview.details.country}</small>
            </div>
            <span className="relay-invite-badge">Ready to add</span>
          </div>
          <dl>
            <div>
              <dt>Relay address</dt>
              <dd data-no-translate dir="ltr">
                {preview.details.address}:{preview.details.port}
              </dd>
            </div>
            <div>
              <dt>Invited as</dt>
              <dd data-no-translate>{preview.details.recipientName}</dd>
            </div>
          </dl>
        </div>
      )}
      <p className="relay-invite-hint">You still need your own VPN or proxy nodes to reach this relay.</p>
      {busy && (
        <p className="relay-invite-progress" role="status">
          {preview ? 'Adding relay…' : 'Reading invitation…'}
        </p>
      )}
      {error && (
        <p className="relay-invite-error" role="alert">
          {error}
        </p>
      )}
      <div className="modal-actions">
        <button
          className="button secondary"
          disabled={busy}
          onClick={
            preview
              ? () => {
                  setPreview(null)
                  setError('')
                }
              : onClose
          }
        >
          {preview ? 'Back' : 'Cancel'}
        </button>
        {preview && (
          <button
            className="button primary"
            disabled={busy}
            onClick={() => void run(async () => onImported(await api.acceptRelayInvite(preview.id)))}
          >
            Add relay
          </button>
        )}
      </div>
    </RelayInviteFrame>
  )
}
