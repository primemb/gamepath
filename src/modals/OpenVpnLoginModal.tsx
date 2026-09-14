import { useEffect, useRef, useState } from 'react'
import { Check, X } from 'lucide-react'
import { AddressWithCountry } from '../IpLocation'
import { errorMessage } from '../components/Toast'
import type { OpenVpnCandidate, OpenVpnRejection } from '../types'

/**
 * Asks for the login the chosen `.ovpn` files turned out to need.
 *
 * It appears only after the files have been read and at least one of them was
 * found to use `auth-user-pass`, so the question is never asked speculatively
 * and the files being added are named while it is asked. A provider issues one
 * login and a file per server, so the same pair covers all of them.
 */
export function OpenVpnLoginModal({
  files,
  rejected,
  onClose,
  onConfirm,
}: {
  files: OpenVpnCandidate[]
  rejected: OpenVpnRejection[]
  onClose: () => void
  onConfirm: (credentials: { username: string; password: string }) => Promise<OpenVpnRejection[]>
}) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [failures, setFailures] = useState<OpenVpnRejection[]>(rejected)
  const [problem, setProblem] = useState<string | null>(null)
  const summary = useRef<HTMLDivElement>(null)
  const complete = username.trim().length > 0 && password.length > 0

  // Moved to the summary so a keyboard or screen-reader user is taken to what
  // went wrong instead of being left on the button that reported it.
  useEffect(() => {
    if (failures.length || problem) summary.current?.focus()
  }, [failures, problem])

  const confirm = async () => {
    setBusy(true)
    setProblem(null)
    try {
      setFailures(await onConfirm({ username: username.trim(), password }))
    } catch (error) {
      // Without this the dialog would swallow anything the add could throw and
      // simply sit there, which is indistinguishable from a dead button.
      setProblem(errorMessage(error))
    } finally {
      setBusy(false)
    }
  }

  const clearFeedback = () => {
    setFailures([])
    setProblem(null)
  }

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section
        className="modal"
        onMouseDown={(event) => event.stopPropagation()}
        onKeyDown={(event) => {
          if (event.key === 'Escape') onClose()
        }}
        role="dialog"
        aria-modal="true"
        aria-label="Enter the OpenVPN login"
      >
        <div className="modal-head">
          <div>
            <span className="eyebrow">OpenVPN</span>
            <h2>{files.length === 1 ? 'This file needs a login' : 'These files need a login'}</h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </div>
        <p className="modal-intro">
          {files.length === 1 ? 'It uses' : 'They use'} <code>auth-user-pass</code>, so the server expects the username
          and password your provider gave you. They are encrypted by Windows and reused every session.
        </p>
        <ul className="chosen-files">
          {files.map((file) => (
            <li key={file.path}>
              <strong>{file.name}</strong>
              <span>
                <AddressWithCountry value={file.endpoint} /> · {file.protocol.toUpperCase()}
              </span>
            </li>
          ))}
        </ul>
        <form
          onSubmit={(event) => {
            event.preventDefault()
            void confirm()
          }}
        >
          <label className="field-label">
            Username
            <input
              autoFocus
              value={username}
              onChange={(event) => {
                setUsername(event.target.value)
                clearFeedback()
              }}
              placeholder="The login from your provider"
            />
          </label>
          <label className="field-label">
            Password
            <input
              type="password"
              value={password}
              onChange={(event) => {
                setPassword(event.target.value)
                clearFeedback()
              }}
              placeholder="Stored encrypted and never shown again"
            />
          </label>
          {(problem || failures.length > 0) && (
            <div className="import-summary" ref={summary} tabIndex={-1} role="alert">
              {problem ? (
                <>
                  <h3>The node could not be added</h3>
                  <p>{problem}</p>
                </>
              ) : (
                <>
                  <h3>
                    {failures.length === 1
                      ? '1 file could not be added'
                      : `${failures.length} files could not be added`}
                  </h3>
                  <ul>
                    {failures.map((failure) => (
                      <li key={failure.path}>
                        <strong>{failure.file}</strong>
                        {failure.message}
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          )}
          <div className="modal-actions">
            <button type="button" className="button secondary" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="button primary" disabled={busy || !complete}>
              <Check size={16} />
              {busy ? 'Adding…' : files.length === 1 ? 'Add node' : `Add ${files.length} nodes`}
            </button>
          </div>
        </form>
      </section>
    </div>
  )
}
