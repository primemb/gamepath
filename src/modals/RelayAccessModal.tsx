import { useEffect, useRef, useState } from 'react'
import { RefreshCw, ShieldCheck, UserRound, UserRoundMinus } from 'lucide-react'
import { api } from '../api'
import { errorMessage } from '../components/Toast'
import { RelayInviteFrame } from './RelayInviteFrame'
import type { AppState, Relay, RelayClientAccess } from '../types'
import './relay-access.css'

export function RelayAccessModal({
  relay,
  onClose,
  setState,
}: {
  relay: Relay
  onClose: () => void
  setState: (state: AppState) => void
}) {
  const [username, setUsername] = useState('root')
  const [password, setPassword] = useState('')
  const [sshPort, setSshPort] = useState('22')
  const [accessId, setAccessId] = useState<string | null>(null)
  const [clients, setClients] = useState<RelayClientAccess[]>([])
  const [target, setTarget] = useState<RelayClientAccess | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [feedback, setFeedback] = useState('')
  const list = useRef<HTMLDivElement>(null)
  const mounted = useRef(true)
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])
  useEffect(() => {
    if (!accessId) return
    list.current?.focus()
    return () => {
      void api.closeRelayAccess(accessId).catch(() => undefined)
    }
  }, [accessId])

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
    <RelayInviteFrame title="Manage relay access" eyebrow="VPS administration" busy={busy} onClose={onClose}>
      <div className="relay-invite-summary">
        <span className="relay-invite-symbol">
          <ShieldCheck size={22} aria-hidden="true" />
        </span>
        <div>
          <strong data-no-translate>{relay.city}</strong>
          <small data-no-translate dir="ltr">
            {relay.address}:{relay.port}
          </small>
        </div>
      </div>
      {!accessId ? (
        <form
          onSubmit={(event) => {
            event.preventDefault()
            if (busy) return
            void run(async () => {
              const result = await api.openRelayAccess(relay.id, {
                host: relay.address,
                username: username.trim(),
                password,
                sshPort: Number(sshPort),
                relayPort: relay.port,
              })
              if (!mounted.current) {
                await api.closeRelayAccess(result.accessId)
                return
              }
              setState(result.state)
              setClients(result.clients)
              setPassword('')
              setAccessId(result.accessId)
            })
          }}
        >
          <p className="modal-intro">
            Sign in with a VPS administrator account (root or sudo) to see and revoke enrolled clients. A relay
            invitation alone cannot manage access.
          </p>
          <fieldset className="relay-invite-fields" disabled={busy}>
            <div className="relay-fields">
              <label className="field-label">
                SSH username
                <input
                  required
                  autoComplete="username"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                />
              </label>
              <label className="field-label port-field">
                SSH port
                <input
                  required
                  type="number"
                  min={1}
                  max={65535}
                  inputMode="numeric"
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
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </label>
          </fieldset>
          <p className="relay-invite-hint">
            The SSH connection stays open only for this dialog, for up to 15 minutes. Your password is never saved.
          </p>
          {error && (
            <p className="relay-invite-error" role="alert">
              {error}
            </p>
          )}
          <div className="modal-actions">
            <button type="button" className="button secondary" disabled={busy} onClick={onClose}>
              Cancel
            </button>
            <button
              className="button primary"
              type="submit"
              disabled={busy || !username.trim() || !password || !sshPort}
            >
              {busy ? 'Signing in…' : 'View client access'}
            </button>
          </div>
        </form>
      ) : (
        <>
          <div className="relay-access-heading">
            <h3>
              Enrolled clients <span data-no-translate>{clients.length}</span>
            </h3>
            <button
              className="button secondary"
              disabled={busy || Boolean(target)}
              onClick={() => void run(async () => setClients(await api.listRelayAccess(accessId)))}
            >
              <RefreshCw size={14} aria-hidden="true" />
              Refresh
            </button>
          </div>
          <div className="relay-access-list" ref={list} tabIndex={0}>
            {clients.length === 0 ? (
              <p className="relay-invite-hint">No enrolled clients.</p>
            ) : (
              clients.map((client) => (
                <div className="relay-access-client" key={client.clientId}>
                  <UserRound size={18} aria-hidden="true" />
                  <div>
                    <strong data-no-translate>{client.name || client.clientId}</strong>
                    <small data-no-translate dir="ltr">
                      {client.virtualIpv4} · {client.clientId.slice(0, 8)}
                    </small>
                  </div>
                  {client.isCurrentClient ? (
                    <span className="relay-invite-badge">This PC</span>
                  ) : (
                    <button
                      className="button secondary danger"
                      disabled={busy || Boolean(target)}
                      onClick={() => {
                        setTarget(client)
                        setError('')
                        setFeedback('')
                      }}
                    >
                      <UserRoundMinus size={14} aria-hidden="true" />
                      <span>Revoke</span>
                      <span className="relay-access-sr" data-no-translate>
                        {' '}
                        {client.name}
                      </span>
                    </button>
                  )}
                </div>
              ))
            )}
          </div>
          {target && (
            <div className="relay-access-confirm" role="group" aria-label="Confirm access revocation">
              <strong>Revoke access?</strong>
              <p data-no-translate>
                {target.name} · {target.virtualIpv4}
              </p>
              <p>
                This client will disconnect within a few seconds. Their invitation will stop working, and they will need
                a new one to reconnect. Other users stay connected.
              </p>
              <div className="modal-actions">
                <button
                  autoFocus
                  className="button secondary"
                  disabled={busy}
                  onClick={() => {
                    setTarget(null)
                    list.current?.focus()
                  }}
                >
                  Keep access
                </button>
                <button
                  className="button danger"
                  disabled={busy}
                  onClick={() =>
                    void run(async () => {
                      setClients(await api.revokeRelayAccess(accessId, target.clientId))
                      setTarget(null)
                      setFeedback('Access revoked. Other relay sessions keep running.')
                      list.current?.focus()
                    })
                  }
                >
                  {busy ? 'Revoking…' : 'Revoke access'}
                </button>
              </div>
            </div>
          )}
          {error && (
            <p className="relay-invite-error" role="alert">
              {error}
            </p>
          )}
          {feedback && (
            <p className="relay-invite-feedback" role="status">
              {feedback}
            </p>
          )}
          {busy && !target && (
            <p className="relay-invite-progress" role="status">
              Loading client access…
            </p>
          )}
          <p className="relay-invite-hint">
            {clients.some((client) => client.isCurrentClient)
              ? 'Removing access affects this credential on every PC using it. Your current PC is protected here.'
              : 'Removing access affects this credential on every PC using it.'}
          </p>
          <div className="modal-actions">
            <button
              className="button secondary"
              disabled={busy}
              onClick={() => {
                setAccessId(null)
                setTarget(null)
                setClients([])
                setError('')
                setFeedback('')
              }}
            >
              Sign out
            </button>
            <button className="button primary" disabled={busy} onClick={onClose}>
              Done
            </button>
          </div>
        </>
      )}
    </RelayInviteFrame>
  )
}
