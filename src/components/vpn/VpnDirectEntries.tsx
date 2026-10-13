import { useId, useState, type FormEvent } from 'react'
import { AlertTriangle, Globe2, Network, Plus, Trash2 } from 'lucide-react'
import { api } from '../../api'
import { Toggle } from '../Toggle'
import { errorMessage } from '../Toast'
import type { AppState, DirectEntry, VpnState } from '../../types'
import type { RunChange } from './VpnDirectCard'

function EntryRow({ entry, run }: { entry: DirectEntry; run: RunChange }) {
  const Icon = entry.kind === 'ip' ? Network : Globe2
  return (
    <li className={`vpn-target ${entry.enabled ? '' : 'is-paused'}`}>
      <span className="vpn-target-icon" aria-hidden="true">
        <Icon size={16} />
      </span>
      <div className="vpn-target-copy">
        <strong data-no-translate>{entry.value}</strong>
        <small>{entry.kind === 'ip' ? 'Address or range' : 'Site and its subdomains'}</small>
      </div>
      <span className="vpn-target-kind">{entry.kind === 'ip' ? 'IP range' : 'Website'}</span>
      <Toggle
        checked={entry.enabled}
        onChange={(enabled) => void run(() => api.vpn.setDirectEntryEnabled(entry.id, enabled))}
        label={`${entry.enabled ? 'Stop sending' : 'Send'} ${entry.value} directly`}
      />
      <button
        className="icon-button danger"
        aria-label={`Remove ${entry.value}`}
        onClick={() => void run(() => api.vpn.removeDirectEntry(entry.id))}
      >
        <Trash2 size={15} aria-hidden="true" />
      </button>
    </li>
  )
}

/** Sites and addresses the user adds by hand, for what the lists miss. */
export function VpnDirectEntries({
  vpn,
  run,
  setState,
}: {
  vpn: VpnState
  run: RunChange
  setState: (next: AppState) => void
}) {
  const { direct } = vpn
  const [value, setValue] = useState('')
  const [failure, setFailure] = useState<string | null>(null)
  const [adding, setAdding] = useState(false)
  const inputId = useId()
  const hintId = useId()
  const errorId = useId()

  // The error belongs next to the field it is about, not in a toast.
  const add = async (event: FormEvent) => {
    event.preventDefault()
    if (!value.trim()) return
    setAdding(true)
    setFailure(null)
    try {
      setState(await api.vpn.addDirectEntry(value))
      setValue('')
    } catch (error) {
      setFailure(errorMessage(error))
    } finally {
      setAdding(false)
    }
  }

  const on = direct.entries.filter((entry) => entry.enabled).length

  return (
    <section className={`vpn-card vpn-targets ${direct.enabled ? '' : 'is-inactive'}`}>
      <div className="card-head">
        <h3>Your own sites and addresses</h3>
        <small>{direct.enabled ? `${on} on` : 'Direct sites are off'}</small>
      </div>
      <form className="vpn-direct-form" onSubmit={add} noValidate>
        <label htmlFor={inputId}>Website or IP address</label>
        <div className="vpn-direct-form-row">
          <input
            id={inputId}
            value={value}
            onChange={(event) => {
              setValue(event.target.value)
              if (failure) setFailure(null)
            }}
            placeholder="digikala.com or 185.143.232.0/22"
            spellCheck={false}
            autoComplete="off"
            aria-invalid={failure ? true : undefined}
            aria-describedby={failure ? `${errorId} ${hintId}` : hintId}
          />
          <button className="button secondary" type="submit" disabled={adding || !value.trim()}>
            <Plus size={14} aria-hidden="true" /> Add
          </button>
        </div>
        <small id={hintId}>A website includes its subdomains. Paste a link and only its site is kept.</small>
        {failure && (
          <p id={errorId} className="vpn-field-error field-error" role="alert">
            <AlertTriangle size={13} aria-hidden="true" /> {failure}
          </p>
        )}
      </form>
      {direct.entries.length ? (
        <ul className="vpn-target-list">
          {direct.entries.map((entry) => (
            <EntryRow key={entry.id} entry={entry} run={run} />
          ))}
        </ul>
      ) : (
        <div className="vpn-empty-targets">
          <Globe2 size={20} aria-hidden="true" />
          <strong>No sites of your own yet</strong>
          <p>Add a site the lists miss, such as your workplace, your bank or a local game server.</p>
        </div>
      )}
    </section>
  )
}
