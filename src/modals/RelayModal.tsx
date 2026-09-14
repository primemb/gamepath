import { useState } from 'react'
import { Check, Plus, ShieldCheck, X } from 'lucide-react'
import type { Relay } from '../types'

export function RelayModal({
  relay,
  onClose,
  onSave,
  onImport,
}: {
  relay: Relay
  onClose: () => void
  onSave: (input: { address: string; port: number; enrollmentToken?: string }) => Promise<void>
  onImport: () => Promise<void>
}) {
  const [address, setAddress] = useState(relay.address)
  const [port, setPort] = useState(String(relay.port || 51821))
  const [enrollmentToken, setEnrollmentToken] = useState('')
  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section
        className="modal relay-modal"
        onMouseDown={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Configure relay"
      >
        <div className="modal-head">
          <div>
            <span className="eyebrow">
              {relay.city}, {relay.country}
            </span>
            <h2>Configure relay endpoint</h2>
          </div>
          <button className="icon-button" onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <p className="modal-intro">
          Set the public endpoint and its unique client credential. The credential is encrypted by Windows and is never
          shown again after saving.
        </p>
        <div className="relay-fields">
          <label className="field-label">
            Hostname or IP address
            <input
              autoFocus
              value={address}
              onChange={(event) => setAddress(event.target.value)}
              placeholder="relay.example.com"
            />
          </label>
          <label className="field-label port-field">
            UDP port
            <input
              value={port}
              onChange={(event) => setPort(event.target.value.replace(/\D/g, '').slice(0, 5))}
              placeholder="51821"
            />
          </label>
        </div>
        <label className="field-label enrollment-field">
          Enrollment token
          <input
            type="password"
            value={enrollmentToken}
            onChange={(event) => setEnrollmentToken(event.target.value)}
            placeholder={
              relay.hasEnrollmentToken ? 'Credential already protected — leave blank to keep it' : 'Paste gpe1_… token'
            }
          />
        </label>
        <button className="file-import-button" onClick={onImport}>
          <ShieldCheck size={15} />
          Import a .enroll file<span>{relay.hasEnrollmentToken ? 'Credential protected' : 'Recommended'}</span>
        </button>
        <div className="modal-actions">
          <button className="button secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            className="button primary"
            disabled={!address.trim() || !port || (!relay.hasEnrollmentToken && !enrollmentToken.trim())}
            onClick={() =>
              onSave({
                address: address.trim(),
                port: Number(port),
                enrollmentToken: enrollmentToken.trim() || undefined,
              })
            }
          >
            <Check size={16} />
            Save relay
          </button>
        </div>
      </section>
    </div>
  )
}

export function AddRelayModal({
  onClose,
  onAdd,
}: {
  onClose: () => void
  onAdd: (input: { city: string; country: string }) => Promise<void>
}) {
  const [city, setCity] = useState('Istanbul')
  const [country, setCountry] = useState('Turkey')
  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section className="modal relay-modal" onMouseDown={(event) => event.stopPropagation()}>
        <div className="modal-head">
          <div>
            <span className="eyebrow">New location</span>
            <h2>Add relay server</h2>
          </div>
          <button className="icon-button" onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <div className="relay-fields">
          <label className="field-label">
            City or label
            <input autoFocus value={city} onChange={(event) => setCity(event.target.value)} />
          </label>
          <label className="field-label">
            Country
            <input value={country} onChange={(event) => setCountry(event.target.value)} />
          </label>
        </div>
        <div className="modal-actions">
          <button className="button secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            className="button primary"
            disabled={!city.trim() || !country.trim()}
            onClick={() => onAdd({ city: city.trim(), country: country.trim() })}
          >
            <Plus size={16} />
            Add relay
          </button>
        </div>
      </section>
    </div>
  )
}
