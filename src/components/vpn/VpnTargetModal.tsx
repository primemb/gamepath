import { useState } from 'react'
import { AlertTriangle, AppWindow, FolderOpen, Globe2, Network, Plus, X } from 'lucide-react'
import { api } from '../../api'
import { errorMessage } from '../Toast'
import type { RuleKind, VpnRule } from '../../types'

const kinds: { id: RuleKind; label: string; icon: typeof AppWindow; needsApps: boolean }[] = [
  { id: 'application', label: 'Application', icon: AppWindow, needsApps: true },
  { id: 'folder', label: 'Folder', icon: FolderOpen, needsApps: true },
  { id: 'hostname', label: 'Website', icon: Globe2, needsApps: false },
  { id: 'ip', label: 'IP address', icon: Network, needsApps: false },
]

/** Adds one app, folder, website or address to the VPN. */
export function VpnTargetModal({
  canSelectApps,
  initialKind,
  onClose,
  onSave,
}: {
  canSelectApps: boolean
  initialKind: RuleKind
  onClose: () => void
  onSave: (input: Pick<VpnRule, 'kind' | 'value' | 'label'>) => Promise<void>
}) {
  const [kind, setKind] = useState<RuleKind>(canSelectApps ? initialKind : 'hostname')
  const [value, setValue] = useState('')
  const [label, setLabel] = useState('')
  const [saving, setSaving] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)

  const browse = async () => {
    const result = await api.vpn.browseTarget(kind)
    if (!result.canceled && result.value) {
      setValue(result.value)
      setLabel(result.label ?? result.value)
    }
  }

  const save = async () => {
    setSaving(true)
    setFailure(null)
    try {
      await onSave({ kind, value: value.trim(), label: label || value.trim() })
    } catch (error) {
      setFailure(errorMessage(error))
      setSaving(false)
    }
  }

  const picksFile = kind === 'application' || kind === 'folder'

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section
        className="modal"
        onMouseDown={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Add a VPN target"
      >
        <div className="modal-head">
          <div>
            <span className="eyebrow">VPN target</span>
            <h2>Choose what uses the VPN</h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close">
            <X size={18} aria-hidden="true" />
          </button>
        </div>
        <p className="modal-intro">
          Matching traffic goes through your VPN node. Your game session still comes first for anything it selects.
        </p>
        <div className="kind-grid">
          {kinds.map((item) => {
            const Icon = item.icon
            const unavailable = item.needsApps && !canSelectApps
            return (
              <button
                key={item.id}
                className={kind === item.id ? 'active' : ''}
                aria-pressed={kind === item.id}
                disabled={unavailable}
                title={unavailable ? 'An L2TP/IPsec node in split mode routes by address only' : undefined}
                onClick={() => {
                  setKind(item.id)
                  setValue('')
                  setLabel('')
                  setFailure(null)
                }}
              >
                <Icon size={17} aria-hidden="true" />
                {item.label}
              </button>
            )
          })}
        </div>
        {picksFile ? (
          <button className="file-drop" onClick={browse}>
            <span className="file-drop-icon">
              <FolderOpen size={22} aria-hidden="true" />
            </span>
            <strong>{value ? label : `Choose ${kind === 'application' ? 'an application' : 'a folder'}`}</strong>
            <small>
              {value || (kind === 'application' ? 'Select its .exe file' : 'Every application inside will match')}
            </small>
          </button>
        ) : (
          <label className="field-label">
            {kind === 'hostname' ? 'Website or hostname' : 'IP or CIDR range'}
            <input
              autoFocus
              value={value}
              onChange={(event) => {
                setValue(event.target.value)
                setLabel(event.target.value)
                setFailure(null)
              }}
              placeholder={kind === 'hostname' ? 'news.example.com or *.example.com' : '203.0.113.20 or 203.0.113.0/24'}
              aria-invalid={Boolean(failure)}
              aria-describedby={failure ? 'vpn-target-error' : undefined}
            />
          </label>
        )}
        {failure && (
          <p className="field-error vpn-field-error" id="vpn-target-error" role="alert">
            <AlertTriangle size={14} aria-hidden="true" /> {failure}
          </p>
        )}
        <div className="modal-actions">
          <button className="button secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="button primary" disabled={!value.trim() || saving} aria-busy={saving} onClick={save}>
            <Plus size={16} aria-hidden="true" />
            {saving ? 'Adding…' : 'Add target'}
          </button>
        </div>
      </section>
    </div>
  )
}
