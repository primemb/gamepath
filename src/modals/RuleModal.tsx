import { useState } from 'react'
import { AppWindow, FolderOpen, Globe2, Network, Plus, X } from 'lucide-react'
import { api } from '../api'
import type { AddRuleInput, RuleKind, SplitRuleGroup } from '../types'

const kinds: { id: RuleKind; label: string; icon: typeof AppWindow }[] = [
  { id: 'application', label: 'Application', icon: AppWindow },
  { id: 'folder', label: 'Folder', icon: FolderOpen },
  { id: 'hostname', label: 'Hostname', icon: Globe2 },
  { id: 'ip', label: 'IP address', icon: Network },
]

export function RuleModal({
  groups,
  initialGroupId,
  onClose,
  onSave,
}: {
  groups: SplitRuleGroup[]
  initialGroupId: string | null
  onClose: () => void
  onSave: (input: AddRuleInput) => Promise<void>
}) {
  const [kind, setKind] = useState<RuleKind>('application')
  const [value, setValue] = useState('')
  const [label, setLabel] = useState('')
  const [groupId, setGroupId] = useState(initialGroupId ?? '')

  const browse = async () => {
    const result = await api.browseRuleTarget(kind)
    if (!result.canceled && result.value) {
      setValue(result.value)
      setLabel(result.label ?? result.value)
    }
  }

  const placeholder = kind === 'hostname' ? 'game.example.com or *.example.com' : '203.0.113.20 or 203.0.113.0/24'

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section
        className="modal"
        onMouseDown={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Add split tunnel target"
      >
        <div className="modal-head">
          <div>
            <span className="eyebrow">Traffic rule</span>
            <h2>Add a split-tunnel target</h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close add target dialog">
            <X size={18} aria-hidden="true" />
          </button>
        </div>
        <p className="modal-intro">
          Only matching traffic will use GamePath. Everything else stays on your normal connection.
        </p>
        <div className="kind-grid">
          {kinds.map((item) => {
            const Icon = item.icon
            return (
              <button
                key={item.id}
                className={kind === item.id ? 'active' : ''}
                onClick={() => {
                  setKind(item.id)
                  setValue('')
                  setLabel('')
                }}
              >
                <Icon size={17} />
                {item.label}
              </button>
            )
          })}
        </div>
        {kind === 'application' || kind === 'folder' ? (
          <button className="file-drop" onClick={browse}>
            <span className="file-drop-icon">
              <FolderOpen size={22} />
            </span>
            <strong>{value ? label : `Choose ${kind === 'application' ? 'an executable' : 'a folder'}`}</strong>
            <small>
              {value || (kind === 'application' ? 'Select the game .exe file' : 'All applications inside will match')}
            </small>
          </button>
        ) : (
          <label className="field-label">
            {kind === 'hostname' ? 'Hostname' : 'IP or CIDR range'}
            <input
              autoFocus
              value={value}
              onChange={(event) => {
                setValue(event.target.value)
                setLabel(event.target.value)
              }}
              placeholder={placeholder}
            />
          </label>
        )}
        <label className="field-label">
          Group
          <select value={groupId} onChange={(event) => setGroupId(event.target.value)}>
            <option value="">Ungrouped</option>
            {groups.map((group) => (
              <option key={group.id} value={group.id}>
                {group.name}
              </option>
            ))}
          </select>
          <small>Groups let you pause a whole game or workflow without changing its individual targets.</small>
        </label>
        <div className="modal-actions">
          <button className="button secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            className="button primary"
            disabled={!value.trim()}
            onClick={() => onSave({ kind, value, label: label || value, groupId: groupId || null })}
          >
            <Plus size={16} />
            Add target
          </button>
        </div>
      </section>
    </div>
  )
}
