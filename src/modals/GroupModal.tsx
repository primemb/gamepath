import { useState } from 'react'
import { Plus, X } from 'lucide-react'
import { errorMessage } from '../components/Toast'

/**
 * Names a group, whether of split-tunnel targets or of nodes.
 *
 * Both kinds of group are the same interaction — one field, one uniqueness
 * rule enforced in the main process — so they share a dialog and differ only
 * in the words describing what is being collected.
 */
export function GroupModal({
  eyebrow,
  createTitle,
  createIntro,
  editIntro,
  placeholder,
  initialName = '',
  onClose,
  onSave,
}: {
  eyebrow: string
  createTitle: string
  createIntro: string
  editIntro: string
  placeholder: string
  initialName?: string
  onClose: () => void
  onSave: (name: string) => Promise<void>
}) {
  const [name, setName] = useState(initialName)
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<string | null>(null)
  const editing = Boolean(initialName)

  const submit = async () => {
    if (!name.trim() || busy) return
    setBusy(true)
    setProblem(null)
    try {
      await onSave(name.trim())
    } catch (error) {
      setProblem(errorMessage(error))
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <form
        className="modal group-modal"
        onMouseDown={(event) => event.stopPropagation()}
        onSubmit={(event) => {
          event.preventDefault()
          void submit()
        }}
        role="dialog"
        aria-modal="true"
        aria-labelledby="group-modal-title"
      >
        <div className="modal-head">
          <div>
            <span className="eyebrow">{eyebrow}</span>
            <h2 id="group-modal-title">{editing ? 'Rename group' : createTitle}</h2>
          </div>
          <button type="button" className="icon-button" onClick={onClose} aria-label="Close group dialog">
            <X size={18} aria-hidden="true" />
          </button>
        </div>
        <p className="modal-intro">{editing ? editIntro : createIntro}</p>
        <label className="field-label">
          Group name
          <input
            autoFocus
            value={name}
            maxLength={64}
            onChange={(event) => setName(event.target.value)}
            placeholder={placeholder}
          />
        </label>
        {problem && (
          <p className="field-error" role="alert">
            {problem}
          </p>
        )}
        <div className="modal-actions">
          <button type="button" className="button secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="button primary" disabled={!name.trim() || busy}>
            <Plus size={16} aria-hidden="true" />
            {busy ? 'Saving…' : editing ? 'Save changes' : 'Create group'}
          </button>
        </div>
      </form>
    </div>
  )
}
