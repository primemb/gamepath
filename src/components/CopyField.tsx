import { useEffect, useState } from 'react'
import { Check, Copy } from 'lucide-react'

/** A value shown large enough to read across a room, with one-click copy. */
export function CopyField({ label, value, disabled = false }: { label: string; value: string; disabled?: boolean }) {
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (!copied) return
    const timer = window.setTimeout(() => setCopied(false), 1600)
    return () => window.clearTimeout(timer)
  }, [copied])

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }

  return (
    <div className={`copy-field ${disabled ? 'is-disabled' : ''}`}>
      <span>{label}</span>
      <strong data-no-translate>{value}</strong>
      <button type="button" className="icon-button" onClick={copy} disabled={disabled} aria-label={`Copy ${label}`}>
        {copied ? <Check size={15} aria-hidden="true" /> : <Copy size={15} aria-hidden="true" />}
      </button>
      <span className="sr-only" role="status" aria-atomic="true">
        {copied ? `${label} copied` : ''}
      </span>
    </div>
  )
}
