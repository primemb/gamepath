import { useEffect, useRef, type ReactNode } from 'react'
import { X } from 'lucide-react'
import './relay-invite.css'

export function RelayInviteFrame({
  title,
  eyebrow,
  busy,
  onClose,
  children,
}: {
  title: string
  eyebrow: string
  busy: boolean
  onClose: () => void
  children: ReactNode
}) {
  const frame = useRef<HTMLElement>(null)
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null
    const initial =
      frame.current?.querySelector<HTMLElement>('input') ?? frame.current?.querySelector<HTMLElement>('button')
    initial?.focus()
    return () => previous?.focus()
  }, [])

  return (
    <div className="modal-backdrop" onMouseDown={busy ? undefined : onClose}>
      <section
        ref={frame}
        className="modal relay-invite-modal"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        aria-busy={busy}
        tabIndex={-1}
        onMouseDown={(event) => event.stopPropagation()}
        onKeyDown={(event) => {
          if (event.key === 'Escape' && !busy) onClose()
          if (event.key !== 'Tab') return
          const controls = [
            ...(frame.current?.querySelectorAll<HTMLElement>(
              'button:not(:disabled), input:not(:disabled), [tabindex="0"]',
            ) ?? []),
          ].filter((element) => !element.closest('fieldset:disabled'))
          const first = controls[0]
          const last = controls.at(-1)
          if (!first) {
            event.preventDefault()
            frame.current?.focus()
            return
          }
          if (
            event.shiftKey &&
            (document.activeElement === first || !controls.includes(document.activeElement as HTMLElement))
          ) {
            event.preventDefault()
            last?.focus()
          } else if (
            !event.shiftKey &&
            (document.activeElement === last || !controls.includes(document.activeElement as HTMLElement))
          ) {
            event.preventDefault()
            first.focus()
          }
        }}
      >
        <div className="modal-head">
          <div>
            <span className="eyebrow">{eyebrow}</span>
            <h2>{title}</h2>
          </div>
          <button className="icon-button" disabled={busy} onClick={onClose} aria-label="Close dialog">
            <X size={18} aria-hidden="true" />
          </button>
        </div>
        {children}
      </section>
    </div>
  )
}
