import { useEffect, useId, useRef, useState } from 'react'
import {
  Check,
  Ellipsis,
  LoaderCircle,
  MapPin,
  Settings2,
  Share2,
  ShieldCheck,
  Trash2,
  Upload,
  Zap,
} from 'lucide-react'
import { AddressWithCountry } from '../../IpLocation'
import type { Relay } from '../../types'
import './relay-card.css'

export function RelayCard({
  relay,
  selected,
  onSelect,
  onTest,
  onConfigureVps,
  onManual,
  onRemoveVps,
  onShare,
  onAccess,
  onDelete,
}: {
  relay: Relay
  selected: boolean
  onSelect: () => void
  onTest: () => Promise<void>
  onConfigureVps: () => void
  onManual: () => void
  onRemoveVps: () => void
  onShare: () => void
  onAccess: () => void
  onDelete: () => void
}) {
  const ready = relay.status === 'ready'
  const [testing, setTesting] = useState(false)
  const [expanded, setExpanded] = useState(false)
  const id = useId()
  const menu = useRef<HTMLDivElement>(null)
  const trigger = useRef<HTMLButtonElement>(null)
  const focusLast = useRef(false)
  useEffect(() => {
    if (!expanded) return
    const close = () => menu.current?.hidePopover()
    const onScroll = (event: Event) => {
      if (!menu.current?.contains(event.target as Node)) close()
    }
    window.addEventListener('resize', close)
    document.addEventListener('scroll', onScroll, true)
    return () => {
      window.removeEventListener('resize', close)
      document.removeEventListener('scroll', onScroll, true)
    }
  }, [expanded])
  const positionMenu = () => {
    const popup = menu.current
    const button = trigger.current
    if (!popup || !button) return
    const anchor = button.getBoundingClientRect()
    const { width, height } = popup.getBoundingClientRect()
    const left = document.documentElement.dir === 'rtl' ? anchor.left : anchor.right - width
    const top = anchor.bottom + height + 8 <= window.innerHeight ? anchor.bottom + 8 : anchor.top - height - 8
    popup.style.left = `${Math.max(12, Math.min(left, window.innerWidth - width - 12))}px`
    popup.style.top = `${Math.max(12, Math.min(top, window.innerHeight - height - 12))}px`
  }
  const action = (work: () => void) => {
    menu.current?.hidePopover()
    trigger.current?.focus()
    work()
  }

  return (
    <article className={`relay-card ${selected ? 'selected' : ''}`}>
      <button className="relay-choice" onClick={onSelect} aria-pressed={selected}>
        <span className="relay-radio">{selected && <Check size={14} aria-hidden="true" />}</span>
        <span className="relay-location-icon">
          <MapPin size={20} aria-hidden="true" />
        </span>
        <span className="relay-location">
          <span className="relay-name-row">
            <strong data-no-translate>{relay.city}</strong>
            <span className={`relay-status ${ready ? (selected ? 'enabled' : 'available') : 'setup'}`}>
              <i aria-hidden="true" />
              {ready ? (selected ? 'Enabled' : 'Disabled') : 'Setup required'}
            </span>
          </span>
          <span className="relay-endpoint" title={relay.address ? `${relay.address}:${relay.port}` : relay.country}>
            {relay.address ? (
              <AddressWithCountry value={relay.address} suffix={`:${relay.port}`} />
            ) : (
              <>
                <span data-no-translate>{relay.country}</span> · VPS not configured
              </>
            )}
          </span>
        </span>
      </button>
      <div className="relay-stat">
        <small>Latency</small>
        <strong data-no-translate>
          {relay.latency ?? '—'}
          <em> ms</em>
        </strong>
      </div>
      <div className="relay-actions">
        {ready ? (
          <>
            <button
              className="button secondary"
              disabled={testing}
              onClick={() => {
                setTesting(true)
                void onTest().finally(() => setTesting(false))
              }}
            >
              {testing ? (
                <LoaderCircle size={15} className="relay-test-spinner" aria-hidden="true" />
              ) : (
                <Zap size={15} aria-hidden="true" />
              )}
              {testing ? 'Testing…' : 'Test'}
            </button>
            <button className="button secondary relay-share" onClick={onShare} title="Share with a friend">
              <Share2 size={15} aria-hidden="true" /> Share
            </button>
          </>
        ) : (
          <button className="button primary" onClick={onConfigureVps}>
            Auto-configure VPS
          </button>
        )}
        <button
          className="button secondary relay-menu-trigger"
          ref={trigger}
          popoverTarget={id}
          aria-haspopup="menu"
          aria-expanded={expanded}
          aria-controls={id}
          onKeyDown={(event) => {
            if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return
            event.preventDefault()
            focusLast.current = event.key === 'ArrowUp'
            menu.current?.showPopover()
          }}
        >
          <Ellipsis size={18} aria-hidden="true" /> More
        </button>
        <div
          id={id}
          ref={menu}
          popover="auto"
          className="relay-menu"
          role="menu"
          aria-label="Relay options"
          onBeforeToggle={(event) => {
            if (event.newState !== 'open') return
            const popup = event.currentTarget
            popup.style.display = 'block'
            popup.style.visibility = 'hidden'
            positionMenu()
            popup.style.removeProperty('display')
            popup.style.removeProperty('visibility')
          }}
          onToggle={(event) => {
            const open = event.newState === 'open'
            setExpanded(open)
            if (open) {
              positionMenu()
              const items = menu.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]')
              const item = focusLast.current ? items?.[items.length - 1] : items?.[0]
              item?.focus()
            }
            focusLast.current = false
          }}
          onBlur={(event) => {
            if (!event.currentTarget.contains(event.relatedTarget) && event.relatedTarget !== trigger.current)
              menu.current?.hidePopover()
          }}
          onKeyDown={(event) => {
            const items = [...(menu.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]') ?? [])]
            const current = items.indexOf(document.activeElement as HTMLButtonElement)
            const next = {
              ArrowDown: (current + 1) % items.length,
              ArrowUp: (current - 1 + items.length) % items.length,
              Home: 0,
              End: items.length - 1,
            }[event.key]
            if (next !== undefined) {
              event.preventDefault()
              items[next]?.focus()
            }
            if (event.key === 'Tab') menu.current?.hidePopover()
          }}
        >
          <div className="relay-menu-heading" data-no-translate>
            {relay.city}
          </div>
          {ready && (
            <>
              <button role="menuitem" onClick={() => action(onAccess)}>
                <ShieldCheck size={16} aria-hidden="true" /> Manage access
              </button>
              <button role="menuitem" onClick={() => action(onConfigureVps)}>
                <Upload size={16} aria-hidden="true" /> Update VPS
              </button>
            </>
          )}
          <button role="menuitem" onClick={() => action(onManual)}>
            <Settings2 size={16} aria-hidden="true" /> Manual configuration
          </button>
          <div className="relay-menu-separator" role="separator" />
          {ready && (
            <button role="menuitem" className="relay-menu-danger" onClick={() => action(onRemoveVps)}>
              <Trash2 size={16} aria-hidden="true" /> Remove VPS
            </button>
          )}
          <button role="menuitem" className="relay-menu-danger" onClick={() => action(onDelete)}>
            <Trash2 size={16} aria-hidden="true" /> Remove from app
          </button>
        </div>
      </div>
    </article>
  )
}
