import { useRef, type KeyboardEvent, type ReactNode } from 'react'
import type { TabDefinition } from '../lib/views'

export type TabExtras = { badge?: number | null; dot?: 'live' | 'pending' | 'warning' | null }

const dotLabels = { live: 'Active', pending: 'Waiting', warning: 'Needs attention' }

export const tabId = (scope: string, id: string) => `${scope}-tab-${id}`
export const panelId = (scope: string, id: string) => `${scope}-panel-${id}`

/**
 * The WAI-ARIA tabs pattern with automatic activation: one tab stop, arrow keys
 * (mirrored right-to-left) and Home/End move between tabs.
 */
export function PageTabs<Id extends string>({
  scope,
  label,
  tabs,
  active,
  onChange,
  extras = {},
}: {
  scope: string
  label: string
  tabs: TabDefinition<Id>[]
  active: Id
  onChange: (next: Id) => void
  extras?: Partial<Record<Id, TabExtras>>
}) {
  const refs = useRef(new Map<Id, HTMLButtonElement>())

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const index = tabs.findIndex((tab) => tab.id === active)
    const rtl = document.documentElement.dir === 'rtl'
    const step = { ArrowRight: rtl ? -1 : 1, ArrowLeft: rtl ? 1 : -1 }[event.key]
    let next: number | null = null
    if (step) next = (index + step + tabs.length) % tabs.length
    else if (event.key === 'Home') next = 0
    else if (event.key === 'End') next = tabs.length - 1
    if (next === null) return
    event.preventDefault()
    const target = tabs[next].id
    onChange(target)
    refs.current.get(target)?.focus()
  }

  return (
    <div className={`page-tabs is-${scope}`} role="tablist" aria-label={label} onKeyDown={onKeyDown}>
      {tabs.map(({ id, label: tabLabel, icon: Icon }) => {
        const selected = id === active
        const { badge, dot } = extras[id] ?? {}
        return (
          <button
            key={id}
            ref={(element) => {
              if (element) refs.current.set(id, element)
              else refs.current.delete(id)
            }}
            id={tabId(scope, id)}
            type="button"
            role="tab"
            aria-selected={selected}
            aria-controls={panelId(scope, id)}
            tabIndex={selected ? 0 : -1}
            className={selected ? 'active' : ''}
            onClick={() => onChange(id)}
          >
            <Icon size={15} aria-hidden="true" />
            <span>{tabLabel}</span>
            {badge ? <b>{badge}</b> : null}
            {dot && (
              <i className={`page-tab-dot is-${dot}`}>
                <span className="sr-only">{dotLabels[dot]}</span>
              </i>
            )}
          </button>
        )
      })}
    </div>
  )
}

export function TabPanel({ scope, id, children }: { scope: string; id: string; children: ReactNode }) {
  return (
    <div key={id} className="page-tab-panel" role="tabpanel" id={panelId(scope, id)} aria-labelledby={tabId(scope, id)}>
      {children}
    </div>
  )
}
