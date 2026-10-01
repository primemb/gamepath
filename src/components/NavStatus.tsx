import type { NavStatus as Status } from '../lib/navStatus'

/** A session's state beside its sidebar entry: a dot while on, a ring while getting there. */
export function NavStatus({ status }: { status: Status | null }) {
  if (!status) return null
  return (
    <span className={`nav-status is-${status.tone} is-${status.state}`} title={status.label}>
      <span className="sr-only">{status.label}</span>
    </span>
  )
}
