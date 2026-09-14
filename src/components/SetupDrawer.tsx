import { Check, ChevronDown, ChevronRight, Gamepad2, Globe2, ListChecks, MapPin } from 'lucide-react'

export type SetupItem = { done: boolean; title: string; detail: string; action: string; onClick: () => void }

function SetupStep({ done, number, title, detail, action, onClick }: SetupItem & { number: number; done: boolean }) {
  return (
    <button className={`setup-step ${done ? 'complete' : ''}`} onClick={onClick}>
      <span className="step-number">{done ? <Check size={15} /> : number}</span>
      <span className="step-copy">
        <strong>{title}</strong>
        <small>{detail}</small>
      </span>
      <span className="step-action">
        {done ? 'Ready' : action}
        <ChevronRight size={15} />
      </span>
    </button>
  )
}

function RouteMap({ routes, destination, direct }: { routes: string[]; destination: string; direct: boolean }) {
  const stack = routes.length
    ? routes.map((name) => ({ name, enabled: true }))
    : [{ name: direct ? 'WireGuard, OpenVPN or L2TP/IPsec node' : 'VPN or proxy node', enabled: false }]
  return (
    <div className="route-map">
      <div className="map-node origin">
        <Gamepad2 size={19} />
        <span>Your game</span>
      </div>
      <div className="map-lines">
        <i />
        <i />
      </div>
      <div className="path-stack">
        {stack.map((item, index) => (
          <div key={item.name}>
            <span className={item.enabled ? 'active' : ''}>{index + 1}</span>
            <p>{item.name}</p>
            <small>{item.enabled ? (direct ? 'Carrying your traffic' : 'VPN path available') : 'Not configured'}</small>
          </div>
        ))}
      </div>
      <div className="map-lines inbound">
        <i />
        <i />
      </div>
      <div className="map-node relay">
        {direct ? <Globe2 size={19} /> : <MapPin size={19} />}
        <span>{destination}</span>
      </div>
    </div>
  )
}

export function SetupDrawer({
  open,
  onToggle,
  steps,
  routes,
  destination,
  direct,
  onManageRoutes,
}: {
  open: boolean
  onToggle: () => void
  steps: SetupItem[]
  routes: string[]
  destination: string
  direct: boolean
  onManageRoutes: () => void
}) {
  const readyCount = steps.filter((step) => step.done).length
  const complete = readyCount === steps.length
  return (
    <section className={`setup-drawer ${open ? 'is-open' : ''} ${complete ? 'is-complete' : ''}`}>
      <button className="drawer-head" onClick={onToggle} aria-expanded={open}>
        <span className="drawer-icon">{complete ? <Check size={15} /> : <ListChecks size={15} />}</span>
        <span className="drawer-copy">
          <strong>{complete ? 'Setup complete' : `Setup — ${readyCount} of ${steps.length} ready`}</strong>
          <small>
            {direct
              ? 'Node, traffic mode and the current path'
              : 'Routes, traffic mode, relay and the current path chain'}
          </small>
        </span>
        <span className="drawer-pips" aria-hidden="true">
          {steps.map((step) => (
            <i key={step.title} className={step.done ? 'done' : ''} />
          ))}
        </span>
        <span className="drawer-toggle">
          {open ? 'Hide' : 'Show'}
          <ChevronDown size={15} />
        </span>
      </button>
      {open && (
        <div className="drawer-body">
          <div className="setup-list">
            {steps.map((step, index) => (
              <SetupStep key={step.title} {...step} number={index + 1} />
            ))}
          </div>
          <div className="route-preview">
            <div className="section-heading">
              <div>
                <span className="eyebrow">Path overview</span>
                <h2>{direct ? 'Current path' : 'Current route chain'}</h2>
              </div>
              <button className="text-button" onClick={onManageRoutes}>
                Manage <ChevronRight size={14} />
              </button>
            </div>
            <RouteMap routes={routes} destination={destination} direct={direct} />
          </div>
        </div>
      )}
    </section>
  )
}
