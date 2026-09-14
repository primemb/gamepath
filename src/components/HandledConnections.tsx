import { useMemo, useState } from 'react'
import { AppWindow, ChevronDown, ChevronRight } from 'lucide-react'
import { AddressWithCountry } from '../IpLocation'
import { formatClockTime, histogramPercentile } from '../lib/format'
import type { AppState, HandledConnection } from '../types'

type CaptureDiagnostics = NonNullable<NonNullable<AppState['session']['capture']>['diagnostics']>

/**
 * Every connection GamePath is currently carrying, gathered under the
 * executable that opened it.
 *
 * A game opens dozens of sockets, so the flat list this replaces was unusable
 * the moment a session got going; the application is what the user recognises,
 * and its destinations stay one click away.
 */
export function HandledConnections({ capture }: { capture: CaptureDiagnostics | undefined }) {
  const [open, setOpen] = useState(true)
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set())
  const connections = capture?.handledConnections ?? []
  const groups = useMemo(() => {
    const byApplication = new Map<string, { application: string; connections: HandledConnection[] }>()
    for (const connection of connections) {
      const application = connection.application.trim() || 'Unknown application'
      const key = application.toLowerCase()
      const group = byApplication.get(key)
      if (group) group.connections.push(connection)
      else byApplication.set(key, { application, connections: [connection] })
    }
    return Array.from(byApplication, ([key, group]) => ({ key, ...group }))
  }, [connections])
  const captureP99 = histogramPercentile(capture?.captureLoopHistogram, 0.99)

  const toggleApplication = (key: string) =>
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })

  return (
    <div className={`connections-card ${open ? 'is-open' : ''}`}>
      <button
        className="connections-head"
        onClick={() => setOpen((current) => !current)}
        aria-expanded={open}
        aria-controls="handled-connections-content"
      >
        <div>
          <span className="eyebrow">Handled connections</span>
          <h3>Traffic currently routed</h3>
        </div>
        <small>
          {connections.length} active connection{connections.length === 1 ? '' : 's'} · {groups.length} application
          {groups.length === 1 ? '' : 's'}
        </small>
        <ChevronDown size={15} aria-hidden="true" />
      </button>
      {open && (
        <div id="handled-connections-content">
          {connections.length ? (
            <div className="connections-table">
              <div className="connection-header">
                <span>Application</span>
                <span>Connections</span>
                <span>Protocols</span>
                <span>Latest</span>
              </div>
              {groups.map((group, groupIndex) => {
                const isExpanded = expanded.has(group.key)
                const protocols = Array.from(new Set(group.connections.map((connection) => connection.protocol)))
                const latestStartedAt = Math.max(...group.connections.map((connection) => connection.startedAt))
                const detailsId = `application-connections-${groupIndex}`
                return (
                  <div className="connection-app" key={group.key}>
                    <button
                      className={`connection-app-row ${isExpanded ? 'is-open' : ''}`}
                      onClick={() => toggleApplication(group.key)}
                      aria-expanded={isExpanded}
                      aria-controls={detailsId}
                    >
                      <span className="connection-app-name">
                        <ChevronRight className="connection-app-chevron" size={14} aria-hidden="true" />
                        <AppWindow size={14} aria-hidden="true" />
                        <strong>{group.application}</strong>
                      </span>
                      <span className="connection-count">
                        <strong>{group.connections.length}</strong>
                        <small>active</small>
                      </span>
                      <span className="connection-protocols">{protocols.join(' / ')}</span>
                      <time>{formatClockTime(latestStartedAt)}</time>
                    </button>
                    {isExpanded && (
                      <div
                        className="connection-details"
                        id={detailsId}
                        role="region"
                        aria-label={`${group.application} connection details`}
                      >
                        <div className="connection-detail-header" aria-hidden="true">
                          <span>Destination</span>
                          <span>Protocol</span>
                          <span>Connected</span>
                        </div>
                        {group.connections.map((connection, connectionIndex) => (
                          <div
                            className="connection-detail-row"
                            key={`${connection.destinationIp}-${connection.destinationPort}-${connection.startedAt}-${connectionIndex}`}
                          >
                            <code>
                              <AddressWithCountry
                                value={connection.destinationIp}
                                suffix={connection.destinationPort ? `:${connection.destinationPort}` : ''}
                              />
                            </code>
                            <em>{connection.protocol}</em>
                            <time>{formatClockTime(connection.startedAt)}</time>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          ) : (
            <p className="connections-empty">
              Start the game to see each executable and destination IP handled by GamePath.
            </p>
          )}
          {capture && (
            <div className="capture-health">
              <span>
                Capture p99 <strong>{captureP99 == null ? '—' : `≤ ${captureP99} µs`}</strong>
              </span>
              <span>
                Pending SYN <strong>{capture.pendingSynDepth ?? 0}</strong>
              </span>
              <span>
                Queue peak <strong>{capture.pendingSynPeak ?? 0}</strong>
              </span>
              <span>
                Overflow <strong>{capture.pendingSynOverflow ?? 0}</strong>
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
