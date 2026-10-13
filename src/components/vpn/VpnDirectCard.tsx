import { useState } from 'react'
import { AlertTriangle, Download, Globe2, LoaderCircle, Network, RefreshCw } from 'lucide-react'
import { api } from '../../api'
import { Toggle } from '../Toggle'
import { formatAge } from '../../lib/format'
import type { AppState, DirectListInfo, VpnState } from '../../types'

/** Runs a change and resolves when it settled, whether it worked or not. */
export type RunChange = (work: () => Promise<AppState>) => Promise<void>

function ListRow({
  list,
  inUse,
  busy,
  onToggle,
  onUpdate,
}: {
  list: DirectListInfo
  inUse: boolean
  busy: boolean
  onToggle: (on: boolean) => void
  onUpdate: () => void
}) {
  const Icon = list.kind === 'ip' ? Network : Globe2
  const downloaded = list.updatedAt !== null
  const working = busy || list.downloading
  return (
    <li className={`vpn-direct-list ${inUse ? 'is-on' : ''}`}>
      <span className="vpn-target-icon" aria-hidden="true">
        <Icon size={16} />
      </span>
      <div className="vpn-direct-list-copy">
        <span className="vpn-direct-list-title">
          <strong>{list.title}</strong>
          <code data-no-translate>{list.tag}</code>
        </span>
        <small>{list.description}</small>
        <span className="vpn-direct-list-meta" aria-live="polite">
          {working ? (
            <span>Downloading…</span>
          ) : downloaded ? (
            <>
              {/* One string each, so the translation can match it whole. */}
              <span>{`${list.count.toLocaleString('en-US')} ${list.kind === 'ip' ? 'ranges' : 'sites'}`}</span>
              <span aria-hidden="true">·</span>
              <span>{`Updated ${formatAge(list.updatedAt!)}`}</span>
            </>
          ) : (
            <span className="is-missing">Not downloaded yet</span>
          )}
        </span>
      </div>
      <button
        className="button subtle"
        onClick={onUpdate}
        disabled={working}
        aria-label={`${downloaded ? 'Update' : 'Download'} the ${list.title} list`}
      >
        {working ? (
          <LoaderCircle size={14} className="vpn-spin" aria-hidden="true" />
        ) : downloaded ? (
          <RefreshCw size={14} aria-hidden="true" />
        ) : (
          <Download size={14} aria-hidden="true" />
        )}
        <span>{downloaded ? 'Update' : 'Download'}</span>
      </button>
      <Toggle
        checked={inUse}
        onChange={onToggle}
        disabled={working}
        label={`${inUse ? 'Stop using' : 'Use'} the ${list.title} list`}
      />
    </li>
  )
}

/** Whether direct sites are on, and which downloaded lists they use. */
export function VpnDirectCard({ vpn, run }: { vpn: VpnState; run: RunChange }) {
  const { direct } = vpn
  const [busy, setBusy] = useState<ReadonlySet<string>>(new Set())

  const track = async (key: string, work: () => Promise<AppState>) => {
    setBusy((current) => new Set(current).add(key))
    await run(work)
    setBusy((current) => {
      const next = new Set(current)
      next.delete(key)
      return next
    })
  }

  const inUse = new Set(direct.lists)
  const anyDownloaded = direct.catalog.some((list) => list.updatedAt !== null)
  const switching = busy.has('switch')

  return (
    <section className={`vpn-card vpn-direct ${direct.enabled ? 'is-on' : ''}`}>
      <div>
        <span className="eyebrow">Direct sites</span>
        <h2>Skip the VPN for local sites</h2>
        <p className="vpn-direct-intro">
          Listed sites use your normal connection. They load at full local speed, and banks, payment pages and
          government services that refuse foreign visitors keep working.
        </p>
      </div>
      <div className="remote-dns-row">
        <div>
          <strong>Use direct sites</strong>
          <p>
            {direct.enabled
              ? vpn.trafficMode === 'all'
                ? 'Every app except your game skips the VPN for these sites. Changes apply at once, without reconnecting.'
                : 'Apps that use the VPN skip it for these sites. Changes apply at once, without reconnecting.'
              : 'Everything the VPN carries goes through the node.'}
          </p>
        </div>
        <span className="node-group-switch">
          {switching ? <LoaderCircle size={14} className="vpn-spin" aria-label="Working" /> : null}
          <span>{direct.enabled ? 'On' : 'Off'}</span>
          <Toggle
            checked={direct.enabled}
            disabled={switching}
            onChange={(on) => void track('switch', () => api.vpn.setDirectEnabled(on))}
            label={`${direct.enabled ? 'Stop using' : 'Use'} direct sites`}
          />
        </span>
      </div>
      {direct.limitation && (
        <p className="vpn-hint">
          <AlertTriangle size={13} aria-hidden="true" /> {direct.limitation}
        </p>
      )}
      <div className="vpn-direct-lists-head">
        <h3>Lists</h3>
        <button
          className="button subtle"
          disabled={!anyDownloaded || busy.size > 0}
          onClick={() => void track('all', () => api.vpn.updateDirectLists())}
        >
          <RefreshCw size={14} aria-hidden="true" /> Update all
        </button>
      </div>
      <ul className={`vpn-direct-lists ${direct.enabled ? '' : 'is-inactive'}`}>
        {direct.catalog.map((list) => (
          <ListRow
            key={list.id}
            list={list}
            inUse={inUse.has(list.id)}
            busy={busy.has(list.id) || busy.has('all') || (switching && !list.updatedAt)}
            onToggle={(on) => void track(list.id, () => api.vpn.setDirectList(list.id, on))}
            onUpdate={() => void track(list.id, () => api.vpn.updateDirectLists([list.id]))}
          />
        ))}
      </ul>
      <p className="vpn-direct-note">
        The same lists Throne uses to bypass Iran, from Chocolate4U&apos;s Iran rules. They are downloaded to this PC
        and refresh once a week. Name lookups still go through the VPN; a listed site turns direct as soon as it is
        looked up. Your game session is never affected.
      </p>
    </section>
  )
}
