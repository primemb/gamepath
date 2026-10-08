import { useState } from 'react'
import { Check, Download, Info, MapPin, Plus, Share2, ShieldCheck, Trash2 } from 'lucide-react'
import { api } from '../api'
import { AddressWithCountry, CountryFlag, IpCountryFlag } from '../IpLocation'
import { ConnectionModes } from '../components/ConnectionModes'
import { errorMessage, type Notify } from '../components/Toast'
import { AddRelayModal, RelayModal } from '../modals/RelayModal'
import { VpsModal } from '../modals/VpsModal'
import { RelayShareModal } from '../modals/RelayShareModal'
import { RelayImportModal } from '../modals/RelayImportModal'
import { RelayAccessModal } from '../modals/RelayAccessModal'
import type { AppState, ConnectionMode, Relay } from '../types'

function RelayCard({
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
  onTest: () => void
  onConfigureVps: () => void
  onManual: () => void
  onRemoveVps: () => void
  onShare: () => void
  onAccess: () => void
  onDelete: () => void
}) {
  const ready = relay.status === 'ready'
  return (
    <article className={`relay-card ${selected ? 'selected' : ''}`}>
      <button className="relay-choice" onClick={onSelect}>
        <span className="relay-radio">{selected && <Check size={14} />}</span>
        <div className="relay-location">
          <span>
            <MapPin size={19} />
          </span>
          <div>
            <strong data-no-translate>{relay.city}</strong>
            <small>
              {relay.address ? (
                <AddressWithCountry value={relay.address} suffix={`:${relay.port}`} />
              ) : (
                `${relay.country} · VPS not configured`
              )}
            </small>
          </div>
        </div>
        <div className="relay-stat">
          <small>Latency</small>
          <strong>
            {relay.latency ?? '—'}
            <em> ms</em>
          </strong>
        </div>
        <div className={`relay-status ${relay.status}`}>
          <i />
          {selected ? 'Enabled' : ready ? 'Disabled' : 'Setup required'}
        </div>
      </button>
      <div className="relay-actions">
        {ready && (
          <button className="button secondary" onClick={onTest}>
            Test
          </button>
        )}
        <button className="button primary" onClick={onConfigureVps}>
          {ready ? 'Update VPS' : 'Auto-configure VPS'}
        </button>
        <button className="button secondary relay-configure" onClick={onManual}>
          Manual
        </button>
        {ready && (
          <button className="button secondary" onClick={onShare}>
            <Share2 size={14} aria-hidden="true" /> Share with a friend
          </button>
        )}
        {ready && (
          <button className="button secondary" onClick={onAccess}>
            <ShieldCheck size={14} aria-hidden="true" /> Manage access
          </button>
        )}
        {ready && (
          <button className="button secondary" onClick={onRemoveVps}>
            Remove VPS
          </button>
        )}
        <button className="icon-button danger" aria-label={`Delete ${relay.city}`} onClick={onDelete}>
          <Trash2 size={16} />
        </button>
      </div>
    </article>
  )
}

export function ConnectionView({
  state,
  setState,
  notify,
}: {
  state: AppState
  setState: (next: AppState) => void
  notify: Notify
}) {
  const [showRelayModal, setShowRelayModal] = useState(false)
  const [showAddRelay, setShowAddRelay] = useState(false)
  const [shareTarget, setShareTarget] = useState<Relay | null>(null)
  const [accessTarget, setAccessTarget] = useState<Relay | null>(null)
  const [showImportRelay, setShowImportRelay] = useState(false)
  const [vpsTarget, setVpsTarget] = useState<{ id: string; action: 'provision' | 'remove' } | null>(null)

  const guard = async (work: () => Promise<void>) => {
    try {
      await work()
    } catch (error) {
      notify(errorMessage(error), 'error')
    }
  }

  const relay = state.relays.find((item) => item.id === state.activeRelayId)
  const direct = state.connectionMode === 'direct'
  // Every tunnelling kind routes packets itself, so each can be the single hop
  // of a direct session; a proxy cannot.
  const routingNodes = state.tunnels.filter((item) => item.kind !== 'socks5').length
  // Point at the mode the user's current setup can actually start in.
  const recommendedMode: ConnectionMode | null =
    relay?.status === 'ready' ? 'relay' : routingNodes > 0 ? 'direct' : null
  const vpsRelay = vpsTarget && state.relays.find((item) => item.id === vpsTarget.id)

  return (
    <section className="page-section">
      <ConnectionModes
        mode={state.connectionMode}
        recommended={recommendedMode}
        onSelect={(next) =>
          guard(async () => {
            if (next === state.connectionMode) return
            setState(await api.setConnectionMode(next))
          })
        }
        onSetUpRelay={() => guard(async () => setState(await api.setConnectionMode('relay')))}
      />
      <div className={`relay-section ${direct ? 'is-inactive' : ''}`}>
        {direct && (
          <p className="relay-section-note">
            <Info size={14} /> Relays are kept here for when you switch back. Direct mode does not use them.
          </p>
        )}
        <div className="relay-intro">
          <div>
            <span className="eyebrow">Relay fleet</span>
            <h2>
              {state.relays.length} server{state.relays.length === 1 ? '' : 's'}
            </h2>
            <p>Add your VPS locations and enable one relay at a time.</p>
            <div className="relay-intro-buttons">
              <button className="button primary" onClick={() => setShowAddRelay(true)}>
                <Plus size={16} />
                Add VPS relay
              </button>
              <button className="button secondary" onClick={() => setShowImportRelay(true)}>
                <Download size={16} aria-hidden="true" /> Import shared relay
              </button>
            </div>
          </div>
          <div className="flag-orb">
            {relay ? (
              relay.address ? (
                <IpCountryFlag target={relay.address} />
              ) : (
                <CountryFlag countryCode={relay.code} country={relay.country} />
              )
            ) : (
              'GP'
            )}
          </div>
        </div>
        <div className="relay-grid">
          {state.relays.map((item) => (
            <RelayCard
              key={item.id}
              relay={item}
              selected={state.activeRelayId === item.id}
              onSelect={() => guard(async () => setState(await api.setRelay(item.id)))}
              onTest={() =>
                guard(async () => {
                  const tested = await api.testRelay(item.id)
                  setState(tested.state)
                  notify(
                    `Authenticated relay ready · ${Math.round(tested.result.latencyMs)} ms · ${tested.result.virtualIpv4}`,
                    'success',
                  )
                })
              }
              onConfigureVps={() => setVpsTarget({ id: item.id, action: 'provision' })}
              onShare={() => setShareTarget(item)}
              onAccess={() => setAccessTarget(item)}
              onManual={() => {
                setState({ ...state, activeRelayId: item.id })
                setShowRelayModal(true)
              }}
              onRemoveVps={() => setVpsTarget({ id: item.id, action: 'remove' })}
              onDelete={() => guard(async () => setState(await api.removeRelayLocal(item.id)))}
            />
          ))}
        </div>
        <div className="coming-regions">
          <span>More regions are planned</span>
          <div>
            <i>DE</i>
            <i>NL</i>
            <i>AE</i>
          </div>
        </div>
      </div>

      {showRelayModal && relay && (
        <RelayModal
          relay={relay}
          onClose={() => setShowRelayModal(false)}
          onImport={() =>
            guard(async () => {
              const result = await api.importRelayEnrollment(relay.id)
              if (result.state) setState(result.state)
            })
          }
          onSave={(input) =>
            guard(async () => {
              setState(await api.configureRelay(relay.id, input))
              setShowRelayModal(false)
            })
          }
        />
      )}
      {shareTarget && <RelayShareModal relay={shareTarget} onClose={() => setShareTarget(null)} setState={setState} />}
      {accessTarget && (
        <RelayAccessModal relay={accessTarget} onClose={() => setAccessTarget(null)} setState={setState} />
      )}
      {showImportRelay && (
        <RelayImportModal
          onClose={() => setShowImportRelay(false)}
          onImported={(next) => {
            setState(next)
            setShowImportRelay(false)
            notify('Shared relay added. Choose it and connect in Relay mode with your own nodes.', 'success')
          }}
        />
      )}
      {showAddRelay && (
        <AddRelayModal
          onClose={() => setShowAddRelay(false)}
          onAdd={(input) =>
            guard(async () => {
              const result = await api.addRelay(input)
              setState(result.state)
              setShowAddRelay(false)
              setVpsTarget({ id: result.relayId, action: 'provision' })
            })
          }
        />
      )}
      {vpsTarget && vpsRelay && (
        <VpsModal
          relay={vpsRelay}
          action={vpsTarget.action}
          onClose={() => setVpsTarget(null)}
          onSubmit={({ existing, ...input }) =>
            guard(async () => {
              setState(
                vpsTarget.action === 'remove'
                  ? await api.removeRelayVps(vpsRelay.id, input)
                  : existing
                    ? await api.enrollRelayVps(vpsRelay.id, input)
                    : await api.provisionRelayVps(vpsRelay.id, input),
              )
              notify(
                vpsTarget.action === 'remove'
                  ? 'GamePath was removed from the VPS.'
                  : existing
                    ? 'This PC is enrolled on the VPS relay and the credential is protected by Windows.'
                    : 'VPS configured and enrollment protected by Windows.',
                'success',
              )
              setVpsTarget(null)
            })
          }
        />
      )}
    </section>
  )
}
