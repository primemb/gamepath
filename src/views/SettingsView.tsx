import { useState } from 'react'
import { Activity, ArrowLeftRight, Link2, MessageCircle, Network, Server, ShieldCheck, Zap } from 'lucide-react'
import { api } from '../api'
import { Toggle } from '../components/Toggle'
import { errorMessage, type Notify } from '../components/Toast'
import type { Language } from '../lib/language'
import type { AppState } from '../types'

export function SettingsView({
  state,
  setState,
  notify,
  language,
  onLanguageChange,
}: {
  state: AppState
  setState: (next: AppState) => void
  notify: Notify
  language: Language
  onLanguageChange: (language: Language) => void
}) {
  const [installing, setInstalling] = useState(false)
  const direct = state.connectionMode === 'direct'
  const routingStrategy = state.routingStrategy ?? 'smart'
  const engine = state.engine
  const service = state.service

  const guard = async (work: () => Promise<void>) => {
    try {
      await work()
    } catch (error) {
      notify(errorMessage(error), 'error')
    }
  }

  const failover = state.relayFailover ?? { enabled: false, standbyRelayId: null }
  const standbyCandidates = state.relays.filter((relay) => relay.status === 'ready' && relay.id !== state.activeRelayId)
  const failoverDetail = direct
    ? 'Available in relay mode.'
    : !standbyCandidates.length
      ? 'Set up a second relay to use as a standby.'
      : 'If your relay stops answering through every node for 30 seconds while your internet works, this session moves to the standby relay. It never moves back by itself. Applies from the next session.'
  const configureFailover = (next: typeof failover) =>
    guard(async () => setState(await api.configureRelayFailover(next)))

  const installService = () =>
    guard(async () => {
      setInstalling(true)
      try {
        setState(await api.installService())
        notify('GamePath Network Service installed and running.', 'success')
      } finally {
        setInstalling(false)
      }
    })

  return (
    <section className="page-section settings-list">
      <div className="settings-card">
        <div>
          <span className="setting-icon">
            <MessageCircle size={18} />
          </span>
          <div>
            <strong>Language</strong>
            <p>Choose the interface language.</p>
          </div>
        </div>
        <div className="segmented-control" role="radiogroup" aria-label="Language">
          <button
            type="button"
            role="radio"
            aria-checked={language === 'en'}
            className={language === 'en' ? 'active' : ''}
            onClick={() => onLanguageChange('en')}
          >
            English
          </button>
          <button
            type="button"
            role="radio"
            aria-checked={language === 'fa'}
            className={language === 'fa' ? 'active' : ''}
            onClick={() => onLanguageChange('fa')}
          >
            فارسی
          </button>
        </div>
      </div>

      <div className="settings-card">
        <div>
          <span className="setting-icon">
            <Zap size={18} />
          </span>
          <div>
            <strong>Relay routing mode</strong>
            <p>
              {direct
                ? 'Available in relay mode. Direct mode always uses its one selected node.'
                : 'Smart uses the best two healthy routes. Manual duplicates through every healthy enabled route. Changes apply when you next start a session.'}
            </p>
          </div>
        </div>
        <div className="segmented-control" role="radiogroup" aria-label="Relay routing mode">
          {(
            [
              ['smart', 'Smart', 'Best two routes'],
              ['manual', 'Manual', 'Every healthy route'],
            ] as const
          ).map(([id, label, detail]) => (
            <button
              key={id}
              className={routingStrategy === id ? 'active' : ''}
              disabled={direct}
              onClick={() => guard(async () => setState(await api.setRoutingStrategy(id)))}
              role="radio"
              aria-checked={routingStrategy === id}
            >
              <span>
                {label}
                <small>{detail}</small>
              </span>
            </button>
          ))}
        </div>
      </div>

      <div className="settings-card">
        <div>
          <span className="setting-icon">
            <ArrowLeftRight size={18} />
          </span>
          <div>
            <strong>Automatic relay failover</strong>
            <p>{failoverDetail}</p>
          </div>
        </div>
        <div className="failover-controls">
          <label className="failover-standby">
            <span className="sr-only">Standby relay</span>
            <select
              value={failover.standbyRelayId ?? ''}
              disabled={direct || !failover.enabled || !standbyCandidates.length}
              onChange={(event) => configureFailover({ ...failover, standbyRelayId: event.target.value || null })}
            >
              <option value="">First other ready relay</option>
              {standbyCandidates.map((relay) => (
                <option key={relay.id} value={relay.id}>
                  {relay.city}
                </option>
              ))}
            </select>
          </label>
          <Toggle
            checked={failover.enabled}
            disabled={direct || (!failover.enabled && !standbyCandidates.length)}
            onChange={(enabled) => configureFailover({ ...failover, enabled })}
            label="Automatic relay failover"
          />
        </div>
      </div>

      <div className="settings-card">
        <div>
          <span className="setting-icon">
            <Link2 size={18} />
          </span>
          <div>
            <strong>Start with Windows</strong>
            <p>Open GamePath in the background after signing in.</p>
          </div>
        </div>
        <Toggle checked={false} onChange={() => undefined} label="Start with Windows" />
      </div>

      <div className="settings-card">
        <div>
          <span className="setting-icon">
            <Activity size={18} />
          </span>
          <div>
            <strong>Local diagnostics</strong>
            <p>Keep route latency and packet-loss history for troubleshooting.</p>
          </div>
        </div>
        <Toggle checked={true} onChange={() => undefined} label="Local diagnostics" />
      </div>

      <div className="settings-card capability-card">
        <div>
          <span className="setting-icon">
            <ShieldCheck size={18} />
          </span>
          <div>
            <strong>Windows network capabilities</strong>
            <p>
              WireGuard {engine.capabilities?.wireGuardInstalled ? 'detected' : 'not found'} · Wintun library{' '}
              {engine.capabilities?.packetAdapter?.libraryLoaded ? 'ready' : 'missing'} · Driver{' '}
              {engine.capabilities?.packetAdapterInstalled ? 'active' : 'not created'}
            </p>
          </div>
        </div>
        <span className={`status-pill ${engine.status === 'ready' ? 'online' : ''}`}>
          <i />
          {engine.status}
        </span>
      </div>

      <div className="settings-card capability-card">
        <div>
          <span className="setting-icon">
            <Network size={18} />
          </span>
          <div>
            <strong>Split-tunnel interception</strong>
            <p>
              WFP backend{' '}
              {engine.capabilities?.interception?.libraryLoaded && engine.capabilities?.interception?.driverAvailable
                ? 'ready'
                : 'missing'}{' '}
              · Winsock transport · Administrator service required to activate
            </p>
          </div>
        </div>
        <span className={`status-pill ${engine.capabilities?.interception?.libraryLoaded ? 'online' : ''}`}>
          <i />
          WFP
        </span>
      </div>

      <div className="settings-card capability-card">
        <div>
          <span className="setting-icon">
            <Server size={18} />
          </span>
          <div>
            <strong>GamePath Network Service</strong>
            <p>
              {service.message}
              {service.version ? ` · Version ${service.version}` : ''}
            </p>
          </div>
        </div>
        <div className="service-actions">
          <button
            className={service.status === 'ready' ? 'button secondary' : 'button primary'}
            disabled={installing}
            onClick={installService}
          >
            {installing ? 'Installing…' : service.status === 'ready' ? 'Reinstall service' : 'Install service'}
          </button>
          <button
            className="button secondary"
            disabled={installing}
            onClick={() => guard(async () => setState(await api.refreshService()))}
          >
            Refresh status
          </button>
          <span className={`status-pill ${service.status === 'ready' ? 'online' : ''}`}>
            <i />
            {service.status}
          </span>
        </div>
      </div>
    </section>
  )
}
