import { useState } from 'react'
import {
  Activity,
  Code2,
  Copy,
  ExternalLink,
  Link2,
  MessageCircle,
  Network,
  Server,
  ShieldCheck,
  Zap,
} from 'lucide-react'
import { api } from '../api'
import { Toggle } from '../components/Toggle'
import { errorMessage, type Notify } from '../components/Toast'
import type { AppState } from '../types'

function CreatorCard({ notify }: { notify: Notify }) {
  const copyDiscord = async () => {
    try {
      await navigator.clipboard.writeText('prime_lifesoul')
      notify('Discord username copied: prime_lifesoul', 'success')
    } catch {
      notify('Could not copy the username. You can add prime_lifesoul on Discord.', 'error')
    }
  }

  return (
    <section className="creator-card" aria-labelledby="creator-title">
      <div className="creator-heading">
        <span className="creator-mark">
          <Zap size={24} aria-hidden="true" />
        </span>
        <div>
          <span className="eyebrow">Behind GamePath</span>
          <h2 id="creator-title">Built by primemb</h2>
          <p>A better path to your next game.</p>
        </div>
        <span className="creator-badge">Creator</span>
      </div>
      <div className="creator-links">
        <a href="https://github.com/primemb/gamepath" target="_blank" rel="noopener noreferrer">
          <Code2 size={20} aria-hidden="true" />
          <span>
            <strong>GamePath on GitHub</strong>
            <small>primemb / gamepath</small>
          </span>
          <ExternalLink size={16} aria-hidden="true" />
        </a>
        <button type="button" onClick={copyDiscord} aria-label="Copy Discord username prime_lifesoul">
          <MessageCircle size={20} aria-hidden="true" />
          <span>
            <strong>Connect on Discord</strong>
            <small>prime_lifesoul</small>
          </span>
          <Copy size={16} aria-hidden="true" />
        </button>
      </div>
      <p className="creator-legal">&copy; {new Date().getFullYear()} primemb. GamePath.</p>
    </section>
  )
}

export function SettingsView({
  state,
  setState,
  notify,
}: {
  state: AppState
  setState: (next: AppState) => void
  notify: Notify
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
      <CreatorCard notify={notify} />

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
