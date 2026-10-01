import { AppWindow, Globe2 } from 'lucide-react'
import { Toggle } from '../Toggle'
import type { VpnState } from '../../types'

/** What enters the VPN, and how it behaves when the node goes quiet. */
export function VpnTrafficCard({
  vpn,
  onTrafficMode,
  onRemoteDns,
  onKillSwitch,
}: {
  vpn: VpnState
  onTrafficMode: (mode: 'all' | 'split') => void
  onRemoteDns: (enabled: boolean) => void
  onKillSwitch: (enabled: boolean) => void
}) {
  return (
    <section className="traffic-mode-card vpn-card">
      <div>
        <span className="eyebrow">Routing scope</span>
        <h2>Choose what uses the VPN</h2>
        <p>Changing these while the VPN is on reconnects it once.</p>
      </div>
      <div className="segmented-control" role="group" aria-label="VPN routing mode">
        <button
          className={vpn.trafficMode === 'split' ? 'active' : ''}
          aria-pressed={vpn.trafficMode === 'split'}
          onClick={() => onTrafficMode('split')}
        >
          <AppWindow size={15} aria-hidden="true" />
          <span>
            Selected apps<small>Everything else stays normal</small>
          </span>
        </button>
        <button
          className={vpn.trafficMode === 'all' ? 'active' : ''}
          aria-pressed={vpn.trafficMode === 'all'}
          onClick={() => onTrafficMode('all')}
        >
          <Globe2 size={15} aria-hidden="true" />
          <span>
            All traffic<small>Except your game</small>
          </span>
        </button>
      </div>
      <div className="remote-dns-row">
        <div>
          <strong>Resolve names through the VPN</strong>
          <p>
            {vpn.remoteDns
              ? 'Website names are looked up through the VPN, so a filtered local resolver cannot send you to a blocked or fake address. A running game session with this on handles lookups first.'
              : 'Lookups use the resolver this PC normally uses. Turn this on if sites fail to open while the VPN is connected.'}
          </p>
        </div>
        <span className="node-group-switch">
          <span>{vpn.remoteDns ? 'On' : 'Off'}</span>
          <Toggle
            checked={vpn.remoteDns}
            onChange={onRemoteDns}
            label={`${vpn.remoteDns ? 'Stop resolving' : 'Resolve'} names through the VPN`}
          />
        </span>
      </div>
      <div className="remote-dns-row">
        <div>
          <strong>Kill switch</strong>
          <p>
            {vpn.killSwitch
              ? 'While the node is not answering, apps you selected are blocked instead of using your normal connection. Name lookups are never blocked.'
              : 'While the node is not answering, apps you selected use your normal connection until it is back.'}
          </p>
        </div>
        <span className="node-group-switch">
          <span>{vpn.killSwitch ? 'On' : 'Off'}</span>
          <Toggle
            checked={vpn.killSwitch}
            onChange={onKillSwitch}
            label={`${vpn.killSwitch ? 'Turn off' : 'Turn on'} the VPN kill switch`}
          />
        </span>
      </div>
    </section>
  )
}
