import { useState } from 'react'
import { LanProxyCard } from '../components/LanProxyCard'
import { VpnStatusCard } from '../components/VpnStatusCard'
import { SetupDrawer, type SetupItem } from '../components/SetupDrawer'
import { TelemetryPanel } from '../components/TelemetryPanel'
import type { PathHistory, PathRate } from '../lib/format'
import { deriveReadiness } from '../lib/readiness'
import type { AppState } from '../types'
import type { GameTab } from '../lib/views'

export function GameOverview({
  state,
  histories,
  rates,
  onOpenTab,
  onOpenVpn,
}: {
  state: AppState
  histories: PathHistory
  rates: Record<number, PathRate>
  onOpenTab: (tab: GameTab) => void
  onOpenVpn: () => void
}) {
  // Null until the user has an opinion, so the drawer opens itself while the
  // setup is unfinished and closes once it is — without fighting the user.
  const [setupOpen, setSetupOpen] = useState<boolean | null>(null)

  const { carrying, directNode, enabledRules, readyCount, stepCount, direct, routesReady, rulesReady, relayReady } =
    deriveReadiness(state)
  const relay = state.relays.find((item) => item.id === state.activeRelayId)
  const routingNodes = state.tunnels.filter((item) => item.kind !== 'socks5').length
  const connected = state.session.status === 'connected'
  const sessionRelay = (connected && state.relays.find((item) => item.id === state.session.relayId)) || relay
  const complete = readyCount === stepCount

  const setupSteps: SetupItem[] = [
    {
      done: routesReady,
      title: direct ? 'Choose a tunnelling node' : 'Add a VPN route',
      detail: direct
        ? directNode
          ? `${directNode.name} will carry your traffic`
          : `${routingNodes} routing node${routingNodes === 1 ? '' : 's'} added; pick exactly one`
        : `${state.tunnels.length} node${state.tunnels.length === 1 ? '' : 's'} added; the relay is reached only through carrying nodes`,
      action: 'Configure',
      onClick: () => onOpenTab('routes'),
    },
    {
      done: rulesReady,
      title: 'Choose traffic mode',
      detail:
        state.trafficMode === 'all'
          ? 'All IPv4 system traffic'
          : `${enabledRules} active split-tunnel target${enabledRules === 1 ? '' : 's'}`,
      action: 'Configure',
      onClick: () => onOpenTab('split'),
    },
    // Direct mode has no relay to set up, so the step is not shown greyed out
    // and unreachable — it simply is not part of this setup.
    ...(direct
      ? []
      : [
          {
            done: relayReady === true,
            title: 'Configure a relay',
            detail: relay ? `${relay.city}, ${relay.country}` : 'No relay selected',
            action: 'Set up',
            onClick: () => onOpenTab('connection'),
          },
        ]),
  ]

  return (
    <div className="dashboard-grid">
      <SetupDrawer
        open={setupOpen ?? !complete}
        onToggle={() => setSetupOpen(!(setupOpen ?? !complete))}
        steps={setupSteps}
        routes={carrying.map((tunnel) => tunnel.name)}
        destination={direct ? 'Game server' : (sessionRelay?.city ?? 'Relay')}
        direct={direct}
        onManageRoutes={() => onOpenTab('routes')}
      />

      {state.lanProxy.enabled && <LanProxyCard state={state} onOpen={() => onOpenTab('sharing')} />}
      {state.vpn.node && <VpnStatusCard state={state} onOpen={onOpenVpn} />}

      <TelemetryPanel state={state} histories={histories} rates={rates} />
    </div>
  )
}
