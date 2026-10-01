import { GameCommandBar } from '../components/game/GameCommandBar'
import { PageTabs, TabPanel, type TabExtras } from '../components/PageTabs'
import type { Notify } from '../components/Toast'
import type { PathHistory, PathRate } from '../lib/format'
import { deriveReadiness } from '../lib/readiness'
import { gameTabs, type GameTab } from '../lib/views'
import type { AppState } from '../types'
import { ConnectionView } from './ConnectionView'
import { GameOverview } from './GameOverview'
import { RoutesView } from './RoutesView'
import { SharingView } from './SharingView'
import { SplitView } from './SplitView'

function sharingDot(state: AppState): TabExtras['dot'] {
  const listener = state.session.status === 'connected' ? state.session.lanProxy?.state : undefined
  if (listener === 'listening') return 'live'
  if (listener === 'error') return 'warning'
  return state.lanProxy.enabled ? 'pending' : null
}

/** Everything the game session uses, one tab per part, under its always-visible switch. */
export function GameView({
  state,
  setState,
  notify,
  histories,
  rates,
  tab,
  onTabChange,
  onToggleSession,
  onOpenVpn,
}: {
  state: AppState
  setState: (next: AppState) => void
  notify: Notify
  histories: PathHistory
  rates: Record<number, PathRate>
  tab: GameTab
  onTabChange: (tab: GameTab) => void
  onToggleSession: () => void
  onOpenVpn: () => void
}) {
  const views = { state, setState, notify }
  const { direct, enabledRules, relayReady } = deriveReadiness(state)

  const extras: Partial<Record<GameTab, TabExtras>> = {
    routes: { badge: state.tunnels.length },
    split: { badge: state.trafficMode === 'split' ? enabledRules : null },
    connection: { dot: !direct && relayReady === false ? 'warning' : null },
    sharing: { dot: sharingDot(state) },
  }

  return (
    <div className="game-page">
      <GameCommandBar
        state={state}
        onToggleSession={onToggleSession}
        onOpenConnection={() => onTabChange('connection')}
      />
      <PageTabs
        scope="game"
        label="Game sections"
        tabs={gameTabs}
        active={tab}
        onChange={onTabChange}
        extras={extras}
      />
      <TabPanel scope="game" id={tab}>
        {tab === 'overview' && (
          <GameOverview
            state={state}
            histories={histories}
            rates={rates}
            onOpenTab={onTabChange}
            onOpenVpn={onOpenVpn}
          />
        )}
        {tab === 'routes' && <RoutesView {...views} />}
        {tab === 'split' && <SplitView {...views} />}
        {tab === 'connection' && <ConnectionView {...views} />}
        {tab === 'sharing' && <SharingView {...views} />}
      </TabPanel>
    </div>
  )
}
