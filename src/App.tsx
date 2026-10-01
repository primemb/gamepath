import { useEffect, useLayoutEffect, useState } from 'react'
import { Info, Settings, ShieldCheck, Zap } from 'lucide-react'
import { api } from './api'
import { Toast, type Notice, type NoticeKind } from './components/Toast'
import { useSessionTelemetry } from './lib/useSessionTelemetry'
import { savedLanguage, saveLanguage, type Language } from './lib/language'
import { observeLanguage } from './lib/localizeDom'
import { gameTabs, navItems, viewTitles, vpnTabs, type GameTab, type View, type VpnTab } from './lib/views'
import { GameView } from './views/GameView'
import { InfoView } from './views/InfoView'
import { SettingsView } from './views/SettingsView'
import { StatisticsView } from './views/StatisticsView'
import { VpnView } from './views/VpnView'
import { gameNavStatus, vpnNavStatus, type NavStatus as NavStatusValue } from './lib/navStatus'
import { NavStatus } from './components/NavStatus'
import type { AppState } from './types'

function Sidebar({
  view,
  onNavigate,
  statuses,
  clientVersion,
}: {
  view: View
  onNavigate: (next: View) => void
  statuses: Partial<Record<View, NavStatusValue | null>>
  clientVersion: string | undefined
}) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="brand-mark">
          <Zap size={19} fill="currentColor" />
        </span>
        <span>
          GAME<strong>PATH</strong>
        </span>
        <em>ALPHA</em>
      </div>
      <nav>
        <span className="nav-caption">Workspace</span>
        {navItems.map((item) => {
          const Icon = item.icon
          return (
            <button key={item.id} className={view === item.id ? 'active' : ''} onClick={() => onNavigate(item.id)}>
              <Icon size={18} />
              <span>{item.label}</span>
              <NavStatus status={statuses[item.id] ?? null} />
            </button>
          )
        })}
      </nav>
      <div className="sidebar-bottom">
        <button className={view === 'settings' ? 'active' : ''} onClick={() => onNavigate('settings')}>
          <Settings size={18} />
          Settings
        </button>
        <button className={view === 'info' ? 'active' : ''} onClick={() => onNavigate('info')}>
          <Info size={18} />
          Info
        </button>
        <div className="client-card">
          <span>
            <ShieldCheck size={16} />
          </span>
          <div>
            <strong>Local protection</strong>
            <small>Keys secured by Windows</small>
          </div>
        </div>
        <div className="version">
          Client {clientVersion ?? 'development'} <i /> Alpha build
        </div>
      </div>
    </aside>
  )
}

function App() {
  const [language, setLanguage] = useState<Language>(savedLanguage)
  const [state, setState] = useState<AppState | null>(null)
  const [view, setView] = useState<View>('game')
  // Kept here, not in the pages, so a tab survives a trip to another screen.
  const [gameTab, setGameTab] = useState<GameTab>('overview')
  const [vpnTab, setVpnTab] = useState<VpnTab>('node')
  const [notice, setNotice] = useState<Notice | null>(null)
  const notify = (message: string, kind: NoticeKind = 'info') => setNotice({ message, kind })
  const { histories, rates } = useSessionTelemetry(state)

  useLayoutEffect(() => observeLanguage(document.getElementById('root')!, language), [language, state === null])

  const changeLanguage = (next: Language) => {
    saveLanguage(next)
    setLanguage(next)
  }

  useEffect(() => {
    api.bootstrap().then(setState)
  }, [])

  // The main process pushes VPN changes; the window keeps no timer for them.
  useEffect(() => api.vpn.onChanged((vpn) => setState((current) => current && { ...current, vpn })), [])

  useEffect(() => {
    if (state?.session.status !== 'connected') return
    const timer = window.setInterval(() => api.refreshSession().then(setState), 2000)
    return () => window.clearInterval(timer)
  }, [state?.session.status])

  if (!state)
    return (
      <div className="loading">
        <div className="brand-mark">
          <Zap size={22} />
        </div>
        <span>Loading GamePath…</span>
      </div>
    )

  const toggleSession = async () => {
    if (state.session.status !== 'connected') setState({ ...state, session: { status: 'starting' } })
    const next = state.session.status === 'connected' ? await api.stopSession() : await api.startSession()
    setState(next)
    if (next.session.message)
      notify(
        next.session.message,
        next.session.status === 'error' ? 'error' : next.session.status === 'connected' ? 'success' : 'info',
      )
  }

  const engineStatus = state.engine.status
  const [heading, viewDescription] = viewTitles[view]
  const description =
    view === 'game'
      ? gameTabs.find((tab) => tab.id === gameTab)!.description
      : view === 'vpn'
        ? vpnTabs.find((tab) => tab.id === vpnTab)!.description
        : viewDescription
  const openGameTab = (tab: GameTab) => {
    setGameTab(tab)
    setView('game')
  }
  const views = { state, setState, notify }

  return (
    <div className="app-shell">
      <Sidebar
        view={view}
        onNavigate={setView}
        statuses={{
          game: gameNavStatus(state.session.status),
          vpn: vpnNavStatus(state.vpn.session.status),
        }}
        clientVersion={state.clientVersion}
      />

      <main>
        <header className="topbar">
          <div>
            <span className="eyebrow">GamePath client</span>
            <h1>{heading}</h1>
            <p>{description}</p>
          </div>
          <div className={`topbar-status ${engineStatus}`}>
            <span className="pulse-dot" />{' '}
            {engineStatus === 'ready' ? `Engine ${state.engine.version} ready` : state.engine.message}
          </div>
        </header>

        <div className="content">
          {view === 'game' && (
            <GameView
              {...views}
              histories={histories}
              rates={rates}
              tab={gameTab}
              onTabChange={setGameTab}
              onToggleSession={toggleSession}
              onOpenVpn={() => setView('vpn')}
            />
          )}
          {view === 'vpn' && (
            <VpnView {...views} tab={vpnTab} onTabChange={setVpnTab} onOpenGameTraffic={() => openGameTab('split')} />
          )}
          {view === 'statistics' && <StatisticsView notify={notify} />}
          {view === 'settings' && <SettingsView {...views} language={language} onLanguageChange={changeLanguage} />}
          {view === 'info' && <InfoView notify={notify} />}
        </div>
      </main>

      {notice && <Toast notice={notice} onDismiss={() => setNotice(null)} />}
    </div>
  )
}

export default App
