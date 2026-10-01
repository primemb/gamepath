import {
  AppWindow,
  Cast,
  ChartNoAxesCombined,
  Gamepad2,
  LayoutDashboard,
  Network,
  Route,
  Server,
  ShieldCheck,
} from 'lucide-react'

export type View = 'game' | 'vpn' | 'statistics' | 'settings' | 'info'
export type GameTab = 'overview' | 'routes' | 'split' | 'connection' | 'sharing'
export type VpnTab = 'overview' | 'node' | 'split'

type Icon = typeof Gamepad2

export const navItems: { id: View; label: string; icon: Icon }[] = [
  { id: 'game', label: 'Game', icon: Gamepad2 },
  { id: 'vpn', label: 'VPN', icon: ShieldCheck },
  { id: 'statistics', label: 'Statistics', icon: ChartNoAxesCombined },
]

export type TabDefinition<Id extends string> = { id: Id; label: string; icon: Icon; description: string }

export const gameTabs: TabDefinition<GameTab>[] = [
  {
    id: 'overview',
    label: 'Overview',
    icon: LayoutDashboard,
    description: 'Session control and live route telemetry.',
  },
  {
    id: 'routes',
    label: 'Routes and nodes',
    icon: Route,
    description: 'Add WireGuard, OpenVPN, L2TP/IPsec or SOCKS5 nodes GamePath can use.',
  },
  {
    id: 'split',
    label: 'Split tunnel',
    icon: Network,
    description: 'Choose exactly which traffic should enter the multipath tunnel.',
  },
  { id: 'connection', label: 'Connection', icon: Server, description: 'Choose how your traffic leaves this PC.' },
  {
    id: 'sharing',
    label: 'Console sharing',
    icon: Cast,
    description: 'Let a console or another device use this session through a proxy.',
  },
]

export const vpnTabs: TabDefinition<VpnTab>[] = [
  {
    id: 'overview',
    label: 'Overview',
    icon: LayoutDashboard,
    description: 'A second connection for everyday apps, beside your game and never in its way.',
  },
  { id: 'node', label: 'Node', icon: ShieldCheck, description: 'The one node the VPN connects through.' },
  {
    id: 'split',
    label: 'Split tunnel',
    icon: AppWindow,
    description: 'Choose which apps and websites use the VPN, and how it behaves when the node goes quiet.',
  },
]

/** The heading and the sentence under it, for screens without tabs. */
export const viewTitles: Record<View, [string, string]> = {
  game: ['Game', 'Session control and live route telemetry.'],
  vpn: ['VPN', 'A second connection for everyday apps, beside your game and never in its way.'],
  statistics: ['Statistics', 'Track tunnel usage over time, by node, application and device.'],
  settings: ['Settings', 'Control startup, diagnostics, and client behavior.'],
  info: ['Info', 'About GamePath and its creator.'],
}
