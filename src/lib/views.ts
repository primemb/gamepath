import { ChartNoAxesCombined, LayoutDashboard, Network, Route, Server } from 'lucide-react'

export type View = 'dashboard' | 'routes' | 'split' | 'relays' | 'statistics' | 'settings'

export const navItems: { id: View; label: string; icon: typeof LayoutDashboard }[] = [
  { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
  { id: 'routes', label: 'Routes and nodes', icon: Route },
  { id: 'split', label: 'Split tunnel', icon: Network },
  { id: 'relays', label: 'Connection', icon: Server },
  { id: 'statistics', label: 'Statistics', icon: ChartNoAxesCombined },
]

/** The heading and the sentence under it, per screen. */
export const viewTitles: Record<View, [string, string]> = {
  dashboard: ['Overview', 'Session control and live route telemetry.'],
  routes: ['Routes and nodes', 'Add WireGuard, OpenVPN, L2TP/IPsec or SOCKS5 nodes GamePath can use.'],
  split: ['Split tunnel', 'Choose exactly which traffic should enter the multipath tunnel.'],
  relays: ['Connection', 'Choose how your traffic leaves this PC.'],
  statistics: ['Statistics', 'Track tunnel usage over time, by node and application.'],
  settings: ['Settings', 'Control startup, diagnostics, and client behavior.'],
}
