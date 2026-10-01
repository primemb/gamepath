import { Cast, ChartNoAxesCombined, Gamepad2, Network, Route, Server, ShieldCheck } from 'lucide-react'

export type View = 'dashboard' | 'vpn' | 'routes' | 'split' | 'relays' | 'sharing' | 'statistics' | 'settings' | 'info'

export const navItems: { id: View; label: string; icon: typeof Gamepad2 }[] = [
  { id: 'dashboard', label: 'Game', icon: Gamepad2 },
  { id: 'vpn', label: 'VPN', icon: ShieldCheck },
  { id: 'routes', label: 'Routes and nodes', icon: Route },
  { id: 'split', label: 'Split tunnel', icon: Network },
  { id: 'relays', label: 'Connection', icon: Server },
  { id: 'sharing', label: 'Console sharing', icon: Cast },
  { id: 'statistics', label: 'Statistics', icon: ChartNoAxesCombined },
]

/** The heading and the sentence under it, per screen. */
export const viewTitles: Record<View, [string, string]> = {
  dashboard: ['Game', 'Session control and live route telemetry.'],
  vpn: ['VPN', 'A second connection for everyday apps, beside your game and never in its way.'],
  routes: ['Routes and nodes', 'Add WireGuard, OpenVPN, L2TP/IPsec or SOCKS5 nodes GamePath can use.'],
  split: ['Split tunnel', 'Choose exactly which traffic should enter the multipath tunnel.'],
  relays: ['Connection', 'Choose how your traffic leaves this PC.'],
  sharing: ['Console sharing', 'Let a console or another device use this session through a proxy.'],
  statistics: ['Statistics', 'Track tunnel usage over time, by node, application and device.'],
  settings: ['Settings', 'Control startup, diagnostics, and client behavior.'],
  info: ['Info', 'About GamePath and its creator.'],
}
