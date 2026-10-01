import type { AppState, VpnSessionStatus } from '../types'

export type NavStatus = {
  tone: 'game' | 'vpn'
  /** On and carrying traffic, or on its way there. */
  state: 'live' | 'pending'
  label: string
}

export function gameNavStatus(status: AppState['session']['status']): NavStatus | null {
  if (status === 'connected') return { tone: 'game', state: 'live', label: 'Game session on' }
  if (status === 'starting' || status === 'prepared') {
    return { tone: 'game', state: 'pending', label: 'Game session starting' }
  }
  return null
}

export function vpnNavStatus(status: VpnSessionStatus): NavStatus | null {
  switch (status) {
    case 'connected':
    case 'degraded':
      return { tone: 'vpn', state: 'live', label: 'VPN on' }
    case 'connecting':
    case 'reconnecting':
      return { tone: 'vpn', state: 'pending', label: 'VPN connecting' }
    case 'paused':
      return { tone: 'vpn', state: 'pending', label: 'VPN paused for your game' }
    default:
      return null
  }
}
