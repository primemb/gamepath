import { useEffect, useRef, useState } from 'react'
import type { NodeKind, VpnSession, VpnSessionStatus } from '../types'

/** Statuses in which the VPN holds a session in the service. */
export const vpnLive = (status: VpnSessionStatus) => status === 'connected' || status === 'degraded'

/** Statuses in which the connect button should offer to stop instead. */
export const vpnOn = (status: VpnSessionStatus) =>
  status === 'connected' || status === 'degraded' || status === 'reconnecting' || status === 'paused'

export const vpnBusy = (status: VpnSessionStatus) => status === 'connecting'

/** What each status says to the user. Text as well as colour, always. */
export const vpnStatusText: Record<VpnSessionStatus, { headline: string; pill: string }> = {
  idle: { headline: 'VPN is off', pill: 'Off' },
  connecting: { headline: 'Connecting…', pill: 'Connecting' },
  reconnecting: { headline: 'Reconnecting…', pill: 'Reconnecting' },
  connected: { headline: 'VPN is on', pill: 'Protected' },
  degraded: { headline: 'Node not answering', pill: 'Degraded' },
  paused: { headline: 'Paused for your game', pill: 'Paused' },
  error: { headline: 'VPN could not connect', pill: 'Error' },
}

export const vpnNodeKinds: { kind: NodeKind; label: string; hint: string }[] = [
  { kind: 'wireguard', label: 'WireGuard', hint: 'Import a .conf file' },
  { kind: 'openvpn', label: 'OpenVPN', hint: 'Import an .ovpn file' },
  { kind: 'socks5', label: 'SOCKS5', hint: 'Proxy address and login' },
  { kind: 'l2tp', label: 'L2TP/IPsec', hint: 'Server, key and login' },
]

/** Bytes per second from the session's cumulative counters, per poll. */
export function useVpnRates(session: VpnSession) {
  const previous = useRef<{ at: number; sent: number; received: number } | null>(null)
  const [rates, setRates] = useState({ sent: 0, received: 0 })
  // Keyed by when the counters were read, so a poll where nothing moved
  // brings the rate back to zero, and a push between polls changes nothing.
  const metrics = session.metrics
  const sampledAt = metrics?.sampledAt
  useEffect(() => {
    const sent = metrics?.bytesSent
    const received = metrics?.bytesReceived
    if (sent == null || received == null || sampledAt == null || !vpnLive(session.status)) {
      previous.current = null
      setRates({ sent: 0, received: 0 })
      return
    }
    const now = sampledAt
    const last = previous.current
    previous.current = { at: now, sent, received }
    if (!last || now <= last.at) return
    const seconds = (now - last.at) / 1000
    setRates({
      sent: Math.max(0, (sent - last.sent) / seconds),
      received: Math.max(0, (received - last.received) / seconds),
    })
    // Only a new sample matters; the counters arrive with it.
  }, [sampledAt, session.status])
  return rates
}

/** Re-renders once a second while `active`, for live clocks. */
export function useTicker(active: boolean) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!active) return
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [active])
  return now
}

export function formatUptime(milliseconds: number) {
  const total = Math.max(0, Math.floor(milliseconds / 1000))
  const hours = Math.floor(total / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  const seconds = total % 60
  const pad = (value: number) => String(value).padStart(2, '0')
  return hours ? `${hours}:${pad(minutes)}:${pad(seconds)}` : `${pad(minutes)}:${pad(seconds)}`
}
