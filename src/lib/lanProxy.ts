import { useEffect, useRef, useState } from 'react'
import type { PathRate } from './format'
import type { LanProxyStatus } from '../types'

/** The address a console on the same router should be given. */
export function primaryLanAddress(status: LanProxyStatus | undefined) {
  return status?.addresses?.[0]?.address ?? null
}

export function connectedDevices(status: LanProxyStatus | undefined) {
  return (status?.clients ?? []).filter((device) => device.connected)
}

/**
 * Per-device transfer rates, from the difference between two status polls.
 * The engine reports running totals, as it does for routes.
 */
export function useLanProxyRates(status: LanProxyStatus | undefined) {
  const [rates, setRates] = useState<Record<string, PathRate>>({})
  const previous = useRef<{ at: number; startedAt?: number; totals: Record<string, PathRate> } | null>(null)

  useEffect(() => {
    const clients = status?.clients
    if (status?.state !== 'listening' || !clients) {
      previous.current = null
      setRates({})
      return
    }
    const now = performance.now()
    const totals = Object.fromEntries(
      clients.map((device) => [device.address, { sent: device.bytesSent, received: device.bytesReceived }]),
    )
    const last = previous.current
    // A restarted proxy counts from zero again, so its first sample has no rate.
    if (last && last.startedAt === status.startedAt) {
      const elapsed = Math.max((now - last.at) / 1000, 0.001)
      setRates(
        Object.fromEntries(
          clients.map((device) => {
            const old = last.totals[device.address]
            return [
              device.address,
              {
                sent: old ? Math.max(0, device.bytesSent - old.sent) / elapsed : 0,
                received: old ? Math.max(0, device.bytesReceived - old.received) / elapsed : 0,
              },
            ]
          }),
        ),
      )
    }
    previous.current = { at: now, startedAt: status.startedAt, totals }
  }, [status])

  return rates
}
