import { useEffect, useRef, useState } from 'react'
import type { PathHistory, PathRate } from './format'
import type { AppState } from '../types'

/**
 * Keeps the per-route latency history and byte rates the dashboard charts.
 *
 * The engine reports running totals, so the rates are differences between two
 * polls rather than anything the session itself provides, and a sample is only
 * appended when the probe counter moves — otherwise a route that has stopped
 * answering would keep drawing a flat line out of its last reading.
 */
export function useSessionTelemetry(state: AppState | null) {
  const [histories, setHistories] = useState<PathHistory>({})
  const [rates, setRates] = useState<Record<number, PathRate>>({})
  const previousCounters = useRef<{ at: number; paths: Record<number, { sent: number; received: number }> } | null>(
    null,
  )

  useEffect(() => {
    if (state?.session.status === 'idle') {
      setHistories({})
      setRates({})
      previousCounters.current = null
      return
    }
    const paths = state?.session.pathMetrics
    if (!paths?.length) return

    setHistories((current) => {
      const next = { ...current }
      for (const path of paths) {
        if (path.latencyMs == null) continue
        const probe = path.probesReceived ?? 0
        const samples = next[path.route] ?? []
        if (samples.at(-1)?.probe !== probe)
          next[path.route] = [...samples.slice(-59), { latency: path.latencyMs, probe }]
      }
      return next
    })

    const now = performance.now()
    const previous = previousCounters.current
    if (previous) {
      const elapsed = Math.max((now - previous.at) / 1000, 0.001)
      setRates(
        Object.fromEntries(
          paths.map((path) => {
            const old = previous.paths[path.route]
            return [
              path.route,
              {
                sent: old ? Math.max(0, path.bytesSent - old.sent) / elapsed : 0,
                received: old ? Math.max(0, path.bytesReceived - old.received) / elapsed : 0,
              },
            ]
          }),
        ),
      )
    }
    previousCounters.current = {
      at: now,
      paths: Object.fromEntries(
        paths.map((path) => [path.route, { sent: path.bytesSent, received: path.bytesReceived }]),
      ),
    }
  }, [state?.session.pathMetrics, state?.session.status])

  return { histories, rates }
}
