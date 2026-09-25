import { useLayoutEffect, useMemo, useRef } from 'react'
import type { PathSample } from '../lib/format'

export const CHART_WIDTH = 600
export const CHART_HEIGHT = 160
export const CHART_TOP = 4
export const CHART_BOTTOM = 156
const PLOT_POINTS = 60
const TRANSITION_MS = 450

function plotPoints(values: number[]) {
  return values.map((y, index) => `${((index / (PLOT_POINTS - 1)) * CHART_WIDTH).toFixed(2)},${y.toFixed(2)}`).join(' ')
}

export function AnimatedLatencySeries({
  samples,
  low,
  high,
  color,
  route,
}: {
  samples: PathSample[]
  low: number
  high: number
  color: string
  route: number
}) {
  const polygon = useRef<SVGPolygonElement>(null)
  const polyline = useRef<SVGPolylineElement>(null)
  const displayed = useRef<number[] | null>(null)
  const target = useMemo(() => {
    const range = Math.max(high - low, 1)
    return Array.from({ length: PLOT_POINTS }, (_, index) => {
      const position = (index / (PLOT_POINTS - 1)) * (samples.length - 1)
      const left = Math.floor(position)
      const next = Math.min(left + 1, samples.length - 1)
      const latency = samples[left].latency + (samples[next].latency - samples[left].latency) * (position - left)
      return CHART_BOTTOM - ((latency - low) / range) * (CHART_BOTTOM - CHART_TOP)
    })
  }, [samples, low, high])

  useLayoutEffect(() => {
    const draw = (values: number[]) => {
      const points = plotPoints(values)
      polyline.current?.setAttribute('points', points)
      polygon.current?.setAttribute('points', `0,${CHART_HEIGHT} ${points} ${CHART_WIDTH},${CHART_HEIGHT}`)
      displayed.current = values
    }
    const previous = displayed.current
    const motion = window.matchMedia('(prefers-reduced-motion: reduce)')
    if (!previous || motion.matches) {
      draw(target)
      return
    }
    if (previous.every((value, index) => value === target[index])) return

    let frame = 0
    const started = performance.now()
    const tick = (now: number) => {
      const progress = Math.min((now - started) / TRANSITION_MS, 1)
      const eased = 1 - (1 - progress) ** 3
      draw(previous.map((value, index) => value + (target[index] - value) * eased))
      if (progress < 1) frame = requestAnimationFrame(tick)
      else draw(target)
    }
    const onMotionChange = () => {
      if (!motion.matches) return
      cancelAnimationFrame(frame)
      draw(target)
    }
    motion.addEventListener('change', onMotionChange)
    frame = requestAnimationFrame(tick)
    return () => {
      cancelAnimationFrame(frame)
      motion.removeEventListener('change', onMotionChange)
    }
  }, [target])

  return (
    <g>
      <polygon ref={polygon} fill={`url(#route-fill-${route})`} />
      <polyline
        ref={polyline}
        fill="none"
        stroke={color}
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
    </g>
  )
}
