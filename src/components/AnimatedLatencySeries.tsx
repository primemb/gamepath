import { useLayoutEffect, useMemo, useRef } from 'react'
import type { PathSample } from '../lib/format'

export const CHART_WIDTH = 600
export const CHART_HEIGHT = 160
export const CHART_TOP = 4
export const CHART_BOTTOM = 156
const TRANSITION_MS = 450

function curvedPath(values: number[]) {
  const step = CHART_WIDTH / (values.length - 1)
  const slopes = values.slice(1).map((value, index) => value - values[index])
  const tangents = values.map((_, index) => {
    if (index === 0) return slopes[0]
    if (index === values.length - 1) return slopes.at(-1)!
    const before = slopes[index - 1]
    const after = slopes[index]
    // Flat tangents at peaks keep the curve rounded without inventing a higher or lower reading.
    return before * after <= 0 ? 0 : (2 * before * after) / (before + after)
  })
  const segments = [`M 0 ${values[0].toFixed(2)}`]
  for (let index = 0; index < slopes.length; index++) {
    const x = index * step
    segments.push(
      `C ${(x + step / 3).toFixed(2)} ${(values[index] + tangents[index] / 3).toFixed(2)} ` +
        `${(x + (2 * step) / 3).toFixed(2)} ${(values[index + 1] - tangents[index + 1] / 3).toFixed(2)} ` +
        `${(x + step).toFixed(2)} ${values[index + 1].toFixed(2)}`,
    )
  }
  return segments.join(' ')
}

function resample(values: number[], count: number) {
  return Array.from({ length: count }, (_, index) => {
    const position = (index / (count - 1)) * (values.length - 1)
    const left = Math.floor(position)
    const next = Math.min(left + 1, values.length - 1)
    return values[left] + (values[next] - values[left]) * (position - left)
  })
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
  const area = useRef<SVGPathElement>(null)
  const line = useRef<SVGPathElement>(null)
  const displayed = useRef<number[] | null>(null)
  const target = useMemo(() => {
    const range = Math.max(high - low, 1)
    const values = samples.map((sample) => CHART_BOTTOM - ((sample.latency - low) / range) * (CHART_BOTTOM - CHART_TOP))
    return values.length === 1 ? [values[0], values[0]] : values
  }, [samples, low, high])

  useLayoutEffect(() => {
    const draw = (values: number[]) => {
      const path = curvedPath(values)
      line.current?.setAttribute('d', path)
      area.current?.setAttribute('d', `${path} L ${CHART_WIDTH} ${CHART_HEIGHT} L 0 ${CHART_HEIGHT} Z`)
      displayed.current = values
    }
    const previous = displayed.current
    const motion = window.matchMedia('(prefers-reduced-motion: reduce)')
    if (!previous || motion.matches) {
      draw(target)
      return
    }
    if (previous.length === target.length && previous.every((value, index) => value === target[index])) return

    const from = resample(previous, target.length)
    let frame = 0
    const started = performance.now()
    const tick = (now: number) => {
      const progress = Math.min((now - started) / TRANSITION_MS, 1)
      const eased = 1 - (1 - progress) ** 3
      draw(from.map((value, index) => value + (target[index] - value) * eased))
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
      <path ref={area} fill={`url(#route-fill-${route})`} />
      <path
        ref={line}
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
