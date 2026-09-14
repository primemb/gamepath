import { formatMetric, pathColors, type PathHistory, type PathSample } from '../lib/format'
import type { PathMetric } from '../types'

const CHART_WIDTH = 600
const CHART_HEIGHT = 160
const CHART_TOP = 4
const CHART_BOTTOM = 156

export function LatencyChart({ histories, paths }: { histories: PathHistory; paths: PathMetric[] }) {
  const series = paths.map((path, index) => ({
    path,
    color: pathColors[index % pathColors.length],
    samples: histories[path.route] ?? [],
  }))
  const allValues = series.flatMap((item) => item.samples.map((sample) => sample.latency))
  const maximum = allValues.length ? Math.max(...allValues) : 10
  const minimum = allValues.length ? Math.min(...allValues) : 0
  const padding = Math.max((maximum - minimum) * 0.15, 4)
  const low = Math.max(0, minimum - padding)
  const high = maximum + padding
  const range = Math.max(high - low, 1)
  const project = (latency: number) => CHART_BOTTOM - ((latency - low) / range) * (CHART_BOTTOM - CHART_TOP)
  const line = (samples: PathSample[]) => {
    const values = samples.length === 1 ? [samples[0], samples[0]] : samples
    return values
      .map((sample, index) => `${(index / Math.max(values.length - 1, 1)) * CHART_WIDTH},${project(sample.latency)}`)
      .join(' ')
  }
  if (!series.length) return <p className="chart-empty">Route latency appears here as soon as a session is running.</p>
  return (
    <>
      <div className="chart-body">
        <div className="chart-axis">
          <span>{Math.round(high)} ms</span>
          <span>{Math.round((high + low) / 2)} ms</span>
          <span>{Math.round(low)} ms</span>
        </div>
        <svg
          className="latency-chart"
          viewBox={`0 0 ${CHART_WIDTH} ${CHART_HEIGHT}`}
          preserveAspectRatio="none"
          role="img"
          aria-label="Latency history for every WireGuard route"
        >
          <defs>
            {series.map((item) => (
              <linearGradient key={item.path.route} id={`route-fill-${item.path.route}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={item.color} stopOpacity="0.26" />
                <stop offset="100%" stopColor={item.color} stopOpacity="0" />
              </linearGradient>
            ))}
          </defs>
          <g className="chart-grid">
            <line x1="0" y1={CHART_TOP} x2={CHART_WIDTH} y2={CHART_TOP} />
            <line x1="0" y1={(CHART_TOP + CHART_BOTTOM) / 2} x2={CHART_WIDTH} y2={(CHART_TOP + CHART_BOTTOM) / 2} />
            <line x1="0" y1={CHART_BOTTOM} x2={CHART_WIDTH} y2={CHART_BOTTOM} />
          </g>
          {series.map((item) => {
            if (!item.samples.length) return null
            const points = line(item.samples)
            return (
              <g key={item.path.route}>
                <polygon
                  points={`0,${CHART_HEIGHT} ${points} ${CHART_WIDTH},${CHART_HEIGHT}`}
                  fill={`url(#route-fill-${item.path.route})`}
                />
                <polyline
                  points={points}
                  fill="none"
                  stroke={item.color}
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                />
              </g>
            )
          })}
        </svg>
      </div>
      <div className="chart-legend">
        {series.map((item) => (
          <span key={item.path.route}>
            <i style={{ background: item.color }} />
            {item.path.label}
            <strong>{formatMetric(item.path.latencyMs)}</strong>
          </span>
        ))}
      </div>
    </>
  )
}
