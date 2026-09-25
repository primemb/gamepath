import { formatMetric, pathColors, type PathHistory } from '../lib/format'
import type { PathMetric } from '../types'
import { AnimatedLatencySeries, CHART_BOTTOM, CHART_HEIGHT, CHART_TOP, CHART_WIDTH } from './AnimatedLatencySeries'

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
          {series.map((item) =>
            item.samples.length ? (
              <AnimatedLatencySeries
                key={item.path.route}
                samples={item.samples}
                low={low}
                high={high}
                color={item.color}
                route={item.path.route}
              />
            ) : null,
          )}
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
