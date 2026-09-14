import type { PathMetric } from '../types'

export const formatMetric = (value: number | null | undefined) => (value == null ? '—' : `${Math.round(value)} ms`)

export const formatBytes = (bytes: number | undefined) => {
  const value = bytes ?? 0
  if (value < 1024) return `${value} B`
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`
  return `${(value / 1024 ** 2).toFixed(2)} MB`
}

export const formatRate = (bytesPerSecond: number | undefined) => `${formatBytes(bytesPerSecond)}/s`

/** One latency reading, tagged with the probe it came from so repeats are skipped. */
export type PathSample = { latency: number; probe: number }
export type PathHistory = Record<number, PathSample[]>
export type PathRate = { sent: number; received: number }

export const pathColors = ['#26e6cd', '#8a7cff', '#ffb35c', '#5ca8ff', '#ef6fae', '#8fdb62']

export const jitter = (samples: PathSample[]) =>
  samples.length < 2
    ? 0
    : samples.slice(1).reduce((total, sample, index) => total + Math.abs(sample.latency - samples[index].latency), 0) /
      (samples.length - 1)

// The engine's smoothed estimate, not a lifetime average: a route that lost
// probes at startup and has been clean since should read clean.
export const pathLoss = (path: PathMetric) => path.lossPercent ?? 0

export const histogramPercentile = (
  buckets: Array<{ upperBoundUs: number | null; count: number }> | undefined,
  percentile: number,
) => {
  if (!buckets?.length) return null
  const total = buckets.reduce((sum, bucket) => sum + bucket.count, 0)
  if (!total) return null
  const target = total * percentile
  let seen = 0
  for (const bucket of buckets) {
    seen += bucket.count
    if (seen >= target) return bucket.upperBoundUs
  }
  return null
}

export const formatClockTime = (secondsSinceEpoch: number) =>
  new Date(secondsSinceEpoch * 1000).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
