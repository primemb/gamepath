import { useEffect, useState } from 'react'
import { ArrowDownLeft, ArrowUpRight, CalendarDays, Database, RotateCcw } from 'lucide-react'
import { api } from '../api'
import { formatBytes } from '../lib/format'
import type { UsageReport, UsageRow } from '../types'
import type { NoticeKind } from '../components/Toast'

type Period = 'today' | 'week' | 'year' | 'all' | 'custom'

function dateKey(date: Date) {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`
}

function bounds(period: Period, from: string, to: string) {
  const now = new Date()
  const today = dateKey(now)
  if (period === 'today') return { from: today, to: today }
  if (period === 'week') {
    const monday = new Date(now.getFullYear(), now.getMonth(), now.getDate() - ((now.getDay() + 6) % 7))
    return { from: dateKey(monday), to: today }
  }
  if (period === 'year') return { from: `${now.getFullYear()}-01-01`, to: today }
  if (period === 'all') return { from: '1970-01-01', to: '9999-12-31' }
  return { from, to }
}

function timeline(report: UsageReport, period: Period) {
  const span = (new Date(`${report.to}T12:00:00`).getTime() - new Date(`${report.from}T12:00:00`).getTime()) / 86400000
  const grouping = period === 'all' || span > 730 ? 'year' : span > 90 ? 'month' : span > 31 ? 'week' : 'day'
  const groups = new Map<string, { label: string; sent: number; received: number }>()
  const bucket = (date: Date) => {
    const day = dateKey(date)
    const key =
      grouping === 'year'
        ? day.slice(0, 4)
        : grouping === 'month'
          ? day.slice(0, 7)
          : grouping === 'week'
            ? dateKey(new Date(date.getFullYear(), date.getMonth(), date.getDate() - ((date.getDay() + 6) % 7)))
            : day
    const label =
      grouping === 'year'
        ? key
        : grouping === 'month'
          ? new Date(`${key}-01T12:00:00`).toLocaleDateString([], { month: 'short', year: 'numeric' })
          : new Date(`${key}T12:00:00`).toLocaleDateString([], { month: 'short', day: 'numeric' })
    return { key, label }
  }
  if (period !== 'all') {
    const end = new Date(`${report.to}T12:00:00`)
    let cursor = new Date(`${report.from}T12:00:00`)
    while (cursor <= end) {
      const { key, label } = bucket(cursor)
      groups.set(key, { label, sent: 0, received: 0 })
      cursor =
        grouping === 'year'
          ? new Date(cursor.getFullYear() + 1, 0, 1, 12)
          : grouping === 'month'
            ? new Date(cursor.getFullYear(), cursor.getMonth() + 1, 1, 12)
            : new Date(cursor.getFullYear(), cursor.getMonth(), cursor.getDate() + (grouping === 'week' ? 7 : 1), 12)
    }
  }
  for (const point of report.days) {
    const { key, label } = bucket(new Date(`${point.day}T12:00:00`))
    const entry = groups.get(key) ?? { label, sent: 0, received: 0 }
    entry.sent += point.sent
    entry.received += point.received
    groups.set(key, entry)
  }
  if (period === 'all' && report.days.length) {
    const first = Number(report.days[0].day.slice(0, 4))
    const last = Number(report.days.at(-1)!.day.slice(0, 4))
    for (let year = first; year <= last; year++) {
      const key = String(year)
      if (!groups.has(key)) groups.set(key, { label: key, sent: 0, received: 0 })
    }
  }
  return {
    points: [...groups.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([, value]) => value),
    grouping,
  }
}

function UsageList({ title, rows }: { title: string; rows: UsageRow[] }) {
  const maximum = Math.max(1, ...rows.map((row) => row.sent + row.received))
  return (
    <section className="usage-panel usage-list">
      <div className="usage-section-head">
        <h2>{title}</h2>
        <span>{rows.length} tracked</span>
      </div>
      {rows.length ? (
        <div className="usage-rows">
          {rows.map((row) => (
            <div className="usage-row" key={`${row.category}:${row.identity}`}>
              <div className="usage-row-top">
                <strong title={row.label}>{row.label}</strong>
                <b>{formatBytes(row.sent + row.received)}</b>
              </div>
              <div className="usage-track" aria-hidden="true">
                <span className="sent" style={{ width: `${(row.sent / maximum) * 100}%` }} />
                <span className="received" style={{ width: `${(row.received / maximum) * 100}%` }} />
              </div>
              <small>
                ↑ {formatBytes(row.sent)} sent · ↓ {formatBytes(row.received)} received
              </small>
            </div>
          ))}
        </div>
      ) : (
        <p className="usage-empty">No {title.toLowerCase()} usage in this range.</p>
      )}
    </section>
  )
}

export function StatisticsView({ notify }: { notify: (message: string, kind?: NoticeKind) => void }) {
  const today = dateKey(new Date())
  const [period, setPeriod] = useState<Period>('week')
  const [customFrom, setCustomFrom] = useState(today)
  const [customTo, setCustomTo] = useState(today)
  const [report, setReport] = useState<UsageReport | null>(null)
  const [error, setError] = useState('')
  const [resetting, setResetting] = useState(false)
  const range = bounds(period, customFrom, customTo)

  useEffect(() => {
    if (range.from > range.to) {
      setError('The start date must be on or before the end date.')
      setReport(null)
      return
    }
    let active = true
    const refresh = () =>
      api.queryUsage(range.from, range.to).then(
        (value) => {
          if (active) {
            setReport(value)
            setError('')
          }
        },
        (reason) => active && setError(reason instanceof Error ? reason.message : 'Could not load usage statistics.'),
      )
    refresh()
    const timer = window.setInterval(refresh, 15000)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [range.from, range.to])

  const reset = async () => {
    if (!window.confirm('Delete all saved usage statistics? This cannot be undone.')) return
    setResetting(true)
    try {
      await api.resetUsage()
      setReport(await api.queryUsage(range.from, range.to))
      notify('Usage statistics reset.', 'success')
    } catch (reason) {
      notify(reason instanceof Error ? reason.message : 'Could not reset statistics.', 'error')
    } finally {
      setResetting(false)
    }
  }

  const total = report?.totals.find((row) => row.category === 'total')
  const nodes = report?.totals.filter((row) => row.category === 'node') ?? []
  const apps = report?.totals.filter((row) => row.category === 'app') ?? []
  const series = report ? timeline(report, period) : { points: [], grouping: 'day' }
  const points = series.points
  const highest = Math.max(1, ...points.flatMap((point) => [point.sent, point.received]))

  return (
    <div className="usage-page">
      <div className="usage-toolbar">
        <div className="usage-periods" aria-label="Statistics period">
          {(
            [
              ['today', 'Today'],
              ['week', 'This week'],
              ['year', 'This year'],
              ['all', 'All time'],
              ['custom', 'Custom'],
            ] as const
          ).map(([value, label]) => (
            <button
              key={value}
              type="button"
              className={period === value ? 'active' : ''}
              aria-pressed={period === value}
              onClick={() => setPeriod(value)}
            >
              {label}
            </button>
          ))}
        </div>
        <button className="usage-reset" type="button" disabled={resetting} onClick={reset}>
          <RotateCcw size={15} aria-hidden="true" /> Reset statistics
        </button>
      </div>
      {period === 'custom' && (
        <div className="usage-dates">
          <CalendarDays size={16} aria-hidden="true" />
          <label>
            From{' '}
            <input
              type="date"
              value={customFrom}
              max={customTo}
              onChange={(event) => setCustomFrom(event.target.value)}
            />
          </label>
          <label>
            To{' '}
            <input
              type="date"
              value={customTo}
              min={customFrom}
              onChange={(event) => setCustomTo(event.target.value)}
            />
          </label>
        </div>
      )}
      {error && (
        <p className="usage-error" role="alert">
          {error}
        </p>
      )}
      <div className="usage-summary">
        <div className="usage-summary-card total">
          <span>
            <Database size={17} aria-hidden="true" /> Total carried
          </span>
          <strong>{formatBytes((total?.sent ?? 0) + (total?.received ?? 0))}</strong>
          <small>Unique tunnelled IP traffic</small>
        </div>
        <div className="usage-summary-card">
          <span>
            <ArrowUpRight size={17} aria-hidden="true" /> Uploaded
          </span>
          <strong>{formatBytes(total?.sent)}</strong>
          <small>From this PC</small>
        </div>
        <div className="usage-summary-card">
          <span>
            <ArrowDownLeft size={17} aria-hidden="true" /> Downloaded
          </span>
          <strong>{formatBytes(total?.received)}</strong>
          <small>To this PC</small>
        </div>
      </div>
      <section className="usage-panel usage-chart-panel">
        <div className="usage-section-head">
          <div>
            <h2>Traffic over time</h2>
            <p>
              {series.grouping === 'year'
                ? 'Yearly'
                : series.grouping === 'month'
                  ? 'Monthly'
                  : series.grouping === 'week'
                    ? 'Weekly'
                    : 'Daily'}{' '}
              usage in the selected range
            </p>
          </div>
          <div className="usage-legend">
            <span>
              <i className="sent" /> Sent
            </span>
            <span>
              <i className="received" /> Received
            </span>
          </div>
        </div>
        {report?.days.length ? (
          <div
            className="usage-chart"
            role="img"
            aria-label={`Traffic across ${points.length} periods. Sent ${formatBytes(total?.sent)}, received ${formatBytes(total?.received)}.`}
          >
            {points.map((point) => (
              <div
                className="usage-chart-column"
                key={point.label}
                title={`${point.label}: ${formatBytes(point.sent)} sent, ${formatBytes(point.received)} received`}
              >
                <div className="usage-chart-bars">
                  <span
                    className="sent"
                    style={{ height: point.sent ? `${Math.max(2, (point.sent / highest) * 100)}%` : 0 }}
                  />
                  <span
                    className="received"
                    style={{ height: point.received ? `${Math.max(2, (point.received / highest) * 100)}%` : 0 }}
                  />
                </div>
                <small>{point.label}</small>
              </div>
            ))}
          </div>
        ) : (
          <p className="usage-empty">No traffic recorded in this range yet.</p>
        )}
        {!!report?.days.length && (
          <details className="usage-data-table">
            <summary>View exact values</summary>
            <table>
              <thead>
                <tr>
                  <th scope="col">Period</th>
                  <th scope="col">Sent</th>
                  <th scope="col">Received</th>
                </tr>
              </thead>
              <tbody>
                {points.map((point) => (
                  <tr key={point.label}>
                    <th scope="row">{point.label}</th>
                    <td>{formatBytes(point.sent)}</td>
                    <td>{formatBytes(point.received)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
        )}
      </section>
      <div className="usage-details">
        <UsageList title="Nodes" rows={nodes} />
        <UsageList title="Applications" rows={apps} />
      </div>
      <p className="usage-note">
        In engine-managed modes, totals count selected IPv4 packets once. Node totals include tunnel overhead and extra
        relay copies, so they can exceed the overall total. Direct L2TP totals use Windows RAS connection counters.
        Split-tunnel flows without a process name appear as Unattributed. All-traffic and direct L2TP sessions do not
        provide per-application usage.
      </p>
    </div>
  )
}
