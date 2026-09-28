import { ArrowDownLeft, ArrowUpRight, MonitorSmartphone } from 'lucide-react'
import { formatBytes, formatRate } from '../lib/format'
import { connectedDevices, useLanProxyRates } from '../lib/lanProxy'
import type { LanProxyStatus } from '../types'

/** Every device that has used the proxy this session, busiest first. */
export function LanProxyDevices({
  status,
  sessionActive,
}: {
  status: LanProxyStatus | undefined
  sessionActive: boolean
}) {
  const rates = useLanProxyRates(status)
  const devices = [...(status?.clients ?? [])].sort(
    (left, right) => right.bytesSent + right.bytesReceived - (left.bytesSent + left.bytesReceived),
  )
  const connected = connectedDevices(status).length

  return (
    <section className="sharing-card sharing-devices" aria-labelledby="sharing-devices-title">
      <div className="sharing-card-head">
        <div>
          <span className="eyebrow">Live</span>
          <h3 id="sharing-devices-title">Connected devices</h3>
        </div>
        <span className={`device-count ${connected ? 'is-live' : ''}`} role="status" aria-atomic="true">
          <i aria-hidden="true" />
          {`${connected} connected`}
        </span>
      </div>
      {devices.length ? (
        <div className="device-table" role="table" aria-label="Devices using the proxy">
          <div className="device-row device-header" role="row">
            <span role="columnheader">Device</span>
            <span role="columnheader">Open</span>
            <span role="columnheader">Now</span>
            <span role="columnheader">This session</span>
          </div>
          {devices.map((device) => {
            const rate = rates[device.address]
            return (
              <div className={`device-row ${device.connected ? '' : 'is-idle'}`} role="row" key={device.address}>
                <span className="device-identity" role="cell">
                  <MonitorSmartphone size={16} aria-hidden="true" />
                  <span>
                    <strong data-no-translate>{device.address}</strong>
                    <small>{device.connected ? 'Connected' : 'Idle'}</small>
                  </span>
                </span>
                <span className="device-flows" role="cell">
                  <b>{device.activeTcp}</b> TCP · <b>{device.activeUdp}</b> UDP
                </span>
                <span className="device-rate" role="cell">
                  <span>
                    <ArrowUpRight size={12} aria-label="Upload" /> {formatRate(Math.round(rate?.sent ?? 0))}
                  </span>
                  <span>
                    <ArrowDownLeft size={12} aria-label="Download" /> {formatRate(Math.round(rate?.received ?? 0))}
                  </span>
                </span>
                <span className="device-total" role="cell">
                  ↑ {formatBytes(device.bytesSent)} · ↓ {formatBytes(device.bytesReceived)}
                </span>
              </div>
            )
          })}
        </div>
      ) : (
        <p className="sharing-empty">
          {status?.state === 'listening'
            ? 'No device has connected yet. Enter the address and port above in its proxy settings.'
            : sessionActive
              ? 'The proxy is not running, so no device can connect.'
              : 'Devices appear here while a session is running.'}
        </p>
      )}
    </section>
  )
}
