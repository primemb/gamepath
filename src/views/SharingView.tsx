import { Gamepad2, Globe, Layers, ShieldCheck, TriangleAlert } from 'lucide-react'
import { api } from '../api'
import { ConsoleSetupGuide } from '../components/ConsoleSetupGuide'
import { CopyField } from '../components/CopyField'
import { LanProxyDevices } from '../components/LanProxyDevices'
import { LanProxySettingsForm } from '../components/LanProxySettingsForm'
import { Toggle } from '../components/Toggle'
import { errorMessage, type Notify } from '../components/Toast'
import { primaryLanAddress } from '../lib/lanProxy'
import type { AppState, LanProxySettingsInput } from '../types'

export function SharingView({
  state,
  setState,
  notify,
}: {
  state: AppState
  setState: (next: AppState) => void
  notify: Notify
}) {
  const settings = state.lanProxy
  const connected = state.session.status === 'connected'
  const status = connected ? state.session.lanProxy : undefined
  const listening = status?.state === 'listening'
  const failed = status?.state === 'error'
  const address = primaryLanAddress(status) ?? state.lanAddresses?.[0] ?? null
  const otherAddresses = (status?.addresses?.map((entry) => entry.address) ?? state.lanAddresses ?? []).filter(
    (entry) => entry !== address,
  )
  const port = listening && status?.port ? status.port : settings.port
  const movedPort = listening && status?.requestedPort && status.port !== status.requestedPort

  const save = async (input: LanProxySettingsInput) => {
    setState(await api.configureLanProxy(input))
    notify(
      connected && settings.enabled ? 'LAN proxy updated. The session stayed connected.' : 'LAN proxy saved.',
      'success',
    )
  }

  const toggle = async (enabled: boolean) => {
    try {
      setState(await api.configureLanProxy({ enabled }))
    } catch (error) {
      notify(errorMessage(error), 'error')
    }
  }

  const [tone, headline, detail] = !settings.enabled
    ? ['off', 'Sharing is off', 'Turn it on to let a console, phone or another PC use this session.']
    : failed
      ? ['error', 'The proxy did not start', status?.error ?? 'Check the port and try again.']
      : listening
        ? [
            'live',
            'Devices can connect',
            "Point a device's proxy setting at this PC. Its traffic goes through the session, whatever the split-tunnel rules say.",
          ]
        : [
            'ready',
            'Ready for the next session',
            `The proxy opens on port ${settings.port} as soon as you start a session.`,
          ]
  const statusLabel = { off: 'Off', error: 'Error', live: 'Listening', ready: 'Waiting for session' }[tone]

  return (
    <section className="page-section sharing-page">
      <div className={`sharing-hero is-${tone}`}>
        <div className="sharing-hero-head">
          <span className="sharing-hero-icon" aria-hidden="true">
            <Gamepad2 size={22} />
          </span>
          <div>
            <span className="eyebrow">LAN proxy · SOCKS5 and HTTP</span>
            <h2>{headline}</h2>
            <p>{detail}</p>
          </div>
          <span className={`sharing-state is-${tone}`}>
            <i aria-hidden="true" />
            {statusLabel}
          </span>
          <Toggle checked={settings.enabled} onChange={toggle} label="Share this session on the local network" />
        </div>
        <div className="sharing-endpoint">
          <CopyField label="Address" value={address ?? 'No network found'} disabled={!address || !settings.enabled} />
          <CopyField label="Port" value={String(port)} disabled={!settings.enabled} />
          <CopyField
            label="SOCKS5 link"
            value={address ? `socks5://${address}:${port}` : '—'}
            disabled={!address || !settings.enabled}
          />
        </div>
        {movedPort && (
          <p className="sharing-warning">
            <TriangleAlert size={14} aria-hidden="true" />
            {`Port ${status?.requestedPort} was in use, so the proxy took ${status?.port}.`}
          </p>
        )}
        {otherAddresses.length > 0 && settings.enabled && (
          <p className="sharing-alternates">
            Also reachable at <span data-no-translate>{otherAddresses.join(', ')}</span>
          </p>
        )}
        <ul className="sharing-facts">
          <li>
            <Layers size={14} aria-hidden="true" /> TCP and UDP
          </li>
          <li>
            <Globe size={14} aria-hidden="true" /> Name lookups through the tunnel
          </li>
          <li>
            <ShieldCheck size={14} aria-hidden="true" /> Local network only
          </li>
        </ul>
      </div>

      <div className="sharing-grid">
        <LanProxyDevices status={status} sessionActive={connected} />
        <LanProxySettingsForm settings={settings} onSave={save} />
      </div>

      <ConsoleSetupGuide address={address ?? 'this-pc'} port={port} login={settings.hasPassword} />
    </section>
  )
}
