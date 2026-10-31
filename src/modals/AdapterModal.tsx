import { useEffect, useState, type ReactNode } from 'react'
import { Check, Info, RefreshCw, X, Zap } from 'lucide-react'
import { api } from '../api'
import { errorMessage } from '../components/Toast'
import type { AdapterNodeInput, AdapterProbeResult, NetworkAdapter } from '../types'

export const describeAdapterProbe = ({ check, udp }: AdapterProbeResult) =>
  `${check.adapter} opened a connection in ${Math.round(check.latencyMs)} ms` +
  (udp && check.udpLatencyMs != null
    ? ` and carried UDP in ${Math.round(check.udpLatencyMs)} ms`
    : ', but no UDP answer came back') +
  (check.publicAddress ? `; traffic leaves as ${check.publicAddress}.` : '.')

/**
 * The prefix a VPN app's adapters share, so a node keeps working when the app
 * switches protocol and brings up another (`WindscribeOpenVPN`,
 * `WindscribeWireguard`).
 */
const appName = (adapter: NetworkAdapter) =>
  adapter.name.match(/^(.+?)\s*(?:OpenVPN|WireGuard|IKEv2)$/i)?.[1] || adapter.name

/**
 * Adds another VPN app's adapter as a node: Windscribe, or any app that
 * leaves a Windows adapter behind. GamePath sends traffic out through it, so
 * the app's own transport and anti-censorship carry it, UDP included.
 */
export function AdapterModal({
  onClose,
  onAdd,
  onTest,
  intro,
}: {
  onClose: () => void
  onAdd: (input: AdapterNodeInput) => Promise<void>
  onTest: (input: AdapterNodeInput) => Promise<AdapterProbeResult>
  intro: ReactNode
}) {
  const [adapters, setAdapters] = useState<NetworkAdapter[] | null>(null)
  const [adapter, setAdapter] = useState('')
  const [label, setLabel] = useState('')
  const [busy, setBusy] = useState<'idle' | 'testing' | 'saving'>('idle')
  const [result, setResult] = useState<AdapterProbeResult | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  const refresh = async () => {
    try {
      const found = await api.listNetworkAdapters()
      setAdapters(found)
      const vpn = found.find((item) => !item.hardware)
      setAdapter((current) => current || (vpn ? appName(vpn) : ''))
    } catch (error) {
      setAdapters([])
      setFailure(errorMessage(error))
    }
  }

  useEffect(() => {
    void refresh()
  }, [])

  const input = (): AdapterNodeInput => ({ adapter: adapter.trim(), label: label.trim() || undefined })

  const runTest = async () => {
    setBusy('testing')
    setResult(null)
    setFailure(null)
    try {
      setResult(await onTest(input()))
    } catch (error) {
      setFailure(errorMessage(error))
    } finally {
      setBusy('idle')
    }
  }

  const save = async () => {
    setBusy('saving')
    setFailure(null)
    try {
      await onAdd(input())
    } catch (error) {
      setFailure(errorMessage(error))
      setBusy('idle')
    }
  }

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section
        className="modal relay-modal"
        onMouseDown={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Add a VPN app node"
      >
        <div className="modal-head">
          <div>
            <span className="eyebrow">VPN app</span>
            <h2>Use another VPN app’s connection</h2>
          </div>
          <button className="icon-button" onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <p className="modal-intro">{intro}</p>
        <label className="field-label">
          Adapter
          <input
            autoFocus
            list="gamepath-adapters"
            value={adapter}
            onChange={(event) => setAdapter(event.target.value)}
            placeholder="Windscribe"
          />
          <datalist id="gamepath-adapters">
            {adapters?.flatMap((item) => [
              <option key={`${item.interfaceIndex}-app`} value={appName(item)}>
                {item.description} · {item.address}
              </option>,
              ...(appName(item) === item.name
                ? []
                : [
                    <option key={`${item.interfaceIndex}-name`} value={item.name}>
                      {item.description} · {item.address}
                    </option>,
                  ]),
            ])}
          </datalist>
          <small>
            {adapters === null
              ? 'Looking for connected adapters…'
              : adapters.some((item) => !item.hardware)
                ? 'The start of a name is enough: “Windscribe” follows whichever protocol the app is connected with.'
                : 'No VPN app adapter is connected. Connect the app, then refresh.'}{' '}
            <button className="text-button" type="button" onClick={() => void refresh()}>
              <RefreshCw size={12} aria-hidden="true" /> Refresh
            </button>
          </small>
        </label>
        <label className="field-label">
          Name (optional)
          <input value={label} onChange={(event) => setLabel(event.target.value)} placeholder="Windscribe" />
        </label>
        {result && (
          <div className="info-banner">
            {result.udp ? <Check size={18} /> : <Info size={18} />}
            <div>
              <strong>{result.udp ? 'This connection carries TCP and UDP' : 'This connection carries TCP only'}</strong>
              <p>{describeAdapterProbe(result)}</p>
            </div>
          </div>
        )}
        {failure && (
          <div className="info-banner">
            <Info size={18} />
            <div>
              <strong>This adapter cannot be used yet</strong>
              <p>{failure}</p>
            </div>
          </div>
        )}
        <div className="modal-actions">
          <button className="button secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="button secondary" disabled={!adapter.trim() || busy !== 'idle'} onClick={runTest}>
            <Zap size={16} />
            {busy === 'testing' ? 'Testing…' : 'Test'}
          </button>
          <button className="button primary" disabled={!adapter.trim() || busy !== 'idle'} onClick={save}>
            <Check size={16} />
            {busy === 'saving' ? 'Saving…' : 'Add node'}
          </button>
        </div>
      </section>
    </div>
  )
}
