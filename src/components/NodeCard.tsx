import { useState } from 'react'
import type { ReactNode } from 'react'
import { Check, Info, Radio, Share2, ShieldCheck, Trash2 } from 'lucide-react'
import { AddressWithCountry } from '../IpLocation'
import { errorMessage } from './Toast'
import { Toggle } from './Toggle'
import { nodeKindLabels } from '../lib/nodes'
import type { L2tpProbeResult, NodeGroup, Socks5ProbeResult, Tunnel } from '../types'

type Probe = Socks5ProbeResult | L2tpProbeResult
type Outcome = { ok: boolean; message: ReactNode }

/** One labelled detail under a node's name; `hint` becomes its tooltip. */
type NodeFact = { label: string; value: ReactNode; hint?: string; icon?: ReactNode }

/** The label/value pairs shown under a node, which differ per protocol. */
function nodeFacts(tunnel: Tunnel): NodeFact[] {
  switch (tunnel.kind) {
    case 'socks5':
      return [
        { label: 'Transport', value: 'UDP associate' },
        { label: 'Auth', value: tunnel.hasCredentials ? 'Username and password' : 'None' },
        {
          label: 'Encryption',
          value: 'Frames only',
          hint: 'Frames are encrypted by GamePath, but the proxy hop itself is not',
          icon: <Info size={12} aria-hidden="true" />,
        },
      ]
    case 'l2tp':
      return [
        { label: 'Transport', value: 'Windows RAS' },
        { label: 'Auth', value: 'PSK + username' },
        {
          label: 'Secrets',
          value: 'Protected',
          hint: 'The pre-shared key and password are protected by Windows secure storage',
          icon: <ShieldCheck size={12} aria-hidden="true" />,
        },
      ]
    case 'openvpn':
      return [
        { label: 'Transport', value: tunnel.protocol === 'tcp' ? 'TCP' : 'UDP' },
        { label: 'Auth', value: tunnel.hasCredentials ? 'Username and password' : 'Certificate' },
        {
          label: 'Secrets',
          value: 'Key protected',
          hint: 'The server assigns the address and the cipher when the session starts',
          icon: <ShieldCheck size={12} aria-hidden="true" />,
        },
      ]
    default:
      return [
        { label: 'Address', value: <AddressWithCountry value={tunnel.address} /> },
        { label: 'DNS', value: <AddressWithCountry value={tunnel.dns} /> },
        { label: 'Secrets', value: 'Key protected', icon: <ShieldCheck size={12} aria-hidden="true" /> },
      ]
  }
}

/**
 * One node, with everything that decides whether it can carry traffic.
 *
 * The card states its own condition rather than only its switch position: a
 * node switched on inside a switched-off group, and a proxy in direct mode,
 * both read as not carrying and say why, so the list never claims something
 * the engine will not do.
 */
export function NodeCard({
  tunnel,
  groups,
  groupEnabled,
  direct,
  onToggle,
  onMove,
  onRemove,
  onTest,
}: {
  tunnel: Tunnel
  groups: NodeGroup[]
  groupEnabled: boolean
  direct: boolean
  onToggle: (enabled: boolean) => void
  onMove: (groupId: string | null) => void
  onRemove: () => void
  onTest: () => Promise<Probe>
}) {
  const [testing, setTesting] = useState(false)
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const isProxy = tunnel.kind === 'socks5'
  const isL2tp = tunnel.kind === 'l2tp'
  // A proxy has no way to route on its own, so in direct mode it stays in the
  // list with the reason attached rather than quietly refusing to switch on.
  // Every tunnelling kind routes, so all three are usable in either mode.
  const unusable = direct && isProxy
  const carrying = tunnel.enabled && groupEnabled && !unusable
  const state = unusable
    ? { label: 'Needs a relay', tone: '' }
    : carrying
      ? { label: direct ? 'Carrying traffic' : 'Carrying', tone: 'online' }
      : tunnel.enabled
        ? { label: 'Paused by group', tone: 'paused' }
        : { label: 'Off', tone: '' }

  const runTest = async () => {
    setTesting(true)
    setOutcome(null)
    try {
      const probe = await onTest()
      if (isL2tp) {
        const l2tp = probe as L2tpProbeResult
        setOutcome({
          ok: true,
          message: `Windows connected and received ${l2tp.assignedIpv4} in ${Math.round(l2tp.setupLatencyMs)} ms; data returned in ${Math.round(l2tp.dataLatencyMs)} ms.`,
        })
      } else {
        const proxy = probe as Socks5ProbeResult
        setOutcome({
          ok: true,
          message: (
            <>
              Relay answered through <AddressWithCountry value={proxy.proxy} /> in {Math.round(proxy.latencyMs)} ms (
              {Math.round(proxy.setupLatencyMs)} ms to open the association).
            </>
          ),
        })
      }
    } catch (error) {
      setOutcome({ ok: false, message: errorMessage(error) })
    } finally {
      setTesting(false)
    }
  }

  return (
    <article className={`node-item ${carrying ? 'is-carrying' : ''} ${unusable ? 'is-unusable' : ''}`}>
      <span className="node-item-rail" aria-hidden="true" />
      <span className="node-item-avatar" aria-hidden="true">
        {isProxy ? <Share2 size={17} /> : <Radio size={17} />}
      </span>

      <div className="node-item-body">
        <div className="node-item-title">
          <h3>{tunnel.name}</h3>
          <span className="kind-pill">{nodeKindLabels[tunnel.kind]}</span>
          <span className={`status-pill ${state.tone}`}>
            <i />
            {state.label}
          </span>
        </div>
        <p className="node-item-endpoint">
          <AddressWithCountry value={tunnel.endpoint} />
        </p>
        <dl className="node-item-facts">
          {nodeFacts(tunnel).map((fact) => (
            <div key={fact.label} title={fact.hint}>
              <dt>{fact.label}</dt>
              <dd>
                {fact.icon}
                {fact.value}
              </dd>
            </div>
          ))}
        </dl>

        {outcome && (
          <p className={`node-item-note ${outcome.ok ? 'is-good' : 'is-bad'}`}>
            {outcome.ok ? <Check size={13} /> : <Info size={13} />} {outcome.message}
          </p>
        )}
        {tunnel.kind === 'openvpn' && tunnel.protocol === 'udp' && (
          <p className="node-item-note">
            <Info size={13} /> If this server’s UDP handshake cannot get through, GamePath connects it over TCP on the
            same port instead. TCP still carries your game’s UDP traffic; it just retransmits, so a lost packet holds up
            the ones behind it.
          </p>
        )}
        {isL2tp && direct && (
          <p className="node-item-note">
            <Info size={13} /> L2TP direct split routing supports IP ranges and exact hostnames. Use all-traffic mode
            for application, folder or wildcard-hostname targets; IPv6 split targets are unavailable.
          </p>
        )}
        {unusable && (
          <p className="node-item-note">
            <Info size={13} /> A SOCKS5 proxy forwards connections, it does not route packets, so it needs a relay on
            the other side. Switch to relay mode to use this node.
          </p>
        )}
      </div>

      <div className="node-item-actions">
        <label className="node-group-field">
          <span className="sr-only">Group for {tunnel.name}</span>
          <select value={tunnel.groupId ?? ''} onChange={(event) => onMove(event.target.value || null)}>
            <option value="">No group</option>
            {groups.map((group) => (
              <option key={group.id} value={group.id}>
                {group.name}
              </option>
            ))}
          </select>
        </label>
        {/* A proxy is the one node whose reachability the app cannot infer, so
            it gets a check of its own. Direct mode has no relay to answer it. */}
        {((isProxy && !direct) || isL2tp) && (
          <button className="button secondary" disabled={testing} onClick={runTest}>
            {testing ? 'Testing…' : 'Test'}
          </button>
        )}
        <Toggle
          checked={tunnel.enabled}
          disabled={unusable}
          onChange={onToggle}
          label={
            unusable
              ? `${tunnel.name} cannot be used in direct mode`
              : direct
                ? `Carry traffic through ${tunnel.name}`
                : `${tunnel.enabled ? 'Disable' : 'Enable'} ${tunnel.name}`
          }
        />
        <button className="icon-button danger" onClick={onRemove} aria-label={`Remove ${tunnel.name}`}>
          <Trash2 size={15} aria-hidden="true" />
        </button>
      </div>
    </article>
  )
}
