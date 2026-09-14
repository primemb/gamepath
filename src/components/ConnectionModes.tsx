import { ChevronRight, Info, Layers, Waypoints } from 'lucide-react'
import type { ConnectionMode } from '../types'

const connectionModes = [
  {
    id: 'relay' as const,
    icon: Layers,
    title: 'Relay mode',
    tagline: 'Lowest loss',
    body: 'Every node you enable carries the same packets to a relay you run. When one hop stumbles, the copy that took the other path still arrives on time.',
    needs: 'Needs a VPS running the GamePath relay.',
  },
  {
    id: 'direct' as const,
    icon: Waypoints,
    title: 'Direct mode',
    tagline: 'No server needed',
    body: 'Your selected traffic goes through one WireGuard, OpenVPN or L2TP/IPsec node and out to the game from there. A plain split tunnel, with nothing else to run.',
    needs: 'Needs one tunnelling node. SOCKS5 proxies can only be used with a relay.',
  },
]

/**
 * Picks how traffic leaves this PC.
 *
 * The two modes are not better and worse versions of each other — one is
 * faster, the other needs nothing to be set up — so both are shown side by
 * side with what each costs, and the one that suits what the user already has
 * is marked. The trade-off of the chosen mode is stated under it rather than
 * saved for the moment a session fails to start.
 */
export function ConnectionModes({
  mode,
  recommended,
  onSelect,
  onSetUpRelay,
}: {
  mode: ConnectionMode
  recommended: ConnectionMode | null
  onSelect: (next: ConnectionMode) => void
  onSetUpRelay: () => void
}) {
  return (
    <div className="mode-picker">
      <div className="mode-grid" role="radiogroup" aria-label="Connection mode">
        {connectionModes.map((option) => {
          const Icon = option.icon
          const active = mode === option.id
          return (
            <button
              type="button"
              role="radio"
              aria-checked={active}
              key={option.id}
              className={`mode-card ${active ? 'is-active' : ''}`}
              onClick={() => onSelect(option.id)}
            >
              <span className="mode-icon">
                <Icon size={19} />
              </span>
              <span className="mode-head">
                <strong>{option.title}</strong>
                <em>{option.tagline}</em>
                {recommended === option.id && <span className="mode-tip">Suits your setup</span>}
              </span>
              <span className="mode-body">{option.body}</span>
              <small>{option.needs}</small>
            </button>
          )
        })}
      </div>
      {mode === 'direct' && (
        <p className="mode-tradeoff">
          <Info size={14} />
          <span>
            One path means a lost packet is simply lost. Combining nodes at a relay is what makes GamePath steadier than
            a plain VPN.
          </span>
          <button className="text-button" onClick={onSetUpRelay}>
            Switch to relay mode <ChevronRight size={14} />
          </button>
        </p>
      )}
    </div>
  )
}
