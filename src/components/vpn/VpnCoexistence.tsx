import { ChevronRight, Gamepad2, PauseCircle } from 'lucide-react'
import type { AppState } from '../../types'

/**
 * How the VPN sits beside the game. The game always wins, and the user should
 * never have to guess why the VPN stepped aside.
 */
export function VpnCoexistence({ state, onOpenGame }: { state: AppState; onOpenGame: () => void }) {
  const { session } = state.vpn
  if (session.status === 'paused') {
    return (
      <div className="vpn-banner is-warning" role="status">
        <PauseCircle size={18} aria-hidden="true" />
        <div>
          <strong>The VPN is paused for your game</strong>
          <p>{session.message}</p>
        </div>
        <button className="button secondary" onClick={onOpenGame}>
          Game traffic settings
          <ChevronRight size={14} aria-hidden="true" />
        </button>
      </div>
    )
  }
  if (state.session.status !== 'connected') return null
  return (
    <div className="vpn-banner">
      <Gamepad2 size={18} aria-hidden="true" />
      <div>
        <strong>Your game session is running and takes priority</strong>
        <p>
          Apps you selected for the game always use the game session, even if they are also listed here. Everything else
          you select below uses the VPN.
        </p>
      </div>
    </div>
  )
}
