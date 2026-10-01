'use strict'

/**
 * How the game session and the VPN share the machine. The game always wins:
 * starting it is never refused because of the VPN, and the VPN steps aside
 * when the game needs what it holds.
 *
 * Both sessions in split mode coexist, because WinDivert hands every packet
 * to the game's capture first. All-traffic mode is the one thing that cannot
 * be shared: a game carrying every packet leaves the VPN nothing to carry,
 * and its default route would swallow the VPN's own tunnel.
 */

const PAUSE_REASONS = {
  'game-all-traffic':
    'Your game session is carrying all traffic. The VPN resumes when it stops or switches to split mode.',
}

const GAME_ACTIVE = new Set(['starting', 'connected'])

/** Why the VPN has to wait for the game right now, or null. */
function vpnPauseReason(gameSession, gameTrafficMode) {
  return GAME_ACTIVE.has(gameSession?.status) && gameTrafficMode === 'all' ? 'game-all-traffic' : null
}

function pauseMessage(reason) {
  return PAUSE_REASONS[reason] ?? 'The VPN is paused.'
}

/** A pause the service reports, recognised from its error text. */
function pauseReasonFromError(message) {
  return Object.keys(PAUSE_REASONS).find((reason) => String(message ?? '').includes(reason)) ?? null
}

module.exports = { vpnPauseReason, pauseMessage, pauseReasonFromError }
