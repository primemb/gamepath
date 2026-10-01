const assert = require('node:assert/strict')
const test = require('node:test')
const { vpnPauseReason, pauseMessage, pauseReasonFromError } = require('./session-coordinator.cjs')

test('only a live all-traffic game session pauses the VPN', () => {
  const cases = [
    [{ status: 'idle' }, 'all', null],
    [{ status: 'error' }, 'all', null],
    [{ status: 'connected' }, 'split', null],
    [{ status: 'starting' }, 'split', null],
    [{ status: 'connected' }, 'all', 'game-all-traffic'],
    [{ status: 'starting' }, 'all', 'game-all-traffic'],
    [undefined, 'all', null],
  ]
  for (const [game, mode, expected] of cases) {
    assert.equal(vpnPauseReason(game, mode), expected, `${game?.status} ${mode}`)
  }
})

test('a pause is explained to the user and recognised from the service', () => {
  assert.match(pauseMessage('game-all-traffic'), /resumes when it stops/)
  assert.equal(pauseMessage('unknown'), 'The VPN is paused.')
  assert.equal(pauseReasonFromError('game-all-traffic: the game session is carrying all traffic'), 'game-all-traffic')
  assert.equal(pauseReasonFromError('no active network session (game-all-traffic)'), 'game-all-traffic')
  assert.equal(pauseReasonFromError('no active network session (lease-expired)'), null)
  assert.equal(pauseReasonFromError(undefined), null)
})
