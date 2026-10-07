'use strict'

/**
 * How long the service keeps a session it hears nothing about: SESSION_LEASE
 * in service/src/slot.rs. A test keeps the two equal.
 */
const SERVICE_LEASE_MS = 60000

/** Errors the service answered with, in a row, before a session is given up. */
const MAX_ANSWERED_FAILURES = 3

/**
 * Decides when a session whose status requests keep failing is really gone.
 *
 * A request the service never answered says nothing about the tunnel. Observed
 * live: the service went quiet for about 35 s mid-match while all four relay
 * paths kept carrying the game, and giving up after three 5 s timeouts is what
 * tore that session down and logged the player out. So an unanswered request
 * is retried until the service's own lease has run out, by which point the
 * session is gone whatever the client does.
 *
 * An answer that is an error, or a service that refuses the connection
 * outright (it is not running, so its engines died with it), is given up on
 * after a few in a row.
 */
class SessionLease {
  constructor(now = () => Date.now()) {
    this.now = now
    this.reset()
  }

  reset() {
    this.renewedAt = this.now()
    this.failures = 0
    this.answeredFailures = 0
  }

  /** A status request succeeded. Returns how many failures it ended. */
  renewed() {
    const ended = this.failures
    this.reset()
    return ended
  }

  /** Records a failed status request. Returns whether to give the session up. */
  failed(error) {
    this.failures += 1
    if (error?.transient && error.code !== 'ECONNREFUSED') {
      return this.silentForMs() >= SERVICE_LEASE_MS
    }
    this.answeredFailures += 1
    return this.answeredFailures >= MAX_ANSWERED_FAILURES
  }

  silentForMs() {
    return this.now() - this.renewedAt
  }

  describe() {
    return `${this.failures} failed, last answered ${Math.round(this.silentForMs() / 1000)} s ago`
  }
}

module.exports = { SessionLease, SERVICE_LEASE_MS, MAX_ANSWERED_FAILURES }
