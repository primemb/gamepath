/**
 * Decides when a relay session should move to its standby relay.
 *
 * Moving costs the session: every node redials, and the game sees a new public
 * address, so it has to rejoin whatever it was in. That is worth paying only
 * for a relay that is gone, never for a freeze it comes back from. A relay VPS
 * pausing on an overloaded host went silent for 3-21 s at a time and recovered
 * each time, so silence alone is not the test; this answers only when every
 * independent witness agrees:
 *
 * - the session had carried traffic, so the outage is not a slow start;
 * - every path to the relay is down, without a break;
 * - the uplink monitor, which probes the Internet outside every node, reports
 *   this machine's own connection up throughout, so the cause is not local;
 * - where this machine can reach the relay directly (learned while the session
 *   was healthy), direct probes fail too, with no success in between: one
 *   answer means the relay is alive and only the paths to it are not.
 *
 * With the direct witness the silence has to last `OUTAGE_WITH_WITNESS_MS`;
 * without it, on a network that filters direct traffic to the relay, twice as
 * long. The caller asks for at most one move per session and never moves back.
 */

const OUTAGE_WITH_WITNESS_MS = 30_000
const OUTAGE_WITHOUT_WITNESS_MS = 60_000
const DIRECT_PROBE_INTERVAL_MS = 5_000
const DIRECT_FAILURES_REQUIRED = 3
/** How often a healthy session re-checks that direct probes still reach the relay. */
const BASELINE_INTERVAL_MS = 10 * 60_000
/**
 * How long a direct answer during an outage settles the question. The relay is
 * up, so there is nothing to decide, and every probe opens a session on a relay
 * from before stateless probe replies: a probe every few seconds through a long
 * outage could push the real session out of that relay's per-client cap.
 */
const RELAY_ALIVE_HOLD_MS = 60_000

class RelayFailoverWatch {
  constructor() {
    this.carried = false
    this.done = false
    /** true once a direct probe has reached the relay this session. */
    this.directWitness = false
    this.lastBaselineAt = null
    this.aliveUntil = null
    this.epoch = 0
    this.resetOutage()
  }

  resetOutage() {
    this.outageSince = null
    this.directFailures = 0
    this.lastDirectProbeAt = null
    // Probe results from a previous outage must not count toward this one.
    this.epoch += 1
  }

  /**
   * One session-status observation. Returns `{ action, epoch }`, where action
   * is `none`, `probe-baseline`, `probe-outage` or `failover`.
   */
  observe({ connected, uplink, now }) {
    const answer = (action) => ({ action, epoch: this.epoch })
    if (this.done) return answer('none')
    if (connected) {
      this.carried = true
      if (this.outageSince !== null) this.resetOutage()
      if (this.lastBaselineAt === null || now - this.lastBaselineAt >= BASELINE_INTERVAL_MS) {
        this.lastBaselineAt = now
        return answer('probe-baseline')
      }
      return answer('none')
    }
    if (!this.carried) return answer('none')
    if (this.aliveUntil !== null && now < this.aliveUntil) return answer('none')
    if (uplink !== 'up') {
      if (this.outageSince !== null) this.resetOutage()
      return answer('none')
    }
    this.outageSince ??= now
    const silent = now - this.outageSince
    if (!this.directWitness) return answer(silent >= OUTAGE_WITHOUT_WITNESS_MS ? 'failover' : 'none')
    if (this.directFailures >= DIRECT_FAILURES_REQUIRED && silent >= OUTAGE_WITH_WITNESS_MS) return answer('failover')
    if (this.lastDirectProbeAt === null || now - this.lastDirectProbeAt >= DIRECT_PROBE_INTERVAL_MS) {
      this.lastDirectProbeAt = now
      return answer('probe-outage')
    }
    return answer('none')
  }

  /** A direct probe sent while the session was healthy. */
  noteBaseline(reachable) {
    if (reachable) this.directWitness = true
  }

  /** A direct probe sent during the outage numbered `epoch`, answered at `now`. */
  noteOutageProbe(reachable, epoch, now) {
    if (epoch !== this.epoch || this.done) return
    if (reachable) {
      // The relay is up; what failed is the paths to it, which a different
      // relay would not fix. The clock starts again, after a quiet spell.
      this.resetOutage()
      this.aliveUntil = now + RELAY_ALIVE_HOLD_MS
      return
    }
    this.directFailures += 1
  }

  /** How long every path has been silent, for the log line that explains a move. */
  silentFor(now) {
    return this.outageSince === null ? 0 : now - this.outageSince
  }

  finish() {
    this.done = true
  }
}

/**
 * Runs a `RelayFailoverWatch` against a live session: sends the direct probes
 * it asks for without holding up the status poll, and hands the move itself to
 * `moveToStandby`, which the main process owns because it owns the session.
 *
 * `moveToStandby({ silentMs, directWitness })` resolves to `moved`, `no-standby`
 * or `standby-down`. Only `standby-down` is worth another try later, after a
 * fresh outage has been measured from the start.
 */
class RelayFailoverController {
  constructor({ probeMainRelay, moveToStandby, logger, now = () => Date.now() }) {
    this.probeMainRelay = probeMainRelay
    this.moveToStandby = moveToStandby
    this.logger = logger
    this.now = now
    this.watch = null
    this.probing = false
    this.moving = false
  }

  /** A session has started. `watching` is false when the setting is off or this session is already the move. */
  begin(watching) {
    this.watch = new RelayFailoverWatch()
    if (!watching) this.watch.finish()
  }

  end() {
    this.watch?.finish()
    this.watch = null
  }

  /** One `session-status` result from the service. */
  observe(runtime) {
    const watch = this.watch
    if (!watch || watch.done || this.moving) return
    const now = this.now()
    const { action, epoch } = watch.observe({
      connected: runtime.state === 'connected',
      uplink: runtime.uplink,
      now,
    })
    if (action === 'probe-baseline' || action === 'probe-outage') this.probe(watch, action, epoch)
    if (action === 'failover') this.move(watch, now)
  }

  probe(watch, action, epoch) {
    // A probe waits up to three seconds, as long as a poll interval; one at a
    // time, and a missed turn is simply taken at the next poll.
    if (this.probing) {
      if (action === 'probe-outage') watch.lastDirectProbeAt = null
      return
    }
    this.probing = true
    Promise.resolve()
      .then(() => this.probeMainRelay())
      .catch(() => false)
      .then((reachable) => {
        if (action === 'probe-baseline') watch.noteBaseline(reachable)
        else watch.noteOutageProbe(reachable, epoch, this.now())
      })
      .finally(() => {
        this.probing = false
      })
  }

  move(watch, now) {
    this.moving = true
    const silentMs = watch.silentFor(now)
    Promise.resolve()
      .then(() => this.moveToStandby({ silentMs, directWitness: watch.directWitness }))
      .catch((error) => {
        this.logger.error(`relay failover failed: ${error.message}`)
        return 'moved'
      })
      .then((outcome) => {
        if (outcome === 'standby-down') watch.resetOutage()
        else watch.finish()
      })
      .finally(() => {
        this.moving = false
      })
  }
}

/**
 * The relay a session on `mainId` would move to: the one the user picked, or
 * the first other relay that is set up when they left it automatic. A relay
 * on the same address as the main one is no standby at all.
 */
function standbyRelayFor(relays, hasToken, mainId, preferredId) {
  const main = relays.find((relay) => relay.id === mainId)
  const candidates = relays.filter(
    (relay) => relay.id !== mainId && relay.address && hasToken(relay.id) && relay.address !== main?.address,
  )
  if (preferredId) return candidates.find((relay) => relay.id === preferredId) ?? null
  return candidates[0] ?? null
}

function normalizeRelayFailover(value) {
  return {
    enabled: value?.enabled === true,
    standbyRelayId: typeof value?.standbyRelayId === 'string' && value.standbyRelayId ? value.standbyRelayId : null,
  }
}

module.exports = {
  BASELINE_INTERVAL_MS,
  DIRECT_FAILURES_REQUIRED,
  DIRECT_PROBE_INTERVAL_MS,
  OUTAGE_WITHOUT_WITNESS_MS,
  OUTAGE_WITH_WITNESS_MS,
  RELAY_ALIVE_HOLD_MS,
  RelayFailoverController,
  RelayFailoverWatch,
  normalizeRelayFailover,
  standbyRelayFor,
}
