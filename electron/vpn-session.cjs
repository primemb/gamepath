'use strict'

const crypto = require('node:crypto')
const { pauseMessage, pauseReasonFromError } = require('./session-coordinator.cjs')

/**
 * How often the VPN's lease is renewed. Same headroom as the game's: the
 * service tears a slot down if it hears nothing for 30 s, and three failed
 * polls in a row are still well inside that.
 */
const VPN_POLL_MS = 3000
const VPN_POLL_MAX_FAILURES = 3

/**
 * Waits between reconnect attempts. Short at first, because most drops are a
 * Wi-Fi hiccup or a node restarting and come straight back; capped, so a node
 * that is gone for good is retried without hammering it.
 */
const RECONNECT_DELAYS_MS = [1000, 2000, 5000, 10000, 30000]

/**
 * A tunnel that keeps reporting itself degraded for this long is restarted.
 * WireGuard and OpenVPN recover a lost handshake by themselves well inside
 * this, so a restart only happens when the node is really gone.
 */
const DEGRADED_RESTART_MS = 30000

const START_TIMEOUT_MS = 30000
/** IKE plus waiting for the RAS adapter to appear takes far longer. */
const L2TP_START_TIMEOUT_MS = 60000

const LIVE = new Set(['connected', 'degraded'])
const ACTIVE = new Set(['connecting', 'reconnecting', 'connected', 'degraded'])

const defaultTimers = { setInterval, clearInterval, setTimeout, clearTimeout }

/** A configuration problem that retrying cannot fix. */
class VpnConfigError extends Error {}

/**
 * Runs the VPN session in the service's `vpn` slot.
 *
 * Its lifecycle is independent of the game session: nothing here ever stops,
 * restarts or waits for the game. The one direction it does look is
 * `pauseReason`, which says when the game needs the VPN out of the way.
 */
class VpnSessionController {
  constructor({
    service,
    logger,
    buildRequest,
    pauseReason = () => null,
    usage = null,
    onChange = () => {},
    timers = defaultTimers,
    now = () => Date.now(),
    randomId = () => crypto.randomBytes(3).toString('hex'),
  }) {
    this.service = service
    this.logger = logger
    this.log = logger.scope('vpn')
    this.buildRequest = buildRequest
    this.pauseReason = pauseReason
    this.usage = usage
    this.onChange = onChange
    this.timers = timers
    this.now = now
    this.randomId = randomId
    this.wanted = false
    this.session = { status: 'idle' }
    this.queue = Promise.resolve()
    this.pollTimer = null
    this.reconnectTimer = null
    this.reconnectAttempt = 0
    this.pollFailures = 0
    this.pollInFlight = false
    this.degradedSince = null
  }

  snapshot() {
    return structuredClone(this.session)
  }

  /** The user asked for the VPN on. It stays wanted until they turn it off. */
  connect() {
    this.wanted = true
    this.reconnectAttempt = 0
    return this.exclusive(() => this.startNow())
  }

  disconnect() {
    this.wanted = false
    this.cancelReconnect()
    return this.exclusive(() => this.stopNow({ status: 'idle' }, 'turned off'))
  }

  /** Settings that a running session cannot take live: reconnect with them. */
  restart(why) {
    if (!this.wanted) return this.queue
    return this.exclusive(async () => {
      if (ACTIVE.has(this.session.status)) await this.stopNow({ status: 'idle' }, why)
      await this.startNow()
    })
  }

  /** The game session changed: step aside for it, or come back after it. */
  reconsider() {
    return this.exclusive(async () => {
      const reason = this.pauseReason()
      if (reason && ACTIVE.has(this.session.status)) {
        this.cancelReconnect()
        await this.stopNow(this.pausedState(reason), `paused: ${reason}`)
      } else if (!reason && this.wanted && this.session.status === 'paused') {
        this.log.info('the game no longer needs all traffic; resuming')
        await this.startNow()
      }
    })
  }

  /** The PC woke up. A session from before sleep is retried at once. */
  onResume() {
    if (!this.wanted) return this.queue
    if (LIVE.has(this.session.status)) return this.poll()
    this.reconnectAttempt = 0
    this.cancelReconnect()
    return this.exclusive(() => this.startNow())
  }

  /**
   * Applies new split rules to a running session without reconnecting.
   * Throws if the service rejects them, so the caller can keep the old ones.
   */
  async applyRules(rules, trafficMode) {
    if (!LIVE.has(this.session.status) || trafficMode !== 'split') return null
    const session = this.session
    const capture = await this.service.request('update-session-rules', { slot: 'vpn', rules })
    if (this.isCurrent(session)) session.capture = capture
    this.log.info(`live targets updated: count=${capture?.targetCount ?? rules.length}`)
    this.onChange()
    return capture
  }

  /** Quitting: stop now, but remember the user wanted it, for next launch. */
  shutdown() {
    this.cancelReconnect()
    return this.exclusive(() => this.stopNow({ status: 'idle' }, 'the app is quitting'))
  }

  exclusive(work) {
    const run = this.queue.then(work, work)
    this.queue = run.catch(() => {})
    return run
  }

  pausedState(reason) {
    return { status: 'paused', pauseReason: reason, message: pauseMessage(reason) }
  }

  async startNow() {
    this.cancelReconnect()
    if (!this.wanted) return
    const reason = this.pauseReason()
    if (reason) {
      this.session = this.pausedState(reason)
      this.log.info(`waiting: ${reason}`)
      this.onChange()
      return
    }
    let built
    try {
      if (!this.service.ready()) throw new Error('Install and start the GamePath Network Service in Settings.')
      built = this.buildRequest()
    } catch (error) {
      this.fail(error, !(error instanceof VpnConfigError))
      return
    }
    const sessionId = `vpn-${this.randomId()}`
    const log = this.logger.scope(`vpn ${sessionId}`)
    const { request, node } = built
    const retrying = this.reconnectAttempt > 0
    this.session = {
      status: retrying ? 'reconnecting' : 'connecting',
      sessionId,
      node: { id: node.id, name: node.name, kind: node.kind },
      message: `${retrying ? 'Reconnecting' : 'Connecting'} to ${node.name}…`,
    }
    this.onChange()
    log.info(
      `starting: node=${node.kind} traffic=${request.trafficMode} rules=${request.rules.length} ` +
        `dns=${request.remoteDns ? 'remote' : 'local'} killSwitch=${request.killSwitch ? 'on' : 'off'}` +
        (retrying ? ` attempt=${this.reconnectAttempt + 1}` : ''),
    )
    const startedAt = this.now()
    try {
      await this.service.request('validate-runtime', { ...request, slot: 'vpn' })
    } catch (error) {
      // A refusal stays refused; a request that never got an answer is retried.
      log.error(`${error.transient ? 'could not check' : 'refused'} before connecting: ${error.message}`)
      this.fail(error, error.transient === true)
      return
    }
    try {
      const timeout = node.kind === 'l2tp' ? L2TP_START_TIMEOUT_MS : START_TIMEOUT_MS
      const started = await this.service.request('start-session', { ...request, slot: 'vpn', sessionId }, timeout)
      this.session = {
        status: 'connected',
        sessionId,
        node: this.session.node,
        startedAt: this.now(),
        trafficMode: request.trafficMode,
        killSwitch: request.killSwitch,
        message: `Connected through ${node.name}.`,
      }
      this.applyRuntime({ ...started.paths, capture: started.capture })
      this.reconnectAttempt = 0
      this.degradedSince = null
      this.usage?.start(sessionId, [{ id: node.id, name: node.name }])
      this.recordUsage({ ...started.paths, capture: started.capture })
      this.startPolling()
      log.info(
        `connected in ${this.now() - startedAt} ms: mtu=${started.capture?.effectiveMtu ?? 'unknown'} ` +
          `capture=${started.capture?.backend ?? 'unknown'}`,
      )
      if (request.remoteDns && request.trafficMode === 'split' && !started.capture?.dnsServers?.length) {
        log.warn('remote DNS unavailable: lookups use the normal network and can return filtered addresses')
      }
    } catch (error) {
      try {
        await this.service.request('stop-session', { slot: 'vpn' })
      } catch {}
      const pause = pauseReasonFromError(error.message)
      if (pause) {
        this.session = this.pausedState(pause)
        log.info(`waiting: ${pause}`)
      } else {
        log.error(`did not connect after ${this.now() - startedAt} ms: ${error.message}`)
        this.fail(error, true)
        return
      }
    }
    this.onChange()
  }

  /** Records a failure. A retryable one is retried while the VPN is wanted. */
  fail(error, retryable) {
    if (!retryable) this.wanted = false
    this.session = { status: 'error', message: error.message, node: this.session.node }
    this.onChange()
    if (retryable) this.scheduleReconnect()
  }

  async stopNow(next, why) {
    this.stopPolling()
    const wasActive = ACTIVE.has(this.session.status)
    if (wasActive) {
      try {
        await this.service.request('stop-session', { slot: 'vpn' })
      } catch (error) {
        this.log.warn(`stop request failed (${error.message}); the service lease will end it`)
      }
      this.log.info(`stopped: ${why}`)
    }
    this.session = next
    this.onChange()
  }

  scheduleReconnect() {
    if (!this.wanted || this.reconnectTimer) return
    const delay = RECONNECT_DELAYS_MS[Math.min(this.reconnectAttempt, RECONNECT_DELAYS_MS.length - 1)]
    this.reconnectAttempt += 1
    this.session = {
      ...this.session,
      status: 'reconnecting',
      retryAt: this.now() + delay,
      message: `${this.session.message ?? 'The VPN dropped.'} Retrying in ${Math.round(delay / 1000)} s.`,
    }
    this.log.warn(`reconnecting in ${delay} ms (attempt ${this.reconnectAttempt})`)
    this.onChange()
    this.reconnectTimer = this.timers.setTimeout(() => {
      this.reconnectTimer = null
      void this.exclusive(() => this.startNow())
    }, delay)
    this.reconnectTimer.unref?.()
  }

  cancelReconnect() {
    if (this.reconnectTimer) this.timers.clearTimeout(this.reconnectTimer)
    this.reconnectTimer = null
  }

  /**
   * Renews the lease from the main process. Like the game's keep-alive, this
   * must never depend on a renderer timer, which Chromium throttles while a
   * fullscreen game covers the window.
   */
  startPolling() {
    this.stopPolling()
    this.pollFailures = 0
    this.pollTimer = this.timers.setInterval(() => void this.poll(), VPN_POLL_MS)
    this.pollTimer.unref?.()
  }

  stopPolling() {
    if (this.pollTimer) this.timers.clearInterval(this.pollTimer)
    this.pollTimer = null
  }

  /** Whether `session` is still the running one, after an await. */
  isCurrent(session) {
    return this.session === session && LIVE.has(session.status)
  }

  async poll() {
    if (!LIVE.has(this.session.status) || this.pollInFlight) return
    this.pollInFlight = true
    const polled = this.session
    try {
      const runtime = await this.service.request('session-status', { slot: 'vpn' })
      // Stopped or replaced while the request was out: the answer is about a
      // session that is gone, and applying it would bring it back to life.
      if (!this.isCurrent(polled)) return
      this.pollFailures = 0
      this.applyRuntime(runtime)
      this.recordUsage(runtime)
      this.trackHealth(runtime.state === 'connected')
    } catch (error) {
      if (this.isCurrent(polled)) this.pollFailed(error)
    } finally {
      this.pollInFlight = false
      this.onChange()
    }
  }

  trackHealth(healthy) {
    if (healthy) {
      if (this.session.status === 'degraded') this.log.info('recovered')
      this.session.status = 'connected'
      this.session.message = `Connected through ${this.session.node?.name ?? 'the VPN node'}.`
      this.degradedSince = null
      return
    }
    if (this.session.status !== 'degraded') this.log.warn('the node stopped answering')
    this.session.status = 'degraded'
    this.session.message = this.session.killSwitch
      ? 'The node has stopped answering. Selected apps are blocked until it is back.'
      : 'The node has stopped answering. Selected apps use your normal connection until it is back.'
    this.degradedSince ??= this.now()
    if (this.now() - this.degradedSince >= DEGRADED_RESTART_MS) {
      this.log.warn(`degraded for ${Math.round((this.now() - this.degradedSince) / 1000)} s; reconnecting`)
      this.degradedSince = null
      void this.exclusive(async () => {
        await this.stopNow({ ...this.session, status: 'error' }, 'node unreachable')
        this.scheduleReconnect()
      })
    }
  }

  pollFailed(error) {
    const pause = pauseReasonFromError(error.message)
    if (pause) {
      // The service stopped the slot itself because the game took over.
      this.stopPolling()
      this.session = this.pausedState(pause)
      this.log.info(`paused by the service: ${pause}`)
      return
    }
    this.pollFailures += 1
    if (this.pollFailures < VPN_POLL_MAX_FAILURES) {
      this.log.warn(`status failed (${this.pollFailures}/${VPN_POLL_MAX_FAILURES}): ${error.message}`)
      return
    }
    this.log.error(`lost after ${this.pollFailures} failed status requests: ${error.message}`)
    void this.exclusive(async () => {
      await this.stopNow({ status: 'error', message: error.message, node: this.session.node }, 'lost')
      this.scheduleReconnect()
    })
  }

  applyRuntime(runtime) {
    const paths = runtime.paths ?? []
    const path = paths[0]
    this.session.pathMetrics = paths
    if (runtime.capture) this.session.capture = runtime.capture
    this.session.metrics = {
      latencyMs: path?.latencyMs ?? null,
      lossPercent: path?.lossPercent ?? null,
      bytesSent: runtime.userBytesSent ?? path?.bytesSent ?? 0,
      bytesReceived: runtime.userBytesReceived ?? path?.bytesReceived ?? 0,
      // When these counters were read, so the window can turn them into rates.
      sampledAt: this.now(),
    }
  }

  recordUsage(runtime) {
    try {
      this.usage?.record(runtime)
    } catch (error) {
      this.log.warn(`usage accounting failed: ${error.message}`)
    }
  }
}

module.exports = {
  VpnSessionController,
  VpnConfigError,
  VPN_POLL_MS,
  VPN_POLL_MAX_FAILURES,
  RECONNECT_DELAYS_MS,
  DEGRADED_RESTART_MS,
}
