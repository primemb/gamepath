/**
 * Settings for the LAN proxy: the SOCKS5/HTTP proxy a running session offers
 * to consoles and other devices on the local network.
 *
 * The password is a secret like any node credential, so it is kept apart from
 * these settings, encrypted, and the renderer only ever learns whether one is set.
 */

const DEFAULT_PORT = 1080
/** The service's own control port; the proxy must never try to take it. */
const RESERVED_PORTS = new Set([47983])
/** RFC 1929 carries each field behind a one-byte length. */
const MAX_CREDENTIAL_BYTES = 255

function defaultLanProxy() {
  return { enabled: false, port: DEFAULT_PORT, username: '' }
}

function normalizeLanProxy(saved) {
  const defaults = defaultLanProxy()
  if (!saved || typeof saved !== 'object') return defaults
  const port = Number(saved.port)
  return {
    enabled: saved.enabled === true,
    port: Number.isInteger(port) && port > 0 && port < 65536 && !RESERVED_PORTS.has(port) ? port : defaults.port,
    username: typeof saved.username === 'string' ? saved.username : '',
  }
}

/**
 * Validates a settings change.
 *
 * `password` is `undefined` to keep the stored one, `null` to clear it, or the
 * new value. Leaving the username empty turns the login off and clears it.
 */
function parseLanProxySettings(input, current, hasStoredPassword) {
  const next = { ...current }
  if (input.enabled !== undefined) next.enabled = Boolean(input.enabled)
  if (input.port !== undefined) {
    const port = Number(input.port)
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Choose a port from 1 to 65535.')
    if (RESERVED_PORTS.has(port)) throw new Error(`Port ${port} is used by the GamePath service. Choose another.`)
    next.port = port
  }
  let password
  if (input.username !== undefined) {
    const username = String(input.username).trim()
    if (Buffer.byteLength(username) > MAX_CREDENTIAL_BYTES) throw new Error('The username is too long.')
    // HTTP proxy logins separate the two fields with a colon.
    if (username.includes(':')) throw new Error('The username cannot contain a colon.')
    next.username = username
  }
  if (!next.username) {
    password = hasStoredPassword ? null : undefined
  } else if (typeof input.password === 'string' && input.password.length) {
    if (Buffer.byteLength(input.password) > MAX_CREDENTIAL_BYTES) throw new Error('The password is too long.')
    password = input.password
  } else if (!hasStoredPassword) {
    throw new Error('Enter a password for the proxy login, or leave the username empty to turn the login off.')
  }
  return { settings: next, password }
}

/** What the service is sent to start the proxy with a session. */
function lanProxySessionPayload(settings, password) {
  const login = Boolean(settings.username && password)
  return {
    enabled: settings.enabled === true,
    port: settings.port,
    username: login ? settings.username : null,
    password: login ? password : null,
  }
}

function publicLanProxy(settings, hasPassword) {
  return { ...settings, hasPassword: Boolean(settings.username && hasPassword) }
}

module.exports = {
  DEFAULT_PORT,
  defaultLanProxy,
  normalizeLanProxy,
  parseLanProxySettings,
  lanProxySessionPayload,
  publicLanProxy,
}
