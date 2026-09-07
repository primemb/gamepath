const SUPPORTED_SCHEMES = new Set(['socks5:', 'socks5h:', 'socks:'])

function bracketed(host) {
  // The engine resolves a node as `host:port`, so a literal IPv6 address has
  // to keep the brackets that separate it from the port.
  if (host.includes(':') && !host.startsWith('[')) return `[${host}]`
  return host
}

function parseAddress(text) {
  const trimmed = String(text ?? '').trim()
  if (!trimmed) throw new Error('Enter the proxy address')
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `socks5://${trimmed}`
  let url
  try {
    url = new URL(withScheme)
  } catch {
    // The URL parser rejects an out-of-range port outright, so name the real
    // problem instead of blaming the whole address.
    const port = Number(trimmed.match(/:(\d+)$/)?.[1])
    if (Number.isInteger(port) && (port < 1 || port > 65535)) {
      throw new Error('The proxy port must be between 1 and 65535')
    }
    throw new Error('Enter the proxy as host:port, or as socks5://user:password@host:port')
  }
  if (!SUPPORTED_SCHEMES.has(url.protocol)) {
    throw new Error(`GamePath nodes speak SOCKS5; ${url.protocol.replace(':', '')} is not supported`)
  }
  if (!url.hostname) throw new Error('Enter the proxy host')
  return {
    host: url.hostname,
    port: url.port ? Number(url.port) : 1080,
    username: url.username ? decodeURIComponent(url.username) : '',
    password: url.password ? decodeURIComponent(url.password) : '',
  }
}

/**
 * Normalizes what the user typed into a stored SOCKS5 node plus the secret
 * that is kept in Windows secure storage. Explicit fields win over anything
 * carried in the address, so a pasted URI can still be corrected in the form.
 */
function parseSocks5Node(input, id, importedAt = new Date().toISOString()) {
  // An address may be a bare host:port or a full socks5:// URI. Separate
  // fields skip that parsing entirely, so a literal IPv6 host works as typed.
  const explicitHost = String(input.host ?? '').trim()
  const fromAddress = input.address ? parseAddress(input.address) : null
  if (!fromAddress && !explicitHost) throw new Error('Enter the proxy address')
  const host = bracketed(explicitHost || fromAddress.host)
  const port = Number(input.port ?? fromAddress?.port ?? 1080)
  const username = String(input.username ?? fromAddress?.username ?? '').trim()
  const password = String(input.password ?? fromAddress?.password ?? '')

  if (!host) throw new Error('Enter the proxy host')
  if (/\s/.test(host)) throw new Error('The proxy host cannot contain spaces')
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('The proxy port must be between 1 and 65535')
  }
  if (Boolean(username) !== Boolean(password)) {
    throw new Error('SOCKS5 authentication needs both a username and a password')
  }
  for (const [name, value] of [
    ['username', username],
    ['password', password],
  ]) {
    if (Buffer.byteLength(value, 'utf8') > 255) {
      throw new Error(`The proxy ${name} must be at most 255 bytes`)
    }
  }

  const label = String(input.label ?? '').trim() || `${host}:${port}`
  return {
    node: {
      id,
      kind: 'socks5',
      name: label,
      endpoint: `${host}:${port}`,
      host,
      port,
      // A SOCKS5 hop carries no tunnel address and applies no DNS of its own.
      address: 'SOCKS5 proxy',
      dns: 'System default',
      enabled: true,
      importedAt,
      hasPrivateKey: false,
      hasCredentials: Boolean(username),
    },
    credentials: { username, password },
  }
}

module.exports = { parseSocks5Node, parseAddress }
