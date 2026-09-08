const path = require('node:path')

/**
 * Reads the parts of an `.ovpn` file the node list has to show.
 *
 * The engine parses the file properly and is the authority on whether it can be
 * used. What happens here is narrower: pull out the name, the server and
 * whether a password is wanted, and refuse the handful of things that are
 * cheaper to explain at import time than at connect time.
 */
function parseOpenVpnConfig(source, filePath, id, importedAt = new Date().toISOString()) {
  const directives = readDirectives(source)
  const refusal = unsupported(directives, source)
  if (refusal) throw new Error(refusal)

  const remote = directives.find((line) => line.name === 'remote')
  if (!remote) throw new Error('No `remote` line, so there is no server to connect to')
  const [host, port = '1194', remoteProtocol] = remote.arguments
  if (!host) throw new Error('The `remote` line has no host')

  const override = directives.find((line) => line.name === 'proto')?.arguments[0]
  const protocol = normaliseProtocol(remoteProtocol ?? override ?? 'udp')
  const portOverride = directives.find((line) => line.name === 'port')?.arguments[0]

  if (!/<ca>/i.test(source)) {
    throw new Error('No `<ca>` block, so the server’s certificate cannot be checked')
  }
  const wantsCredentials = directives.some((line) => line.name === 'auth-user-pass')
  const hasClientCertificate = /<cert>/i.test(source) && /<key>/i.test(source)
  if (!wantsCredentials && !hasClientCertificate) {
    throw new Error('Neither `auth-user-pass` nor a client certificate, so there is no way to authenticate')
  }

  return {
    id,
    kind: 'openvpn',
    name: path.basename(filePath, path.extname(filePath)),
    endpoint: `${host}:${portOverride ?? port}`,
    protocol,
    // Both are decided by the server during the handshake, so there is nothing
    // truthful to show until a session runs.
    address: 'Assigned by the server',
    dns: 'Pushed by the server',
    enabled: true,
    importedAt,
    hasPrivateKey: true,
    wantsCredentials,
  }
}

function readDirectives(source) {
  const directives = []
  let insideBlock = false
  for (const raw of source.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || line.startsWith('#') || line.startsWith(';')) continue
    if (/^<\/?[a-z0-9-]+>$/i.test(line)) {
      insideBlock = !line.startsWith('</')
      continue
    }
    // A line inside `<ca>` or `<key>` is certificate body, not a directive.
    if (insideBlock) continue
    const [name, ...args] = line.split(/\s+/)
    directives.push({ name: name.toLowerCase(), arguments: args })
  }
  return directives
}

/**
 * Names the configurations GamePath cannot carry, in the same terms the engine
 * uses, so a file is refused once with a reason rather than twice.
 */
function unsupported(directives, source) {
  const named = (name) => directives.find((line) => line.name === name)

  const device = named('dev')
  if (device && !(device.arguments[0] ?? '').startsWith('tun')) {
    return `This configuration uses \`dev ${device.arguments[0]}\`. GamePath carries IP packets, so it needs a \`tun\` configuration; ask the provider for one.`
  }
  for (const name of ['ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2', 'pkcs12']) {
    const directive = named(name)
    if (directive && directive.arguments.length) {
      return `This configuration keeps its \`${name}\` in a separate file. GamePath needs one self-contained file, with the certificates and keys inline between \`<${name}>\` and \`</${name}>\` tags.`
    }
  }
  if (/<tls-crypt-v2>/i.test(source)) {
    return 'This configuration uses `tls-crypt-v2`, which GamePath does not implement yet. A `tls-crypt` or plain configuration from the same provider will work.'
  }
  if (named('secret')) {
    return 'This configuration uses OpenVPN’s static-key mode, which has no TLS handshake and is removed in current OpenVPN releases. Ask the provider for a normal TLS configuration.'
  }
  for (const name of ['comp-lzo', 'compress']) {
    const directive = named(name)
    const mode = directive?.arguments[0]
    if (directive && mode && !['no', 'stub', 'stub-v2'].includes(mode)) {
      return `This configuration turns on \`${name} ${mode}\`. GamePath does not compress tunnelled traffic, because compression leaks information about it and adds latency. Ask the provider for a configuration without compression.`
    }
  }
  if (named('fragment')) {
    return 'This configuration uses `--fragment`, OpenVPN’s own packet splitting, which GamePath does not implement. Ask the provider for a configuration without it.'
  }
  for (const name of ['http-proxy', 'socks-proxy']) {
    if (named(name)) {
      return `This configuration reaches its server through \`${name}\`. Add that proxy as its own GamePath node instead of naming it inside the OpenVPN file.`
    }
  }
  if (named('static-challenge')) {
    return 'This configuration asks for a one-time code at connect time, which GamePath cannot prompt for.'
  }
  const authUserPass = named('auth-user-pass')
  if (authUserPass?.arguments.length) {
    return `This configuration reads its username and password from \`${authUserPass.arguments[0]}\`. Remove that filename and enter the credentials in GamePath instead.`
  }
  return null
}

function normaliseProtocol(value) {
  return String(value).toLowerCase().startsWith('tcp') ? 'tcp' : 'udp'
}

module.exports = { parseOpenVpnConfig, normaliseProtocol }
