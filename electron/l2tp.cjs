const { isIP } = require('node:net')

/**
 * Turns the L2TP form into public node metadata plus the secret material that
 * is kept behind Electron's Windows secure-storage boundary.
 */
function parseL2tpNode(input, id, importedAt = new Date().toISOString()) {
  const server = String(input.server ?? '').trim()
  const username = String(input.username ?? '').trim()
  const password = String(input.password ?? '')
  const preSharedKey = String(input.preSharedKey ?? '')
  const label = String(input.label ?? '').trim() || server

  if (!server) throw new Error('Enter the L2TP server hostname or IPv4 address')
  const ipVersion = isIP(server)
  if (ipVersion === 6) throw new Error('L2TP currently needs an IPv4 server or a hostname that resolves to IPv4')
  const validHostname =
    server.length <= 255 &&
    server
      .split('.')
      .every(
        (part) =>
          part.length > 0 &&
          part.length <= 63 &&
          !part.startsWith('-') &&
          !part.endsWith('-') &&
          /^[a-z0-9-]+$/i.test(part),
      )
  if (!ipVersion && !validHostname) {
    throw new Error('Enter only the L2TP server hostname or IP address, without a URL or port')
  }
  if (!username) throw new Error('Enter the L2TP username')
  if (!password) throw new Error('Enter the L2TP password')
  if (!preSharedKey) throw new Error('Enter the L2TP/IPsec pre-shared key')
  if (server.length > 255) throw new Error('The L2TP server name is too long')
  if (username.length > 256) throw new Error('The L2TP username is too long')
  if (password.length > 256) throw new Error('The L2TP password is too long')
  if (preSharedKey.length > 1024) throw new Error('The L2TP/IPsec pre-shared key is too long')
  if (label.length > 128) throw new Error('The L2TP node name is too long')

  return {
    node: {
      id,
      kind: 'l2tp',
      name: label,
      endpoint: server,
      host: server,
      address: 'Assigned when connected',
      dns: 'Provider assigned',
      enabled: true,
      importedAt,
      hasPrivateKey: true,
      hasCredentials: true,
    },
    credentials: { server, username, password, preSharedKey },
  }
}

module.exports = { parseL2tpNode }
