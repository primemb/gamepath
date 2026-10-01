'use strict'

/**
 * Turns a saved node and its decrypted secret into the tagged node the engine
 * and service expect. Secrets live in Windows secure storage until a session
 * starts and never reach the renderer: a WireGuard node yields its
 * configuration body, a SOCKS5 node its stored credentials, an OpenVPN node
 * its file and credentials, and an L2TP node its login and pre-shared key.
 */
function nodeSpec(node, secret) {
  if (node.kind === 'socks5') {
    const { username, password } = JSON.parse(secret)
    return {
      kind: 'socks5',
      host: node.host,
      port: node.port,
      username: username || null,
      password: password || null,
      label: node.name,
    }
  }
  if (node.kind === 'openvpn') {
    const { config, username, password } = JSON.parse(secret)
    return { kind: 'openvpn', config, username: username || null, password: password || null, label: node.name }
  }
  if (node.kind === 'l2tp') {
    const { server, username, password, preSharedKey } = JSON.parse(secret)
    return { kind: 'l2tp', server, username, password, preSharedKey, label: node.name }
  }
  return { kind: 'wireguard', config: secret, label: node.name }
}

module.exports = { nodeSpec }
