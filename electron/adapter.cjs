'use strict'

/**
 * Turns the network adapter form into a stored node. The adapter is kept by
 * name, never by index or address: the app behind it is handed a new address
 * each time it reconnects, and may bring up a different adapter for another
 * protocol, so the engine looks the name up again whenever it opens a socket.
 * A name such as `Windscribe` matches the start of whichever adapter that app
 * has up. Nothing about the node is secret; it still stores an empty secret
 * so every node is decrypted the same way when a session starts.
 */
function parseAdapterNode(input, id, importedAt = new Date().toISOString()) {
  const adapter = String(input.adapter ?? '').trim()
  const label = String(input.label ?? '').trim() || adapter

  if (!adapter) throw new Error('Choose or type the network adapter of the VPN app')
  if (adapter.length > 256) throw new Error('The adapter name is too long')
  if (/^gamepath/i.test(adapter)) throw new Error('That is a GamePath adapter. Choose the other VPN app’s adapter.')
  if (label.length > 128) throw new Error('The node name is too long')

  return {
    node: {
      id,
      kind: 'adapter',
      name: label,
      endpoint: adapter,
      adapter,
      address: 'Network adapter',
      dns: 'System default',
      enabled: true,
      importedAt,
      hasPrivateKey: false,
      hasCredentials: false,
    },
    secret: '{}',
  }
}

module.exports = { parseAdapterNode }
