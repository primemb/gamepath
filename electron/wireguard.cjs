const path = require('node:path')

function valueFromSection(source, section, key) {
  const sectionMatch = source.match(new RegExp(`\\[${section}\\]([\\s\\S]*?)(?=\\n\\s*\\[|$)`, 'i'))
  if (!sectionMatch) return ''
  const keyMatch = sectionMatch[1].match(new RegExp(`^\\s*${key}\\s*=\\s*(.+?)\\s*$`, 'im'))
  return keyMatch?.[1]?.trim() ?? ''
}

function parseWireGuardConfig(source, filePath, id, importedAt = new Date().toISOString()) {
  const privateKey = valueFromSection(source, 'Interface', 'PrivateKey')
  const endpoint = valueFromSection(source, 'Peer', 'Endpoint')
  const publicKey = valueFromSection(source, 'Peer', 'PublicKey')
  if (!privateKey || !endpoint || !publicKey) {
    throw new Error('Missing Interface PrivateKey, Peer PublicKey, or Peer Endpoint')
  }

  return {
    id,
    kind: 'wireguard',
    name: path.basename(filePath, path.extname(filePath)),
    endpoint,
    address: valueFromSection(source, 'Interface', 'Address') || 'Automatic',
    dns: valueFromSection(source, 'Interface', 'DNS') || 'System default',
    enabled: true,
    importedAt,
    hasPrivateKey: true,
  }
}

module.exports = { parseWireGuardConfig, valueFromSection }
