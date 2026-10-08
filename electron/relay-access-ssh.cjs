const net = require('node:net')
const { connectSsh, execute, rootCommand, quote } = require('./vps.cjs')

function accessCommandScript(clientId) {
  if (clientId !== undefined && !/^[A-Za-z0-9_-]{22}$/.test(clientId)) throw new Error('Invalid relay client ID')
  return `set -euo pipefail
pid=$(systemctl show --property MainPID --value gamepath-relay.service)
if [[ ! "$pid" =~ ^[1-9][0-9]*$ ]] || ! "/proc/$pid/exe" capabilities 2>/dev/null | grep -Fx 'client-access-management-v1' >/dev/null; then
  echo "Update this VPS relay once to enable access management. Use Update VPS between games." >&2
  exit 4
fi
. /etc/gamepath/relay.env
exec 9>/var/lock/gamepath-enrollment.lock
flock -x 9
"/proc/$pid/exe" ${clientId === undefined ? 'clients' : `revoke --client-id ${quote(clientId)}`} --clients-dir "\${GAMEPATH_CLIENTS:-/etc/gamepath/clients}"`
}

function parseClientAccess(output) {
  try {
    const clients = JSON.parse(output)
    if (!Array.isArray(clients) || clients.length > 253) throw new Error('Invalid list')
    const ids = new Set()
    return clients.map((client) => {
      if (
        !client ||
        typeof client.clientId !== 'string' ||
        !/^[A-Za-z0-9_-]{22}$/.test(client.clientId) ||
        ids.has(client.clientId) ||
        typeof client.name !== 'string' ||
        client.name.length > 1024 ||
        /[\x00-\x1f\x7f]/.test(client.name) ||
        net.isIP(client.virtualIpv4) !== 4
      )
        throw new Error('Invalid client')
      ids.add(client.clientId)
      return { clientId: client.clientId, name: client.name, virtualIpv4: client.virtualIpv4 }
    })
  } catch {
    throw new Error('The VPS returned an invalid client access list')
  }
}

async function connectRelayAccess(input) {
  const { connection, fingerprint } = await connectSsh(input)
  try {
    const isRoot = (await execute(connection, 'id -u')).trim() === '0'
    const command = async (id) =>
      parseClientAccess(await rootCommand(connection, accessCommandScript(id), input.password, isRoot))
    return { fingerprint, list: () => command(), revoke: (id) => command(id), close: () => connection.end() }
  } catch (error) {
    connection.end()
    throw error
  }
}

module.exports = { connectRelayAccess, accessCommandScript, parseClientAccess }
