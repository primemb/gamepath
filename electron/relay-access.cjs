const crypto = require('node:crypto')

function registerRelayAccess({
  ipcMain,
  vpsSetupInput,
  connectRelayAccess,
  currentClientId,
  getState,
  saveState,
  publicState,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
}) {
  const sessions = new Map()
  const close = (id) => {
    const session = sessions.get(id)
    if (!session) return
    sessions.delete(id)
    clearTimer(session.timer)
    session.sender.removeListener('destroyed', session.onDestroyed)
    session.remote.close()
  }
  const recall = (sender, id) => {
    const session = sessions.get(id)
    if (!session || session.sender.id !== sender.id) throw new Error('Sign in to the VPS again to manage access')
    return session
  }
  const decorate = (clients, ownId) =>
    clients.map((client) => ({
      clientId: client.clientId,
      name: client.name,
      virtualIpv4: client.virtualIpv4,
      isCurrentClient: client.clientId === ownId,
    }))
  const run = async (sender, id, work) => {
    const session = recall(sender, id)
    if (session.busy) throw new Error('Another access request is still running')
    session.busy = true
    try {
      return decorate(await work(session), session.ownId)
    } finally {
      session.busy = false
    }
  }

  ipcMain.handle('relay:access-open', async (event, id, input) => {
    const { relay, ...ssh } = vpsSetupInput(id, input)
    if (ssh.host !== relay.address) throw new Error('Use the configured relay address to manage access')
    const remote = await connectRelayAccess(ssh)
    let accessId
    try {
      const clients = await remote.list()
      if (event.sender.isDestroyed()) throw new Error('The access dialog was closed')
      for (const [oldId, session] of sessions) if (session.sender.id === event.sender.id) close(oldId)
      accessId = crypto.randomUUID()
      const ownId = currentClientId(id)
      const onDestroyed = () => close(accessId)
      const timer = setTimer(() => close(accessId), 15 * 60_000)
      timer.unref()
      sessions.set(accessId, { sender: event.sender, remote, ownId, timer, onDestroyed, busy: false })
      event.sender.once('destroyed', onDestroyed)
      const current = getState().relays.find((item) => item.id === id)
      if (current?.address === ssh.host) {
        current.sshFingerprint = remote.fingerprint
        saveState()
      }
      return { accessId, clients: decorate(clients, ownId), state: publicState() }
    } catch (error) {
      if (accessId) close(accessId)
      else remote.close()
      throw error
    }
  })
  ipcMain.handle('relay:access-list', (event, id) => run(event.sender, id, (session) => session.remote.list()))
  ipcMain.handle('relay:access-revoke', (event, id, clientId) =>
    run(event.sender, id, async (session) => {
      if (typeof clientId !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(clientId))
        throw new Error('Invalid relay client ID')
      if (clientId === session.ownId) throw new Error('You cannot revoke this PC from this dialog')
      return session.remote.revoke(clientId)
    }),
  )
  ipcMain.handle('relay:access-close', (event, id) => {
    if (!sessions.has(id)) return
    recall(event.sender, id)
    close(id)
  })
}

module.exports = { registerRelayAccess }
