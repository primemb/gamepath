const fs = require('node:fs/promises')
const crypto = require('node:crypto')
const { encodeInvite, decodeInvite, MAX_INVITE_BYTES } = require('./relay-invite.cjs')

function registerRelaySharing({
  ipcMain,
  dialog,
  clipboard,
  getState,
  publicState,
  saveState,
  encryptConfig,
  vpsSetupInput,
  enrollExistingRelay,
}) {
  const pending = new Map()
  const creating = new Set()
  const remember = (sender, kind, payload) => {
    for (const [id, item] of pending) {
      if (item.expires <= Date.now() || (item.sender === sender && item.kind === kind)) pending.delete(id)
    }
    if (pending.size >= 16) pending.delete(pending.keys().next().value)
    const id = crypto.randomUUID()
    pending.set(id, { sender, kind, payload, expires: Date.now() + 3_600_000 })
    return id
  }
  const recalled = (sender, id, kind) => {
    const item = pending.get(id)
    if (!item || item.sender !== sender || item.kind !== kind || item.expires <= Date.now())
      throw new Error('This invitation has expired in the app. Import it or create it again.')
    return item.payload
  }

  ipcMain.handle('relay:share-create', async (event, id, input) => {
    const { relay, ...ssh } = vpsSetupInput(id, input)
    const recipientName = String(input.recipientName ?? '').trim()
    if (!recipientName || recipientName.length > 80 || /[\x00-\x1f\x7f]/.test(recipientName))
      throw new Error('Enter a friend name of up to 80 characters')
    if (ssh.host !== relay.address) throw new Error('Use the configured relay address to share this VPS')
    if (creating.has(id)) throw new Error('An invitation is already being created for this relay')
    const metadata = {
      version: 1,
      city: relay.city,
      country: relay.country,
      address: relay.address,
      port: relay.port,
      recipientName,
    }
    creating.add(id)
    try {
      const result = await enrollExistingRelay(
        { ...ssh, clientName: `friend-${crypto.randomBytes(16).toString('hex')}`, clientLabel: recipientName },
        (update) => event.sender.send('relay:vps-progress', { relayId: id, ...update }),
      )
      const link = encodeInvite({ ...metadata, port: result.port, enrollmentToken: result.token })
      const current = getState().relays.find((item) => item.id === id)
      if (current?.address === metadata.address) {
        current.sshFingerprint = result.fingerprint
        saveState()
      }
      const shareId = remember(event.sender.id, 'share', link)
      return { state: publicState(), shareId, recipientName }
    } finally {
      creating.delete(id)
    }
  })

  ipcMain.handle('relay:share-copy', async (event, id) => {
    await clipboard.writeText(recalled(event.sender.id, id, 'share'))
  })
  ipcMain.handle('relay:share-save', async (event, id) => {
    const link = recalled(event.sender.id, id, 'share')
    const result = await dialog.showSaveDialog({
      title: 'Save relay invitation',
      defaultPath: 'GamePath-friend.gprelay',
      filters: [{ name: 'GamePath relay invitation', extensions: ['gprelay'] }],
    })
    if (result.canceled || !result.filePath) return { canceled: true }
    await fs.writeFile(result.filePath, `${link}\n`, { mode: 0o600 })
    return { canceled: false }
  })

  ipcMain.handle('relay:invite-preview', async (event, source) => {
    let text
    if (source === 'clipboard') text = await clipboard.readText()
    else if (source === 'file') {
      const result = await dialog.showOpenDialog({
        title: 'Import shared relay',
        properties: ['openFile'],
        filters: [{ name: 'GamePath relay invitation', extensions: ['gprelay'] }],
      })
      if (result.canceled) return { canceled: true }
      const file = await fs.open(result.filePaths[0], 'r')
      try {
        const bytes = Buffer.alloc(MAX_INVITE_BYTES + 1)
        const { bytesRead } = await file.read(bytes, 0, bytes.length, 0)
        text = bytes.subarray(0, bytesRead).toString('utf8')
      } finally {
        await file.close()
      }
    } else throw new Error('Choose a relay invitation file or clipboard link')
    const payload = decodeInvite(text)
    const invitationId = remember(event.sender.id, 'import', payload)
    const { enrollmentToken, ...details } = payload
    return { canceled: false, invitationId, details }
  })

  ipcMain.handle('relay:invite-accept', (event, id) => {
    const payload = recalled(event.sender.id, id, 'import')
    const state = getState()
    const relay = {
      id: crypto.randomUUID(),
      city: payload.city,
      country: payload.country,
      code: 'VP',
      address: payload.address,
      port: payload.port,
      status: 'ready',
      hasEnrollmentToken: true,
    }
    const encrypted = encryptConfig(payload.enrollmentToken)
    state.relays.push(relay)
    state.encryptedRelayTokens[relay.id] = encrypted
    // Importing never changes a running session or the owner's existing relay selection.
    if (!state.activeRelayId) state.activeRelayId = relay.id
    saveState()
    pending.delete(id)
    return publicState()
  })
}

module.exports = { registerRelaySharing }
