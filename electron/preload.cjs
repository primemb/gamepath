const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('gamepath', {
  bootstrap: () => ipcRenderer.invoke('app:bootstrap'),
  importWireGuard: () => ipcRenderer.invoke('tunnel:import'),
  setTunnelEnabled: (id, enabled) => ipcRenderer.invoke('tunnel:set-enabled', id, enabled),
  removeTunnel: (id) => ipcRenderer.invoke('tunnel:remove', id),
  browseRuleTarget: (kind) => ipcRenderer.invoke('rule:browse', kind),
  addRule: (input) => ipcRenderer.invoke('rule:add', input),
  setRuleEnabled: (id, enabled) => ipcRenderer.invoke('rule:set-enabled', id, enabled),
  removeRule: (id) => ipcRenderer.invoke('rule:remove', id),
  setTrafficMode: (mode) => ipcRenderer.invoke('traffic:set-mode', mode),
  setRelay: (id) => ipcRenderer.invoke('relay:set', id),
  addRelay: (input) => ipcRenderer.invoke('relay:add', input),
  removeRelayLocal: (id) => ipcRenderer.invoke('relay:remove-local', id),
  configureRelay: (id, input) => ipcRenderer.invoke('relay:configure', id, input),
  importRelayEnrollment: (id) => ipcRenderer.invoke('relay:import-enrollment', id),
  testRelay: (id) => ipcRenderer.invoke('relay:test', id),
  provisionRelayVps: (id, input) => ipcRenderer.invoke('relay:vps-provision', id, input),
  removeRelayVps: (id, input) => ipcRenderer.invoke('relay:vps-remove', id, input),
  onRelayVpsProgress: (callback) => {
    const handler = (_event, update) => callback(update)
    ipcRenderer.on('relay:vps-progress', handler)
    return () => ipcRenderer.removeListener('relay:vps-progress', handler)
  },
  refreshService: () => ipcRenderer.invoke('service:refresh'),
  installService: () => ipcRenderer.invoke('service:install'),
  startSession: () => ipcRenderer.invoke('engine:start'),
  stopSession: () => ipcRenderer.invoke('engine:stop'),
  refreshSession: () => ipcRenderer.invoke('engine:session-status'),
})
