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
  configureRelay: (id, input) => ipcRenderer.invoke('relay:configure', id, input),
  importRelayEnrollment: (id) => ipcRenderer.invoke('relay:import-enrollment', id),
  testRelay: (id) => ipcRenderer.invoke('relay:test', id),
  refreshService: () => ipcRenderer.invoke('service:refresh'),
  installService: () => ipcRenderer.invoke('service:install'),
  startSession: () => ipcRenderer.invoke('engine:start'),
  stopSession: () => ipcRenderer.invoke('engine:stop'),
})
