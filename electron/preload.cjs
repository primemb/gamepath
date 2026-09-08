const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('gamepath', {
  bootstrap: () => ipcRenderer.invoke('app:bootstrap'),
  lookupIpCountry: (target) => ipcRenderer.invoke('ip-country:lookup', target),
  importWireGuard: () => ipcRenderer.invoke('tunnel:import'),
  chooseOpenVpnFiles: () => ipcRenderer.invoke('openvpn:choose'),
  addOpenVpnNodes: (input) => ipcRenderer.invoke('openvpn:add', input),
  addSocks5Node: (input) => ipcRenderer.invoke('node:add-socks5', input),
  testSocks5Node: (input) => ipcRenderer.invoke('node:test-socks5', input),
  testSavedSocks5Node: (id) => ipcRenderer.invoke('node:test-saved-socks5', id),
  setTunnelEnabled: (id, enabled) => ipcRenderer.invoke('tunnel:set-enabled', id, enabled),
  removeTunnel: (id) => ipcRenderer.invoke('tunnel:remove', id),
  browseRuleTarget: (kind) => ipcRenderer.invoke('rule:browse', kind),
  addRule: (input) => ipcRenderer.invoke('rule:add', input),
  setRuleEnabled: (id, enabled) => ipcRenderer.invoke('rule:set-enabled', id, enabled),
  setRuleGroup: (id, groupId) => ipcRenderer.invoke('rule:set-group', id, groupId),
  removeRule: (id) => ipcRenderer.invoke('rule:remove', id),
  addRuleGroup: (name) => ipcRenderer.invoke('rule-group:add', name),
  renameRuleGroup: (id, name) => ipcRenderer.invoke('rule-group:rename', id, name),
  setRuleGroupEnabled: (id, enabled) => ipcRenderer.invoke('rule-group:set-enabled', id, enabled),
  removeRuleGroup: (id) => ipcRenderer.invoke('rule-group:remove', id),
  setTrafficMode: (mode) => ipcRenderer.invoke('traffic:set-mode', mode),
  setConnectionMode: (mode) => ipcRenderer.invoke('connection:set-mode', mode),
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
