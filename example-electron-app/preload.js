const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('exposedAddon', {
  createCredential: async (options) => ipcRenderer.invoke('webauthn:createCredential', options),
  getCredential: async (options) => ipcRenderer.invoke('webauthn:getCredential', options),
  managePasswords: async () => ipcRenderer.invoke('webauthn:managePasswords'),
});
