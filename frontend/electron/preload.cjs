const { contextBridge, ipcRenderer } = require('electron');

let syncPort = '8000';
try {
  syncPort = String(ipcRenderer.sendSync('get-backend-port-sync') || '8000');
} catch (e) {}

contextBridge.exposeInMainWorld('electron', {
  getVersion: () => ipcRenderer.invoke('get-app-version'),
  quit: () => ipcRenderer.invoke('quit-app'),
  minimize: () => ipcRenderer.invoke('minimize-window'),
  maximize: () => ipcRenderer.invoke('maximize-window'),
  close: () => ipcRenderer.invoke('close-window'),
  onNavigate: (callback) => ipcRenderer.on('navigate', (_, path) => callback(path)),
  captureScreenshot: (filename) => ipcRenderer.invoke('capture-screenshot', filename),
  isElectron: true,
  port: syncPort,
});

contextBridge.exposeInMainWorld('AI_FIREWALL_PORT', syncPort);
contextBridge.exposeInMainWorld('AI_FIREWALL_API_URL', `http://127.0.0.1:${syncPort}`);

// Backward compatibility bridge
contextBridge.exposeInMainWorld('aiFirewallDesktop', {
  getStartupSettings: () => ipcRenderer.invoke('desktop:get-startup-settings'),
  setStartupEnabled: (enabled) => ipcRenderer.invoke('desktop:set-startup-enabled', enabled),
  getApiUrl: () => `http://127.0.0.1:${syncPort}`,
  getPort: () => syncPort,
  isElectron: true,
});
