const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("electronAPI", {
  saveFile: (options) => ipcRenderer.invoke("save-file", options),
  saveSettings: (data) => ipcRenderer.invoke("save-settings", data),
  loadSettings: () => ipcRenderer.invoke("load-settings"),
  onBackendError: (callback) => ipcRenderer.on("backend-error", (_, msg) => callback(msg)),
});
