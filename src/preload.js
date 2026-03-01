const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("electronAPI", {
  saveFile: (options) => ipcRenderer.invoke("save-file", options),
  onBackendError: (callback) => ipcRenderer.on("backend-error", (_, msg) => callback(msg)),
});
