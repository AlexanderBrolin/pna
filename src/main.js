// ELECTRON_RUN_AS_NODE must be unset before requiring electron,
// otherwise Electron runs as plain Node.js without its built-in modules.
delete process.env.ELECTRON_RUN_AS_NODE;

const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const path = require("path");
const { spawn } = require("child_process");
const fs = require("fs");

let mainWindow = null;
let pythonProcess = null;

function findPython() {
  const candidates = ["python", "python3", "py"];
  for (const cmd of candidates) {
    try {
      require("child_process").execSync(`${cmd} --version`, {
        timeout: 5000,
        stdio: "pipe",
      });
      return cmd;
    } catch {
      continue;
    }
  }
  return null;
}

function getBackendPath() {
  const devPath = path.join(__dirname, "..", "backend", "server.py");
  if (fs.existsSync(devPath)) return devPath;
  const prodPath = path.join(process.resourcesPath, "backend", "server.py");
  if (fs.existsSync(prodPath)) return prodPath;
  return devPath;
}

function startPythonBackend() {
  return new Promise((resolve, reject) => {
    const pythonCmd = findPython();
    if (!pythonCmd) {
      reject(new Error("Python не найден. Установите Python 3.10+"));
      return;
    }

    const serverPath = getBackendPath();
    const cwd = path.dirname(serverPath);

    pythonProcess = spawn(pythonCmd, [serverPath], {
      cwd,
      stdio: ["pipe", "pipe", "pipe"],
    });

    let resolved = false;
    const timeout = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        resolve();
      }
    }, 10000);

    pythonProcess.stdout.on("data", (data) => {
      const text = data.toString();
      console.log("[Python]", text.trim());
      if (!resolved && text.includes("READY:")) {
        resolved = true;
        clearTimeout(timeout);
        resolve();
      }
    });

    pythonProcess.stderr.on("data", (data) => {
      console.error("[Python ERR]", data.toString().trim());
    });

    pythonProcess.on("error", (err) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timeout);
        reject(err);
      }
    });

    pythonProcess.on("exit", (code) => {
      console.log(`Python process exited with code ${code}`);
      if (!resolved) {
        resolved = true;
        clearTimeout(timeout);
        reject(new Error(`Python exited with code ${code}`));
      }
      pythonProcess = null;
    });
  });
}

function stopPythonBackend() {
  if (pythonProcess) {
    pythonProcess.kill("SIGTERM");
    setTimeout(() => {
      if (pythonProcess) {
        try {
          pythonProcess.kill("SIGKILL");
        } catch {}
      }
    }, 3000);
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 960,
    minHeight: 600,
    title: "Process Network Analyzer",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
    backgroundColor: "#1a1a2e",
    show: false,
  });

  mainWindow.loadFile(path.join(__dirname, "renderer", "index.html"));
  mainWindow.once("ready-to-show", () => mainWindow.show());
  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

ipcMain.handle("save-file", async (event, { defaultName, filters, content }) => {
  const result = await dialog.showSaveDialog(mainWindow, {
    defaultPath: defaultName,
    filters: filters,
  });
  if (!result.canceled && result.filePath) {
    fs.writeFileSync(result.filePath, content, "utf-8");
    return result.filePath;
  }
  return null;
});

app.whenReady().then(async () => {
  createWindow();
  try {
    await startPythonBackend();
    console.log("Python backend started successfully");
  } catch (err) {
    console.error("Failed to start Python backend:", err.message);
    if (mainWindow) {
      mainWindow.webContents.on("did-finish-load", () => {
        mainWindow.webContents.send("backend-error", err.message);
      });
    }
  }
});

app.on("window-all-closed", () => {
  stopPythonBackend();
  app.quit();
});

app.on("before-quit", () => {
  stopPythonBackend();
});
