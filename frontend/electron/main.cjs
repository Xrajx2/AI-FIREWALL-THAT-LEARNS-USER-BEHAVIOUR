const { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage } = require('electron');
const { spawn, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const http = require('http');
const url = require('url');

// Enforce single instance lock
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  console.log('[App] Another instance of AI Firewall is already running. Quitting.');
  app.quit();
  process.exit(0);
}

let mainWindow;
let tray;
let backendProcess;
let backendReady = false;
let isQuitting = false;

const isDev = !app.isPackaged;
let activePort = process.env.AI_FIREWALL_PORT || '8000';

function getRuntimePort() {
  try {
    const appdata = process.env.APPDATA || (process.env.USERPROFILE ? path.join(process.env.USERPROFILE, 'AppData', 'Roaming') : '');
    if (appdata) {
      const portFile = path.join(appdata, 'AIFirewall', 'runtime_port.json');
      if (fs.existsSync(portFile)) {
        const raw = JSON.parse(fs.readFileSync(portFile, 'utf8'));
        if (raw && raw.port) {
          activePort = String(raw.port);
          return activePort;
        }
      }
    }
  } catch (e) {}
  return activePort;
}

function resolvePythonCommand() {
  if (process.env.PYTHON && fs.existsSync(process.env.PYTHON)) {
    return process.env.PYTHON;
  }
  const localAppData = process.env.LOCALAPPDATA || '';
  const python314 = path.join(localAppData, 'Python', 'pythoncore-3.14-64', 'python.exe');
  if (fs.existsSync(python314)) {
    return python314;
  }
  return 'python';
}

function resolveBackendExe() {
  const possiblePaths = [
    path.join(process.resourcesPath, 'backend', 'aifirewall-backend', 'aifirewall-backend.exe'),
    path.join(process.resourcesPath, 'backend', 'aifirewall-backend.exe'),
    path.join(process.resourcesPath, 'aifirewall-backend', 'aifirewall-backend.exe'),
    path.join(__dirname, '..', 'build-resources', 'backend', 'aifirewall-backend', 'aifirewall-backend.exe'),
    path.join(__dirname, '..', 'build-resources', 'backend', 'aifirewall-backend.exe'),
  ];
  for (const p of possiblePaths) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

function getIconPath() {
  const possiblePaths = [
    path.join(__dirname, '..', 'assets', 'icon.png'),
    path.join(__dirname, '..', '..', 'assets', 'icon.png'),
    path.join(__dirname, '..', 'public', 'favicon.svg'),
    path.join(process.resourcesPath, 'assets', 'icon.png'),
  ];
  for (const p of possiblePaths) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

// Kill backend process and all child processes cleanly without leaving orphans
function killBackendProcess() {
  if (backendProcess && backendProcess.pid) {
    const pid = backendProcess.pid;
    console.log(`[App] Terminating backend process tree (PID: ${pid})...`);
    if (process.platform === 'win32') {
      try {
        execSync(`taskkill /F /T /PID ${pid}`, { stdio: 'ignore' });
      } catch (e) {
        try {
          backendProcess.kill('SIGKILL');
        } catch (err) {}
      }
    } else {
      try {
        backendProcess.kill('SIGTERM');
      } catch (e) {}
    }
    backendProcess = null;
    console.log('[App] Backend process terminated cleanly');
  }
}

// Start backend process
function startBackend() {
  return new Promise((resolve, reject) => {
    const pythonExe = resolvePythonCommand();
    const backendExe = resolveBackendExe();
    const rootBackendPy = path.resolve(__dirname, '..', '..', 'backend', 'main.py');

    let cmd;
    let args = [];
    let cwd;

    const useBuiltBackend = !isDev || process.env.TEST_PACKAGED_BACKEND === '1';

    if (useBuiltBackend && backendExe) {
      cmd = backendExe;
      args = [];
      cwd = path.dirname(backendExe);
    } else {
      if (!isDev) {
        console.warn('[App] Packaged backend exe not found, falling back to python script');
      }
      cmd = pythonExe;
      args = [rootBackendPy];
      cwd = isDev ? path.resolve(__dirname, '..', '..') : process.resourcesPath;
    }

    console.log(`[App] Spawning backend: ${cmd} ${args.join(' ')} (cwd: ${cwd})`);

    try {
      backendProcess = spawn(cmd, args, {
        cwd: cwd,
        windowsHide: true,
        env: {
          ...process.env,
          AI_FIREWALL_DESKTOP: '1',
          AI_FIREWALL_PORT: activePort,
          AI_FIREWALL_PARENT_PID: process.pid.toString(),
          PYTHONPATH: isDev ? path.resolve(__dirname, '..', '..') : process.resourcesPath,
        },
      });

      backendProcess.stdout.on('data', (data) => {
        const text = data.toString();
        console.log('[Backend]', text.trim());
        const portMatch = text.match(/Starting on http:\/\/[^:]+:(\d+)/);
        if (portMatch) {
          activePort = portMatch[1];
          console.log(`[App] Backend dynamically bound to port: ${activePort}`);
        }
        if (
          text.includes('Application startup complete') ||
          text.includes('Uvicorn running') ||
          text.includes('[AI Firewall Backend] Starting')
        ) {
          backendReady = true;
          resolve();
        }
      });

      backendProcess.stderr.on('data', (data) => {
        const text = data.toString();
        console.error('[Backend Error]', text.trim());
        if (
          text.includes('Application startup complete') ||
          text.includes('Uvicorn running')
        ) {
          backendReady = true;
          resolve();
        }
      });

      backendProcess.on('error', (err) => {
        console.error('[Backend Spawn Error]', err);
        reject(err);
      });

      backendProcess.on('exit', (code, signal) => {
        console.log(`[Backend] Process exited with code ${code} signal ${signal}`);
        backendReady = false;
      });

      // Timeout fallback after 30 seconds
      setTimeout(() => {
        if (!backendReady) {
          console.log('[App] Backend startup timeout check, verifying via HTTP...');
        }
      }, 30000);
    } catch (err) {
      reject(err);
    }
  });
}

// Poll until backend is ready
function waitForBackend(retries = 35) {
  return new Promise((resolve, reject) => {
    const check = (n) => {
      const port = getRuntimePort();
      const req = http.get(`http://127.0.0.1:${port}/api/health`, (res) => {
        if (res.statusCode === 200) {
          backendReady = true;
          resolve();
        } else if (n > 0) {
          setTimeout(() => check(n - 1), 1000);
        } else {
          reject(new Error('Backend not ready'));
        }
      });

      req.on('error', () => {
        if (n > 0) {
          setTimeout(() => check(n - 1), 1000);
        } else {
          reject(new Error('Backend not reachable'));
        }
      });

      req.setTimeout(2000, () => {
        req.destroy();
        if (n > 0) {
          setTimeout(() => check(n - 1), 1000);
        } else {
          reject(new Error('Backend health check timed out'));
        }
      });
    };
    check(retries);
  });
}

function createWindow() {
  const iconPath = getIconPath();
  const windowOpts = {
    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    frame: false,
    titleBarStyle: 'hidden',
    backgroundColor: '#0a0a0f',
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  };

  if (iconPath) {
    windowOpts.icon = iconPath;
  }

  mainWindow = new BrowserWindow(windowOpts);

  // Splash loading screen data URL
  const splashHtml = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="UTF-8" />
        <title>AI Firewall</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body {
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            background: #0a0a0f;
            color: #00d4ff;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
            flex-direction: column;
            gap: 16px;
            user-select: none;
            -webkit-app-region: drag;
          }
          .icon { font-size: 52px; animation: pulse 2s infinite ease-in-out; }
          .title { font-size: 22px; font-weight: 700; letter-spacing: 1px; color: #ffffff; }
          .subtitle { font-size: 13px; color: #8892b0; font-family: monospace; }
          .spinner {
            width: 32px;
            height: 32px;
            border: 3px solid rgba(0, 212, 255, 0.2);
            border-top: 3px solid #00d4ff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-top: 8px;
          }
          @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
          @keyframes pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.08); } }
        </style>
      </head>
      <body>
        <div class="icon">🛡️</div>
        <div class="title">AI Firewall</div>
        <div class="subtitle">Starting protection engine...</div>
        <div class="spinner"></div>
      </body>
    </html>
  `;

  mainWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(splashHtml)}`);

  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      if (process.env.AI_FIREWALL_MINIMIZE_TO_TRAY === '1') {
        e.preventDefault();
        mainWindow.hide();
      } else {
        isQuitting = true;
        killBackendProcess();
      }
    }
  });
}

function createTray() {
  const iconPath = getIconPath();
  let icon;
  if (iconPath) {
    icon = nativeImage.createFromPath(iconPath);
  } else {
    icon = nativeImage.createEmpty();
  }

  tray = new Tray(icon.isEmpty() ? nativeImage.createEmpty() : icon.resize({ width: 16, height: 16 }));

  const isStartWithWindows = () => {
    try {
      return Boolean(app.getLoginItemSettings().openAtLogin);
    } catch (e) {
      return false;
    }
  };

  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Open AI Firewall',
      click: () => {
        mainWindow.show();
        mainWindow.focus();
      },
    },
    {
      label: 'Dashboard',
      click: () => {
        mainWindow.show();
        mainWindow.focus();
        mainWindow.webContents.send('navigate', '/dashboard');
      },
    },
    { type: 'separator' },
    {
      label: 'Start with Windows',
      type: 'checkbox',
      checked: isStartWithWindows(),
      click: (item) => {
        try {
          app.setLoginItemSettings({
            openAtLogin: item.checked,
            openAsHidden: true,
            name: 'AI Firewall',
            args: ['--hidden'],
          });
        } catch (e) {
          console.warn('[App] Failed to update login item settings:', e);
        }
      },
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => {
        isQuitting = true;
        killBackendProcess();
        app.quit();
      },
    },
  ]);

  tray.setToolTip('AI Firewall — Protection Active');
  tray.setContextMenu(contextMenu);
  tray.on('double-click', () => {
    mainWindow.show();
    mainWindow.focus();
  });
}

// Single instance event - restore and focus main window when second instance attempted
app.on('second-instance', () => {
  if (mainWindow) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    if (!mainWindow.isVisible()) mainWindow.show();
    mainWindow.focus();
  }
});

app.whenReady().then(async () => {
  // Option A Admin: App runs elevated via requireAdministrator manifest.
  // Start with Windows is OFF by default; we do not force openAtLogin = true.

  createWindow();
  createTray();

  if (process.argv.includes('--hidden')) {
    mainWindow.hide();
  } else {
    mainWindow.show();
    mainWindow.focus();
  }

  try {
    startBackend().catch((e) => console.log('[App] Async startBackend notification:', e.message));
    await waitForBackend();
    console.log('[App] Backend ready');

    mainWindow.webContents.on('dom-ready', () => {
      const p = getRuntimePort();
      mainWindow.webContents.executeJavaScript(`
        window.AI_FIREWALL_PORT = "${p}";
        window.AI_FIREWALL_API_URL = "http://127.0.0.1:${p}";
        try { sessionStorage.setItem("ai_firewall_port", "${p}"); } catch(e){}
      `).catch(() => {});
    });

    mainWindow.webContents.on('console-message', (event, level, message, line, sourceId) => {
      console.log(`[Renderer Console L${level}] ${message} (${sourceId}:${line})`);
    });

    const isLocalDist = !isDev || process.env.ELECTRON_FORCE_LOCAL_DIST === '1';
    if (isLocalDist) {
      const distIndex = path.join(__dirname, '..', 'dist', 'index.html');
      console.log(`[App] Loading local dist index: ${distIndex}`);
      try {
        await mainWindow.loadFile(distIndex);
      } catch (err) {
        const fileUrl = url.pathToFileURL(distIndex).href;
        console.log(`[App] loadFile fallback to URL: ${fileUrl}`);
        await mainWindow.loadURL(fileUrl);
      }
    } else {
      console.log('[App] Loading dev server URL');
      await mainWindow.loadURL(process.env.ELECTRON_RENDERER_URL || 'http://localhost:5173');
    }

    mainWindow.show();
    mainWindow.focus();

    if (process.env.AI_FIREWALL_TEST_LOGIN === '1') {
      try {
        await mainWindow.webContents.executeJavaScript(`
          (async () => {
            try {
              const port = window.AI_FIREWALL_PORT || '8000';
              const res = await fetch('http://127.0.0.1:' + port + '/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ username: 'installedadmin', password: 'Password12345!' })
              });
              const data = await res.json();
              if (data.access_token) {
                localStorage.setItem('token', data.access_token);
                localStorage.setItem('user', JSON.stringify(data.user));
                window.location.hash = '#/dashboard';
              }
            } catch (err) {
              console.error('Test login injection failed:', err);
            }
          })();
        `);
      } catch (err) {
        console.error('[App] Test login injection script error:', err);
      }
    }

    if (process.env.AI_FIREWALL_SCREENSHOT_PATH) {
      const shotPath = process.env.AI_FIREWALL_SCREENSHOT_PATH;
      const delayMs = process.env.AI_FIREWALL_TEST_LOGIN === '1' ? 4500 : 3500;
      setTimeout(async () => {
        try {
          if (mainWindow) {
            mainWindow.show();
            const img = await mainWindow.webContents.capturePage();
            fs.mkdirSync(path.dirname(shotPath), { recursive: true });
            fs.writeFileSync(shotPath, img.toPNG());
            console.log(`[App] Captured UI screenshot to: ${shotPath}`);
            if (process.env.AI_FIREWALL_AUTO_EXIT === '1') {
              setTimeout(() => {
                isQuitting = true;
                killBackendProcess();
                app.quit();
              }, 1000);
            }
          }
        } catch (e) {
          console.error('[App] Failed capturing screenshot:', e);
        }
      }, delayMs);
    }
  } catch (err) {
    console.error('[App] Backend failed to start:', err);
    mainWindow.webContents.executeJavaScript(`
      document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;background:#0a0a0f;color:#ef4444;font-family:monospace;flex-direction:column;gap:14px;padding:24px;text-align:center"><div style="font-size:52px">⚠️</div><div style="font-size:18px;font-weight:bold;color:#f87171">Failed to start protection engine</div><div style="font-size:13px;color:#9ca3af;max-width:400px">Please right-click AI Firewall and select <b>"Run as administrator"</b> to grant network protection permissions.</div></div>';
    `);
  }
});

// App termination hooks: guarantee backend cleanup
app.on('before-quit', () => {
  isQuitting = true;
  killBackendProcess();
});

app.on('will-quit', () => {
  killBackendProcess();
});

process.on('exit', () => {
  killBackendProcess();
});

process.on('uncaughtException', (err) => {
  console.error('[App] Uncaught exception:', err);
  killBackendProcess();
  process.exit(1);
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    isQuitting = true;
    killBackendProcess();
    app.quit();
  }
});

// IPC handlers for window controls & info
ipcMain.on('get-backend-port-sync', (event) => {
  event.returnValue = getRuntimePort();
});
ipcMain.handle('desktop:api-url', () => `http://127.0.0.1:${getRuntimePort()}`);
ipcMain.handle('get-backend-port', () => getRuntimePort());
ipcMain.handle('get-app-version', () => app.getVersion());
ipcMain.handle('quit-app', () => {
  isQuitting = true;
  killBackendProcess();
  app.quit();
});
ipcMain.handle('minimize-window', () => {
  if (mainWindow) mainWindow.minimize();
});
ipcMain.handle('maximize-window', () => {
  if (mainWindow) {
    if (mainWindow.isMaximized()) {
      mainWindow.unmaximize();
    } else {
      mainWindow.maximize();
    }
  }
});
ipcMain.handle('close-window', () => {
  if (process.env.AI_FIREWALL_MINIMIZE_TO_TRAY === '1') {
    if (mainWindow) mainWindow.hide();
  } else {
    isQuitting = true;
    killBackendProcess();
    app.quit();
  }
});
ipcMain.handle('capture-screenshot', async (_, filename) => {
  if (!mainWindow) return null;
  const img = await mainWindow.webContents.capturePage();
  const target = path.isAbsolute(filename) ? filename : path.resolve(__dirname, '..', '..', filename);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, img.toPNG());
  console.log(`[App] Screenshot saved to ${target}`);
  return target;
});

// Windows Login startup IPC handlers
ipcMain.handle('desktop:get-startup-settings', () => {
  try {
    const settings = app.getLoginItemSettings();
    return {
      openAtLogin: Boolean(settings.openAtLogin),
      openAsHidden: Boolean(settings.openAsHidden),
    };
  } catch (e) {
    return { openAtLogin: false, openAsHidden: false };
  }
});

ipcMain.handle('desktop:set-startup-enabled', (_, enabled) => {
  try {
    app.setLoginItemSettings({
      openAtLogin: Boolean(enabled),
      openAsHidden: true,
      name: 'AI Firewall',
      args: ['--hidden'],
    });
    return true;
  } catch (e) {
    console.error('[App] Failed to set login item settings:', e);
    return false;
  }
});
