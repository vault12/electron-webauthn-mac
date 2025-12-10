const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');

const webauthn = require('electron-webauthn-mac');

function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));
}

ipcMain.handle('webauthn:createCredential', async (_event, options) => {
  console.log('webauthn:createCredential invoked with:', options);
  return await webauthn.createCredential(options);
});

ipcMain.handle('webauthn:getCredential', async (_event, options) => {
  console.log('webauthn:getCredential invoked with:', options);
  return await webauthn.getCredential(options);
});

ipcMain.handle('webauthn:managePasswords', async (_event) => {
  console.log('webauthn:managePasswords invoked');
  webauthn.managePasswords();
  return 'Passwords app opened';
});

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  app.quit();
});
