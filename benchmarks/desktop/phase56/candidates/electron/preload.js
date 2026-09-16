'use strict';
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('atlas', Object.freeze({
  status: () => ipcRenderer.invoke('atlas:status')
}));
