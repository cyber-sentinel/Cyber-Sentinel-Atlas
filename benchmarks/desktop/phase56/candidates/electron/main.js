'use strict';

const { app, BrowserWindow, ipcMain, shell } = require('electron');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { performance } = require('node:perf_hooks');

const MAX_RESPONSE = 8 * 1024 * 1024;
const ENV_ALLOWLIST = ['PATH', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA'];

function sha256File(file) {
  const data = fs.readFileSync(file);
  return crypto.createHash('sha256').update(data).digest('hex');
}

function verifySidecar(core) {
  const manifest = `${core}.sha256`;
  if (!fs.existsSync(core)) throw new Error(`atlas-core sidecar missing: ${core}`);
  if (!fs.existsSync(manifest)) throw new Error(`atlas-core SHA-256 manifest missing: ${manifest}`);
  const expectedHex = fs.readFileSync(manifest, 'utf8').trim().split(/\s+/)[0].toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expectedHex)) throw new Error('invalid atlas-core SHA-256 manifest');
  const actualHex = sha256File(core);
  if (!crypto.timingSafeEqual(Buffer.from(expectedHex, 'hex'), Buffer.from(actualHex, 'hex'))) {
    throw new Error('atlas-core SHA-256 mismatch');
  }
  return actualHex;
}

function frame(value) {
  const body = Buffer.from(JSON.stringify(value), 'utf8');
  const prefix = Buffer.allocUnsafe(4);
  prefix.writeUInt32BE(body.length, 0);
  return Buffer.concat([prefix, body]);
}

function parseFrames(data) {
  const frames = [];
  let offset = 0;
  while (offset < data.length) {
    if (data.length - offset < 4) throw new Error('truncated response frame prefix');
    const length = data.readUInt32BE(offset);
    offset += 4;
    if (length <= 0 || length > MAX_RESPONSE) throw new Error(`invalid response frame length: ${length}`);
    if (data.length - offset < length) throw new Error('truncated response payload');
    frames.push(JSON.parse(data.subarray(offset, offset + length).toString('utf8')));
    offset += length;
  }
  return frames;
}

function minimalEnv() {
  const env = {};
  for (const key of ENV_ALLOWLIST) if (process.env[key]) env[key] = process.env[key];
  return env;
}

async function runCoreProbe() {
  const baseDir = path.dirname(process.execPath);
  const core = path.join(baseDir, 'atlas-core.exe');
  const sidecarSha256 = verifySidecar(core);
  const nonce = 'phase561-electron-nonce';
  const requests = [
    {
      id: 'phase561-handshake', method: 'core.handshake', params: {
        protocol: 'atlas-core', version: '1.0.0', client_name: 'atlas-electron-candidate',
        client_version: '0.1.0-dev', session_nonce: nonce
      }
    },
    { id: 'phase561-status', method: 'core.status', params: {} }
  ];
  const wire = Buffer.concat(requests.map(frame));
  const started = performance.now();

  const result = await new Promise((resolve, reject) => {
    const child = spawn(core, ['--serve-stdio'], {
      cwd: baseDir,
      env: minimalEnv(),
      shell: false,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    const stdout = [];
    const stderr = [];
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error('atlas-core stdio probe timed out'));
    }, 15000);
    child.stdout.on('data', chunk => stdout.push(chunk));
    child.stderr.on('data', chunk => stderr.push(chunk));
    child.on('error', err => { clearTimeout(timer); reject(err); });
    child.on('close', code => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) });
    });
    child.stdin.end(wire);
  });

  const elapsed = Math.round((performance.now() - started) * 1000) / 1000;
  if (result.code !== 0) throw new Error(`atlas-core exited ${result.code}: ${result.stderr.toString('utf8').slice(0, 2000)}`);
  const responses = parseFrames(result.stdout);
  if (responses.length !== 2) throw new Error(`expected 2 responses, got ${responses.length}`);
  const handshake = responses.find(item => item.id === 'phase561-handshake');
  const status = responses.find(item => item.id === 'phase561-status');
  if (!handshake || handshake.ok !== true) throw new Error(`handshake failed: ${JSON.stringify(handshake)}`);
  if (!status || status.ok !== true) throw new Error(`core.status failed: ${JSON.stringify(status)}`);
  if (handshake.result?.protocol !== 'atlas-core' || handshake.result?.version !== '1.0.0') throw new Error('protocol/version mismatch');
  if (handshake.result?.session_nonce !== nonce) throw new Error('session nonce mismatch');

  return {
    candidate: 'electron',
    host_runtime: process.versions.electron,
    protocol: 'atlas-core',
    protocol_version: '1.0.0',
    session_nonce_echoed: true,
    sidecar_sha256: sidecarSha256,
    sidecar_size_bytes: fs.statSync(core).size,
    host_sha256: sha256File(process.execPath),
    host_size_bytes: fs.statSync(process.execPath).size,
    round_trip_ms: elapsed,
    stderr_bytes: result.stderr.length,
    status_result: status.result
  };
}

function argValue(name) {
  const prefix = `${name}=`;
  const exact = process.argv.indexOf(name);
  if (exact >= 0 && exact + 1 < process.argv.length) return process.argv[exact + 1];
  const item = process.argv.find(value => value.startsWith(prefix));
  return item ? item.slice(prefix.length) : null;
}

async function runProbeMode() {
  const output = argValue('--probe-output');
  if (!output) throw new Error('--probe-output is required');
  const evidence = await runCoreProbe();
  fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
  fs.writeFileSync(output, `${JSON.stringify(evidence, null, 2)}\n`, 'utf8');
}

async function createWindow() {
  ipcMain.handle('atlas:status', async () => runCoreProbe());
  const win = new BrowserWindow({
    width: 900,
    height: 620,
    title: 'Cyber-Sentinel ATLAS — Electron Candidate',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false
    }
  });
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith('file://')) event.preventDefault();
  });
  win.webContents.on('will-attach-webview', event => event.preventDefault());
  await win.loadFile('index.html');
}

app.whenReady().then(async () => {
  try {
    if (process.argv.includes('--atlas-probe')) {
      await runProbeMode();
      app.exit(0);
      return;
    }
    await createWindow();
  } catch (error) {
    console.error(error);
    app.exit(1);
  }
});

app.on('window-all-closed', () => app.quit());
