#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CANDIDATES = ROOT / "benchmarks" / "desktop" / "phase56" / "candidates"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def read(path: Path) -> str:
    require(path.is_file(), f"required security-surface file is missing: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def require_csp(csp: str, context: str) -> None:
    normalized = " ".join(csp.split())
    for directive in (
        "default-src 'self'",
        "script-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "connect-src 'none'",
    ):
        require(directive in normalized, f"{context} CSP is missing: {directive}")


def validate_electron() -> dict[str, object]:
    base = CANDIDATES / "electron"
    main = read(base / "main.js")
    preload = read(base / "preload.js")
    renderer = read(base / "renderer.js")
    html = read(base / "index.html")

    require("const { app, BrowserWindow, ipcMain, session } = require('electron');" in main,
            "Electron must import only the constrained session/browser/IPC surface")
    require("shell } = require('electron')" not in main and " shell," not in main,
            "Electron shell API must not be imported")
    for required in (
        "contextIsolation: true",
        "nodeIntegration: false",
        "sandbox: true",
        "webSecurity: true",
        "allowRunningInsecureContent: false",
        "webviewTag: false",
        "devTools: false",
        "setWindowOpenHandler(() => ({ action: 'deny' }))",
        "setPermissionCheckHandler(() => false)",
        "setPermissionRequestHandler((_webContents, _permission, callback) => callback(false))",
        "session.defaultSession.on('will-download', event => event.preventDefault())",
        "win.webContents.on('will-navigate', event => event.preventDefault())",
        "win.webContents.on('will-redirect', event => event.preventDefault())",
        "win.webContents.on('will-attach-webview', event => event.preventDefault())",
        "spawn(core, ['--serve-stdio']",
        "shell: false",
    ):
        require(required in main, f"Electron hardening invariant missing: {required}")

    require(main.count("ipcMain.handle(") == 1 and "ipcMain.handle('atlas:status'" in main,
            "Electron main IPC must expose exactly the fixed atlas:status handler")
    for forbidden in (
        "ipcMain.on(", "ipcMain.handleOnce(", "require('node:http')", "require('node:https')",
        "require('node:net')", "require('node:dgram')", "require('electron').net", "eval(", "new Function(",
    ):
        require(forbidden not in main, f"Electron forbidden surface present: {forbidden}")

    require("contextBridge.exposeInMainWorld('atlas'" in preload,
            "Electron preload must expose only the named atlas bridge")
    require("status: () => ipcRenderer.invoke('atlas:status')" in preload,
            "Electron preload must expose only atlas status invocation")
    for forbidden in ("ipcRenderer.send(", "ipcRenderer.sendSync(", "ipcRenderer.on(", "ipcRenderer.postMessage(", "eval("):
        require(forbidden not in preload, f"Electron preload forbidden surface present: {forbidden}")
    for forbidden in ("fetch(", "XMLHttpRequest", "WebSocket", "eval(", "new Function("):
        require(forbidden not in renderer, f"Electron renderer forbidden surface present: {forbidden}")

    match = re.search(r'http-equiv="Content-Security-Policy"\s+content="([^"]+)"', html, re.IGNORECASE)
    require(match is not None, "Electron renderer CSP meta tag is required")
    require_csp(match.group(1), "Electron")

    package = json.loads(read(base / "package.json"))
    deps = package.get("devDependencies", {}) | package.get("dependencies", {})
    require(set(deps) == {"electron"}, f"Electron candidate has unexpected dependencies: {sorted(deps)}")

    return {
        "state": "PASS",
        "isolation": "contextIsolation+sandbox+nodeIntegration=false",
        "navigation": "window/navigation/redirect/webview denied",
        "permissions": "browser permission requests/checks and downloads denied",
        "ipc": "single frozen atlas:status preload bridge",
        "network_api": "no renderer/main generic network API",
        "csp_connect_src": "none",
    }


def validate_tauri() -> dict[str, object]:
    base = CANDIDATES / "tauri"
    config = json.loads(read(base / "tauri.conf.json"))
    cargo = tomllib.loads(read(base / "Cargo.toml"))
    build = read(base / "build.rs")
    main = read(base / "src" / "main.rs")
    frontend = read(base / "www" / "main.js")

    app = config.get("app", {})
    require(app.get("withGlobalTauri") is True,
            "Tauri static candidate requires the global JS API, which must remain capability-restricted")
    windows = app.get("windows")
    require(isinstance(windows, list) and len(windows) == 1 and windows[0].get("label") == "main",
            "Tauri must expose exactly the explicitly labeled main window")

    security = app.get("security", {})
    require_csp(security.get("csp", ""), "Tauri")
    require(security.get("freezePrototype") is True, "Tauri must freeze Object.prototype for the custom protocol")
    require(security.get("dangerousDisableAssetCspModification") is False,
            "Tauri CSP asset hardening must not be disabled")
    asset_protocol = security.get("assetProtocol")
    require(isinstance(asset_protocol, dict) and asset_protocol.get("enable") is False and asset_protocol.get("scope") == [],
            "Tauri asset protocol must remain disabled")

    capabilities = security.get("capabilities")
    require(isinstance(capabilities, list) and len(capabilities) == 1,
            "Tauri must declare exactly one explicit security capability")
    capability = capabilities[0]
    require(isinstance(capability, dict), "Tauri capability must be inline and inspectable")
    require(capability.get("identifier") == "main-core-status-only", "unexpected Tauri capability identifier")
    require(capability.get("windows") == ["main"], "Tauri capability must bind only to the main window")
    require(capability.get("permissions") == ["allow-core-status"],
            "Tauri capability must grant only allow-core-status")
    require("remote" not in capability, "Tauri remote origins must not receive capabilities")

    require('AppManifest::new().commands(&["core_status"])' in build,
            "Tauri build manifest must register core_status for generated app-command ACL permissions")
    require(".app_manifest(app_manifest)" in build,
            "Tauri build attributes must apply the application ACL manifest")

    dependencies = cargo.get("dependencies", {})
    require(set(dependencies) == {"tauri", "serde_json", "sha2"},
            f"Tauri candidate has unexpected runtime dependencies: {sorted(dependencies)}")
    require(not any(name.startswith("tauri-plugin-") for name in dependencies),
            "Tauri plugins are not allowed in the G-D7 baseline")

    require(main.count("#[tauri::command]") == 1 and "fn core_status()" in main,
            "Tauri must expose exactly one application command")
    require("generate_handler![core_status]" in main, "Tauri invoke handler must expose only core_status")
    require(main.count("Command::new(&core)") == 1, "Tauri may spawn only the verified atlas-core path")
    for forbidden in (
        "std::net", "TcpListener", "TcpStream", "UdpSocket", "reqwest", "hyper::", "tauri_plugin_",
        "powershell", "cmd.exe", "Command::new(\"",
    ):
        require(forbidden not in main, f"Tauri forbidden surface present: {forbidden}")
    require("window.__TAURI__.core.invoke('core_status')" in frontend,
            "Tauri frontend must invoke only the fixed core_status command")
    for forbidden in ("fetch(", "XMLHttpRequest", "WebSocket", ".shell", ".fs", "eval(", "new Function("):
        require(forbidden not in frontend, f"Tauri frontend forbidden surface present: {forbidden}")

    return {
        "state": "PASS",
        "capability": "main window only / allow-core-status only",
        "app_command_acl": "AppManifest-generated allow-core-status only",
        "plugins": "none",
        "command_surface": "core_status only",
        "network_api": "no frontend/Rust generic network API",
        "csp_connect_src": "none",
    }


def validate_dotnet() -> dict[str, object]:
    base = CANDIDATES / "dotnet"
    project = read(base / "Atlas.DotNetCandidate.csproj")
    program = read(base / "Program.cs")

    require("<UseWPF>true</UseWPF>" in project, ".NET candidate must remain native WPF")
    require("<PackageReference" not in project, ".NET G-D7 baseline must not add external runtime packages")
    require('new ProcessStartInfo(core, "--serve-stdio")' in program,
            ".NET must spawn only the resolved atlas-core sidecar in stdio mode")
    require("UseShellExecute = false" in program, ".NET sidecar launch must bypass the shell")
    require("startInfo.Environment.Clear();" in program, ".NET sidecar environment must be allowlisted")
    require("CryptographicOperations.FixedTimeEquals" in program, ".NET sidecar integrity comparison must remain fixed-time")
    for forbidden in (
        "WebView", "HttpClient", "WebClient", "System.Net.Sockets", "TcpClient", "TcpListener", "UdpClient",
        "Socket(", "UseShellExecute = true", "powershell", "cmd.exe", "Process.Start(\"",
    ):
        require(forbidden not in program and forbidden not in project,
                f".NET forbidden desktop surface present: {forbidden}")

    return {
        "state": "PASS",
        "ui": "native WPF / no browser bridge",
        "process": "fixed verified atlas-core stdio launch / shell disabled",
        "network_api": "no application network API",
        "dependencies": "no external runtime packages",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    candidates = {
        "electron": validate_electron(),
        "tauri-v2": validate_tauri(),
        "dotnet-wpf": validate_dotnet(),
    }
    report = {
        "evidence_version": 1,
        "phase": "5.6.2",
        "gate": "G-D7-desktop-security-surface",
        "state": "PASS",
        "candidates": candidates,
        "selection_authorized": False,
        "note": "Static security-surface policy evidence complements the executable G-D3 process-tree network probe; it does not select a framework.",
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
