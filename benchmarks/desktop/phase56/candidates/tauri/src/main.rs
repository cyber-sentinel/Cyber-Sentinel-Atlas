use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_RESPONSE: usize = 8 * 1024 * 1024;
const ENV_ALLOWLIST: &[&str] = &[
    "PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
    "USERPROFILE", "LOCALAPPDATA", "APPDATA",
];

fn sha256_file(path: &Path) -> Result<([u8; 32], String), String> {
    let mut file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|e| format!("read {}: {e}", path.display()))?;
        if read == 0 { break; }
        hasher.update(&buffer[..read]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let hex = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();
    Ok((digest, hex))
}

fn decode_hex_32(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid atlas-core SHA-256 manifest".into());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|_| "invalid atlas-core SHA-256 manifest")?;
    }
    Ok(out)
}

fn fixed_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 { diff |= a[i] ^ b[i]; }
    diff == 0
}

fn locate_and_verify_sidecar() -> Result<(PathBuf, String), String> {
    let host = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let base = host.parent().ok_or("host executable has no parent")?;
    let core = base.join("atlas-core.exe");
    let manifest = base.join("atlas-core.exe.sha256");
    if !core.is_file() { return Err(format!("atlas-core sidecar missing: {}", core.display())); }
    if !manifest.is_file() { return Err(format!("atlas-core SHA-256 manifest missing: {}", manifest.display())); }
    let manifest_text = fs::read_to_string(&manifest).map_err(|e| format!("read manifest: {e}"))?;
    let expected_text = manifest_text.split_whitespace().next().ok_or("empty atlas-core SHA-256 manifest")?.to_ascii_lowercase();
    let expected = decode_hex_32(&expected_text)?;
    let (actual, actual_hex) = sha256_file(&core)?;
    if !fixed_time_eq(&expected, &actual) { return Err("atlas-core SHA-256 mismatch".into()); }
    Ok((core, actual_hex))
}

fn frame(value: &Value) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(value).map_err(|e| format!("serialize request: {e}"))?;
    let length = u32::try_from(body.len()).map_err(|_| "request too large")?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

fn parse_frames(data: &[u8]) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        if data.len() - offset < 4 { return Err("truncated response frame prefix".into()); }
        let length = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if length == 0 || length > MAX_RESPONSE { return Err(format!("invalid response frame length: {length}")); }
        if data.len() - offset < length { return Err("truncated response payload".into()); }
        let value: Value = serde_json::from_slice(&data[offset..offset + length]).map_err(|e| format!("parse response JSON: {e}"))?;
        out.push(value);
        offset += length;
    }
    Ok(out)
}

fn run_core_probe() -> Result<Value, String> {
    let (core, sidecar_sha256) = locate_and_verify_sidecar()?;
    let base = core.parent().ok_or("sidecar has no parent")?;
    let nonce = "phase561-tauri-nonce";
    let requests = [
        json!({"id":"phase561-handshake","method":"core.handshake","params":{"protocol":"atlas-core","version":"1.0.0","client_name":"atlas-tauri-candidate","client_version":"0.1.0-dev","session_nonce":nonce}}),
        json!({"id":"phase561-status","method":"core.status","params":{}}),
    ];
    let mut wire = Vec::new();
    for request in &requests { wire.extend_from_slice(&frame(request)?); }

    let mut command = Command::new(&core);
    command.arg("--serve-stdio")
        .current_dir(base)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for key in ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(key) { command.env(key, value); }
    }

    let started = Instant::now();
    let mut child = command.spawn().map_err(|e| format!("spawn atlas-core: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&wire).map_err(|e| format!("write atlas-core stdin: {e}"))?;
        stdin.flush().map_err(|e| format!("flush atlas-core stdin: {e}"))?;
    }

    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| format!("wait atlas-core: {e}"))? { break status; }
        if started.elapsed() > Duration::from_secs(15) {
            let _ = child.kill();
            return Err("atlas-core stdio probe timed out".into());
        }
        thread::sleep(Duration::from_millis(20));
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut stream) = child.stdout.take() { stream.read_to_end(&mut stdout).map_err(|e| format!("read stdout: {e}"))?; }
    if let Some(mut stream) = child.stderr.take() { stream.read_to_end(&mut stderr).map_err(|e| format!("read stderr: {e}"))?; }
    if !status.success() {
        return Err(format!("atlas-core exited {:?}: {}", status.code(), String::from_utf8_lossy(&stderr).chars().take(2000).collect::<String>()));
    }

    let responses = parse_frames(&stdout)?;
    if responses.len() != 2 { return Err(format!("expected 2 responses, got {}", responses.len())); }
    let handshake = responses.iter().find(|v| v.get("id").and_then(Value::as_str) == Some("phase561-handshake")).ok_or("missing handshake response")?;
    let core_status = responses.iter().find(|v| v.get("id").and_then(Value::as_str) == Some("phase561-status")).ok_or("missing status response")?;
    if handshake.get("ok").and_then(Value::as_bool) != Some(true) { return Err(format!("handshake failed: {handshake}")); }
    if core_status.get("ok").and_then(Value::as_bool) != Some(true) { return Err(format!("core.status failed: {core_status}")); }
    let result = handshake.get("result").ok_or("handshake result missing")?;
    if result.get("protocol").and_then(Value::as_str) != Some("atlas-core") { return Err("protocol mismatch".into()); }
    if result.get("version").and_then(Value::as_str) != Some("1.0.0") { return Err("protocol version mismatch".into()); }
    if result.get("session_nonce").and_then(Value::as_str) != Some(nonce) { return Err("session nonce mismatch".into()); }

    let host = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let (_, host_sha256) = sha256_file(&host)?;
    Ok(json!({
        "candidate": "tauri-v2",
        "host_runtime": "tauri-2.11.5",
        "protocol": "atlas-core",
        "protocol_version": "1.0.0",
        "session_nonce_echoed": true,
        "sidecar_sha256": sidecar_sha256,
        "sidecar_size_bytes": fs::metadata(&core).map_err(|e| format!("sidecar metadata: {e}"))?.len(),
        "host_sha256": host_sha256,
        "host_size_bytes": fs::metadata(&host).map_err(|e| format!("host metadata: {e}"))?.len(),
        "round_trip_ms": (started.elapsed().as_secs_f64() * 1000.0 * 1000.0).round() / 1000.0,
        "stderr_bytes": stderr.len(),
        "status_result": core_status.get("result").cloned().unwrap_or(Value::Null)
    }))
}

#[tauri::command]
fn core_status() -> Result<Value, String> { run_core_probe() }

fn arg_value(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    for (i, value) in args.iter().enumerate() {
        if value == name && i + 1 < args.len() { return Some(args[i + 1].clone()); }
        if let Some(rest) = value.strip_prefix(&(name.to_string() + "=")) { return Some(rest.to_string()); }
    }
    None
}

fn main() {
    if std::env::args().any(|arg| arg == "--atlas-probe") {
        let result = (|| -> Result<(), String> {
            let output = arg_value("--probe-output").ok_or("--probe-output is required")?;
            let evidence = run_core_probe()?;
            let path = PathBuf::from(output);
            if let Some(parent) = path.parent() { fs::create_dir_all(parent).map_err(|e| format!("create evidence directory: {e}"))?; }
            fs::write(&path, format!("{}\n", serde_json::to_string_pretty(&evidence).map_err(|e| format!("serialize evidence: {e}"))?))
                .map_err(|e| format!("write evidence: {e}"))?;
            Ok(())
        })();
        if let Err(error) = result { eprintln!("{error}"); std::process::exit(1); }
        return;
    }

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![core_status])
        .run(tauri::generate_context!())
        .expect("failed to run ATLAS Tauri candidate");
}
