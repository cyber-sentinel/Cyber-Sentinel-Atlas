use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_RESPONSE: usize = 8 * 1024 * 1024;
const MAX_UI_QUERY_SCALARS: usize = 512;
const MAX_UI_IDENTIFIER_SCALARS: usize = 1024;
const MAX_UI_RESULT_LIMIT: i64 = 100;
const MAX_UI_GRAPH_DEPTH: i64 = 32;
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "SystemRoot",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
];

#[derive(Debug)]
struct CoreSessionEvidence {
    result: Value,
    sidecar_sha256: String,
    sidecar_size_bytes: u64,
    elapsed_ms: f64,
    stderr_bytes: usize,
}

fn sha256_file(path: &Path) -> Result<([u8; 32], String), String> {
    let mut file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let hex = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
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
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn locate_and_verify_sidecar() -> Result<(PathBuf, String), String> {
    let host = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let base = host.parent().ok_or("host executable has no parent")?;
    let core = base.join("atlas-core.exe");
    let manifest = base.join("atlas-core.exe.sha256");
    if !core.is_file() {
        return Err(format!("atlas-core sidecar missing: {}", core.display()));
    }
    if !manifest.is_file() {
        return Err(format!(
            "atlas-core SHA-256 manifest missing: {}",
            manifest.display()
        ));
    }
    let manifest_text =
        fs::read_to_string(&manifest).map_err(|e| format!("read manifest: {e}"))?;
    let expected_text = manifest_text
        .split_whitespace()
        .next()
        .ok_or("empty atlas-core SHA-256 manifest")?
        .to_ascii_lowercase();
    let expected = decode_hex_32(&expected_text)?;
    let (actual, actual_hex) = sha256_file(&core)?;
    if !fixed_time_eq(&expected, &actual) {
        return Err("atlas-core SHA-256 mismatch".into());
    }
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
        if data.len() - offset < 4 {
            return Err("truncated response frame prefix".into());
        }
        let length = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if length == 0 || length > MAX_RESPONSE {
            return Err(format!("invalid response frame length: {length}"));
        }
        if data.len() - offset < length {
            return Err("truncated response payload".into());
        }
        let value: Value = serde_json::from_slice(&data[offset..offset + length])
            .map_err(|e| format!("parse response JSON: {e}"))?;
        out.push(value);
        offset += length;
    }
    Ok(out)
}

fn session_nonce() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("atlas-preview-{}-{nanos}", std::process::id())
}

fn run_core_session(method: &'static str, params: Value) -> Result<CoreSessionEvidence, String> {
    let (core, sidecar_sha256) = locate_and_verify_sidecar()?;
    let sidecar_size_bytes = fs::metadata(&core)
        .map_err(|e| format!("sidecar metadata: {e}"))?
        .len();
    let base = core.parent().ok_or("sidecar has no parent")?;
    let nonce = session_nonce();
    let handshake_id = "atlas-preview-handshake";
    let operation_id = "atlas-preview-operation";
    let requests = [
        json!({
            "id": handshake_id,
            "method": "core.handshake",
            "params": {
                "protocol": "atlas-core",
                "version": "1.0.0",
                "client_name": "atlas-desktop-tauri",
                "client_version": "0.1.0-preview",
                "session_nonce": nonce
            }
        }),
        json!({
            "id": operation_id,
            "method": method,
            "params": params
        }),
    ];

    let mut wire = Vec::new();
    for request in &requests {
        wire.extend_from_slice(&frame(request)?);
    }

    let mut command = Command::new(&core);
    command
        .arg("--serve-stdio")
        .current_dir(base)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for key in ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    #[cfg(target_os = "windows")]
    {
        command.creation_flags(CREATE_NO_WINDOW);
    }

    let started = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|e| format!("spawn atlas-core: {e}"))?;
    {
        let mut stdin = child.stdin.take().ok_or("atlas-core stdin unavailable")?;
        stdin
            .write_all(&wire)
            .map_err(|e| format!("write atlas-core stdin: {e}"))?;
        stdin
            .flush()
            .map_err(|e| format!("flush atlas-core stdin: {e}"))?;
    }

    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("wait atlas-core: {e}"))?
        {
            break status;
        }
        if started.elapsed() > Duration::from_secs(15) {
            let _ = child.kill();
            return Err("atlas-core stdio request timed out".into());
        }
        thread::sleep(Duration::from_millis(20));
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut stream) = child.stdout.take() {
        stream
            .read_to_end(&mut stdout)
            .map_err(|e| format!("read stdout: {e}"))?;
    }
    if let Some(mut stream) = child.stderr.take() {
        stream
            .read_to_end(&mut stderr)
            .map_err(|e| format!("read stderr: {e}"))?;
    }
    if !status.success() {
        return Err(format!(
            "atlas-core exited {:?}: {}",
            status.code(),
            String::from_utf8_lossy(&stderr)
                .chars()
                .take(2000)
                .collect::<String>()
        ));
    }

    let responses = parse_frames(&stdout)?;
    if responses.len() != 2 {
        return Err(format!("expected 2 responses, got {}", responses.len()));
    }
    let handshake = responses
        .iter()
        .find(|v| v.get("id").and_then(Value::as_str) == Some(handshake_id))
        .ok_or("missing handshake response")?;
    let operation = responses
        .iter()
        .find(|v| v.get("id").and_then(Value::as_str) == Some(operation_id))
        .ok_or("missing operation response")?;

    if handshake.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err("atlas-core handshake failed closed".into());
    }
    let handshake_result = handshake.get("result").ok_or("handshake result missing")?;
    if handshake_result.get("protocol").and_then(Value::as_str) != Some("atlas-core") {
        return Err("protocol mismatch".into());
    }
    if handshake_result.get("version").and_then(Value::as_str) != Some("1.0.0") {
        return Err("protocol version mismatch".into());
    }
    if handshake_result
        .get("session_nonce")
        .and_then(Value::as_str)
        != Some(nonce.as_str())
    {
        return Err("session nonce mismatch".into());
    }

    if operation.get("ok").and_then(Value::as_bool) != Some(true) {
        let error = operation.get("error").unwrap_or(&Value::Null);
        let code = error
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("ATLAS_OPERATION_FAILED");
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("Shared Core operation failed");
        return Err(format!("{code}: {message}"));
    }

    Ok(CoreSessionEvidence {
        result: operation.get("result").cloned().unwrap_or(Value::Null),
        sidecar_sha256,
        sidecar_size_bytes,
        elapsed_ms: (started.elapsed().as_secs_f64() * 1000.0 * 1000.0).round() / 1000.0,
        stderr_bytes: stderr.len(),
    })
}

fn validate_nonempty_scalar_bounded(value: &str, field: &str, max: usize) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if value.chars().count() > max {
        return Err(format!("{field} exceeds the Desktop input bound"));
    }
    Ok(())
}

fn run_core_probe() -> Result<Value, String> {
    let evidence = run_core_session("core.status", json!({}))?;
    let host = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let (_, host_sha256) = sha256_file(&host)?;
    Ok(json!({
        "candidate": "tauri-v2",
        "selected_by": "ADR-0026",
        "host_runtime": "tauri-2.11.5",
        "protocol": "atlas-core",
        "protocol_version": "1.0.0",
        "session_nonce_echoed": true,
        "sidecar_sha256": evidence.sidecar_sha256,
        "sidecar_size_bytes": evidence.sidecar_size_bytes,
        "host_sha256": host_sha256,
        "host_size_bytes": fs::metadata(&host).map_err(|e| format!("host metadata: {e}"))?.len(),
        "round_trip_ms": evidence.elapsed_ms,
        "stderr_bytes": evidence.stderr_bytes,
        "status_result": evidence.result
    }))
}

#[tauri::command]
fn core_status() -> Result<Value, String> {
    run_core_probe()
}

#[tauri::command]
fn search_records(query: String, limit: Option<i64>) -> Result<Value, String> {
    validate_nonempty_scalar_bounded(&query, "query", MAX_UI_QUERY_SCALARS)?;
    let limit = limit.unwrap_or(20);
    if !(1..=MAX_UI_RESULT_LIMIT).contains(&limit) {
        return Err("limit is outside the Desktop result bound".into());
    }
    Ok(run_core_session(
        "search.query",
        json!({"query": query, "graph_depth": 1, "limit": limit}),
    )?
    .result)
}

#[tauri::command]
fn get_record(id: String) -> Result<Value, String> {
    validate_nonempty_scalar_bounded(&id, "id", MAX_UI_IDENTIFIER_SCALARS)?;
    Ok(run_core_session("record.get", json!({"id": id}))?.result)
}

#[tauri::command]
fn expand_graph(seed_id: String, depth: Option<i64>) -> Result<Value, String> {
    validate_nonempty_scalar_bounded(&seed_id, "seed_id", MAX_UI_IDENTIFIER_SCALARS)?;
    let depth = depth.unwrap_or(1);
    if !(0..=MAX_UI_GRAPH_DEPTH).contains(&depth) {
        return Err("depth is outside the Desktop request bound".into());
    }
    Ok(run_core_session(
        "graph.expand",
        json!({
            "seed_ids": [seed_id],
            "depth": depth,
            "direction": "both",
            "limit": 100
        }),
    )?
    .result)
}

#[tauri::command]
fn pack_status() -> Result<Value, String> {
    Ok(run_core_session("pack.status", json!({}))?.result)
}

#[tauri::command]
fn pack_update() -> Result<Value, String> {
    Ok(run_core_session("pack.update", json!({}))?.result)
}

#[tauri::command]
fn pack_rollback() -> Result<Value, String> {
    Ok(run_core_session("pack.rollback", json!({}))?.result)
}

fn arg_value(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    for (i, value) in args.iter().enumerate() {
        if value == name && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        if let Some(rest) = value.strip_prefix(&(name.to_string() + "=")) {
            return Some(rest.to_string());
        }
    }
    None
}

fn main() {
    if std::env::args().any(|arg| arg == "--atlas-probe") {
        let result = (|| -> Result<(), String> {
            let output = arg_value("--probe-output").ok_or("--probe-output is required")?;
            let evidence = run_core_probe()?;
            let path = PathBuf::from(output);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("create evidence directory: {e}"))?;
            }
            fs::write(
                &path,
                format!(
                    "{}\n",
                    serde_json::to_string_pretty(&evidence)
                        .map_err(|e| format!("serialize evidence: {e}"))?
                ),
            )
            .map_err(|e| format!("write evidence: {e}"))?;
            Ok(())
        })();
        if let Err(error) = result {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            core_status,
            search_records,
            get_record,
            expand_graph,
            pack_status,
            pack_update,
            pack_rollback
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Cyber-Sentinel ATLAS First Preview");
}
