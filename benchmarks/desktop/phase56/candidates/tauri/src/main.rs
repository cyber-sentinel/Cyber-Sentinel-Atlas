use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_RESPONSE: usize = 8 * 1024 * 1024;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;
// A first run may need to verify and atomically activate the bundled private
// preview pack before atlas-core can read the handshake. The enriched pack is
// materially larger than the original MVP fixture, so the previous 15-second
// process-wide limit could kill a healthy, bounded cold activation. Keep the
// host fail-closed, but give cold activation an explicit product-level budget.
const CORE_SESSION_TIMEOUT: Duration = Duration::from_secs(120);
const CORE_SESSION_POLL_INTERVAL: Duration = Duration::from_millis(20);
const CORE_STDERR_DIAGNOSTIC_LIMIT: usize = 2000;
#[cfg(windows)]
const WEBVIEW2_OFFLINE_BROWSER_ARGUMENTS: &str = "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --disable-background-networking --disable-component-update --disable-sync --metrics-recording-only --no-first-run";
const MAX_UI_QUERY_SCALARS: usize = 512;
const MAX_UI_IDENTIFIER_SCALARS: usize = 1024;
const MAX_UI_RESULT_LIMIT: i64 = 100;
const MAX_UI_CATALOG_OFFSET: i64 = 1_000_000;
const MAX_UI_GRAPH_DEPTH: i64 = 32;
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
const CATALOG_FILTER_ALLOWLIST: &[&str] = &[
    "platform",
    "product",
    "provider",
    "channel",
    "namespace",
    "type",
    "lifecycle",
    "version",
    "family",
    "source_family",
    "domain",
    "tactic",
    "active",
    "telemetry_family",
    "function",
    "context",
    "binary",
    "tool_type",
    "attack_technique",
    "parent_technique",
    "detection_strategy",
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
    let manifest_text = fs::read_to_string(&manifest).map_err(|e| format!("read manifest: {e}"))?;
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
    #[cfg(windows)]
    {
        command.creation_flags(CREATE_NO_WINDOW);
    }

    let started = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|e| format!("spawn atlas-core: {e}"))?;
    let write_result = {
        let mut stdin = child.stdin.take().ok_or("atlas-core stdin unavailable")?;
        let result = stdin
            .write_all(&wire)
            .map_err(|e| format!("write atlas-core stdin: {e}"))
            .and_then(|_| {
                stdin
                    .flush()
                    .map_err(|e| format!("flush atlas-core stdin: {e}"))
            });
        result
    };
    if let Err(error) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }

    let mut stdout_stream = child.stdout.take().ok_or("atlas-core stdout unavailable")?;
    let mut stderr_stream = child.stderr.take().ok_or("atlas-core stderr unavailable")?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout_stream
            .read_to_end(&mut bytes)
            .map_err(|e| format!("read stdout: {e}"))?;
        Ok::<Vec<u8>, String>(bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr_stream
            .read_to_end(&mut bytes)
            .map_err(|e| format!("read stderr: {e}"))?;
        Ok::<Vec<u8>, String>(bytes)
    });

    let mut timeout_elapsed_ms = None;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("wait atlas-core: {e}"))?
        {
            break status;
        }
        if started.elapsed() > CORE_SESSION_TIMEOUT {
            let _ = child.kill();
            timeout_elapsed_ms = Some(started.elapsed().as_millis());
            break child
                .wait()
                .map_err(|e| format!("wait for timed-out atlas-core: {e}"))?;
        }
        thread::sleep(CORE_SESSION_POLL_INTERVAL);
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| "atlas-core stdout reader panicked".to_string())??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "atlas-core stderr reader panicked".to_string())??;
    if let Some(elapsed_ms) = timeout_elapsed_ms {
        let stderr_excerpt = String::from_utf8_lossy(&stderr)
            .chars()
            .take(CORE_STDERR_DIAGNOSTIC_LIMIT)
            .collect::<String>();
        return Err(format!(
            "atlas-core stdio request timed out after {elapsed_ms} ms (limit {} ms); stdout_bytes={}; stderr={stderr_excerpt}",
            CORE_SESSION_TIMEOUT.as_millis(),
            stdout.len()
        ));
    }
    if !status.success() {
        return Err(format!(
            "atlas-core exited {:?}: {}",
            status.code(),
            String::from_utf8_lossy(&stderr)
                .chars()
                .take(CORE_STDERR_DIAGNOSTIC_LIMIT)
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

async fn run_core_session_async(
    method: &'static str,
    params: Value,
) -> Result<CoreSessionEvidence, String> {
    tauri::async_runtime::spawn_blocking(move || run_core_session(method, params))
        .await
        .map_err(|error| format!("atlas-core worker failed: {error}"))?
}

#[tauri::command]
async fn core_status() -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(run_core_probe)
        .await
        .map_err(|error| format!("atlas-core status worker failed: {error}"))?
}

#[tauri::command]
async fn search_records(query: String, limit: Option<i64>) -> Result<Value, String> {
    validate_nonempty_scalar_bounded(&query, "query", MAX_UI_QUERY_SCALARS)?;
    let limit = limit.unwrap_or(20);
    if !(1..=MAX_UI_RESULT_LIMIT).contains(&limit) {
        return Err("limit is outside the Desktop result bound".into());
    }
    Ok(run_core_session_async(
        "search.query",
        json!({"query": query, "graph_depth": 1, "limit": limit}),
    )
    .await?
    .result)
}

#[tauri::command]
async fn list_entities(
    filters: Option<HashMap<String, String>>,
    query: Option<String>,
    sort: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Value, String> {
    let filters = filters.unwrap_or_default();
    if filters.len() > 16 {
        return Err("catalog filters exceed the Desktop bound".into());
    }
    for (key, value) in &filters {
        if !CATALOG_FILTER_ALLOWLIST.contains(&key.as_str()) {
            return Err(format!("unsupported catalog filter: {key}"));
        }
        validate_nonempty_scalar_bounded(value, "catalog filter", 256)?;
    }
    let query = query.unwrap_or_default();
    if query.chars().count() > MAX_UI_QUERY_SCALARS {
        return Err("catalog query exceeds the Desktop input bound".into());
    }
    let sort = sort.unwrap_or_else(|| "name".to_string());
    if !matches!(sort.as_str(), "name" | "id" | "type") {
        return Err("unsupported catalog sort".into());
    }
    let limit = limit.unwrap_or(50);
    if !(1..=MAX_UI_RESULT_LIMIT).contains(&limit) {
        return Err("limit is outside the Desktop result bound".into());
    }
    let offset = offset.unwrap_or(0);
    if !(0..=MAX_UI_CATALOG_OFFSET).contains(&offset) {
        return Err("catalog offset is outside the Desktop bound".into());
    }
    Ok(run_core_session_async(
        "catalog.list",
        json!({
            "filters": filters,
            "query": query,
            "sort": sort,
            "limit": limit,
            "offset": offset
        }),
    )
    .await?
    .result)
}

#[tauri::command]
async fn get_record(id: String) -> Result<Value, String> {
    validate_nonempty_scalar_bounded(&id, "id", MAX_UI_IDENTIFIER_SCALARS)?;
    Ok(
        run_core_session_async("record.get", json!({"id": id, "detail": true}))
            .await?
            .result,
    )
}

#[tauri::command]
async fn expand_graph(seed_id: String, depth: Option<i64>) -> Result<Value, String> {
    validate_nonempty_scalar_bounded(&seed_id, "seed_id", MAX_UI_IDENTIFIER_SCALARS)?;
    let depth = depth.unwrap_or(1);
    if !(0..=MAX_UI_GRAPH_DEPTH).contains(&depth) {
        return Err("depth is outside the Desktop request bound".into());
    }
    Ok(run_core_session_async(
        "graph.expand",
        json!({
            "seed_ids": [seed_id],
            "depth": depth,
            "direction": "both",
            "limit": 100
        }),
    )
    .await?
    .result)
}

#[tauri::command]
async fn pack_status() -> Result<Value, String> {
    Ok(run_core_session_async("pack.status", json!({}))
        .await?
        .result)
}

#[tauri::command]
async fn pack_update() -> Result<Value, String> {
    Ok(run_core_session_async("pack.update", json!({}))
        .await?
        .result)
}

#[tauri::command]
async fn pack_rollback() -> Result<Value, String> {
    Ok(run_core_session_async("pack.rollback", json!({}))
        .await?
        .result)
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

#[cfg(windows)]
fn configure_offline_webview() -> Result<(), String> {
    for argument in std::env::args_os().skip(1) {
        let normalized = argument.to_string_lossy().to_ascii_lowercase();
        if normalized.starts_with("--edge-webview-switches") {
            return Err(
                "--edge-webview-switches is not permitted for the offline ATLAS host".to_string(),
            );
        }
    }

    // Tauri applies the same allowlist programmatically from tauri.conf.json.
    // Also replace inherited environment arguments so a non-elevated WebView2
    // cannot append caller-controlled switches or fall through to a per-user
    // AdditionalBrowserArguments registry override. Remove debugger hooks before
    // Tauri constructs the browser environment.
    //
    // SAFETY: this function is Windows-only. Rust documents process-environment
    // mutation as always safe on Windows, and it runs before Tauri or atlas-core
    // starts any application worker threads.
    unsafe {
        std::env::set_var(
            "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
            WEBVIEW2_OFFLINE_BROWSER_ARGUMENTS,
        );
        std::env::remove_var("WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER");
        std::env::remove_var("WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER");
    }
    Ok(())
}

#[cfg(not(windows))]
fn configure_offline_webview() -> Result<(), String> {
    Ok(())
}

fn main() {
    if let Err(error) = configure_offline_webview() {
        eprintln!("{error}");
        std::process::exit(1);
    }

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
            list_entities,
            get_record,
            expand_graph,
            pack_status,
            pack_update,
            pack_rollback
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Cyber-Sentinel ATLAS First Preview");
}
