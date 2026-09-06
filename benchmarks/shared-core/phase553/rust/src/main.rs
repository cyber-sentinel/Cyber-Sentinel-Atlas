use base64::Engine;
use rusqlite::{params, params_from_iter, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Deserialize)]
struct QueryExpectation {
    targets: Vec<String>,
    stage: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct Expected {
    evidence_schema_version: String,
    queries: Vec<String>,
    query_expectations: BTreeMap<String, QueryExpectation>,
    spc_bundle_digest: String,
    search_index_sha256: String,
    serialization_vector: Value,
    compact_json_base64: String,
    compact_json_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct Resolved {
    targets: Vec<String>,
    stage: String,
    status: String,
}

#[derive(Debug)]
struct ParsedQuery {
    normalized: String,
    terms: Vec<String>,
    scope: BTreeMap<String, String>,
    identifier_type_hint: Option<String>,
    identifier_value: Option<String>,
}

fn sha256_prefixed(data: &[u8]) -> String {
    format!("sha256-{:x}", Sha256::digest(data))
}

fn nfkc(value: &str) -> String {
    value.nfkc().collect::<String>()
}

fn fold(value: &str) -> String {
    nfkc(value).to_lowercase()
}

fn parse_query(query: &str) -> Result<ParsedQuery, String> {
    if query.chars().count() > 512 {
        return Err("query exceeds 512 Unicode scalars".into());
    }
    let normalized = nfkc(query).split_whitespace().collect::<Vec<_>>().join(" ");
    let allowed: BTreeSet<&str> = [
        "platform", "product", "provider", "channel", "namespace", "type", "lifecycle", "version",
    ]
    .into_iter()
    .collect();
    let mut scope = BTreeMap::new();
    let mut terms = Vec::new();
    let mut filters = 0usize;
    for term in normalized.split_whitespace() {
        if let Some((key, value)) = term.split_once(':') {
            let key = key.to_lowercase();
            if allowed.contains(key.as_str()) && !value.is_empty() {
                scope.insert(key, value.to_string());
                filters += 1;
                continue;
            }
        }
        terms.push(term.to_string());
    }
    if terms.len() > 32 || filters > 16 {
        return Err("bounded query contract exceeded".into());
    }
    let mut identifier_type_hint = None;
    let mut identifier_value = None;
    if terms.len() >= 2 {
        match terms[0].to_lowercase().as_str() {
            "sysmon" => {
                scope.insert("namespace".into(), "microsoft.sysmon".into());
                scope.insert("product".into(), "sysmon".into());
                if terms.len() == 2 {
                    identifier_value = Some(terms[1].clone());
                }
            }
            "windows" => {
                scope.insert("namespace".into(), "microsoft.windows.security".into());
                scope.insert("platform".into(), "windows".into());
                if terms.len() == 2 {
                    identifier_value = Some(terms[1].clone());
                }
            }
            _ => {}
        }
    }
    if terms.len() == 3
        && terms[0].eq_ignore_ascii_case("event")
        && terms[1].eq_ignore_ascii_case("id")
    {
        identifier_type_hint = Some("event_id".into());
        identifier_value = Some(terms[2].clone());
    } else if terms.len() == 1 {
        identifier_value = Some(terms[0].clone());
    }
    Ok(ParsedQuery {
        normalized,
        terms,
        scope,
        identifier_type_hint,
        identifier_value,
    })
}

fn status_for(targets: &[String]) -> String {
    match targets.len() {
        0 => "no_match".into(),
        1 => "direct".into(),
        _ => "disambiguation".into(),
    }
}

fn scope_clause(scope: &BTreeMap<String, String>, alias: &str) -> (String, Vec<String>) {
    let mut clauses = Vec::new();
    let mut args = Vec::new();
    for (key, value) in scope {
        clauses.push(format!(
            "EXISTS (SELECT 1 FROM facets sf WHERE sf.target_id={alias}.target_id AND sf.facet_key=? AND sf.facet_value_norm=?)"
        ));
        args.push(key.clone());
        args.push(fold(value));
    }
    (clauses.join(" AND "), args)
}

fn stable_targets(conn: &Connection, ids: Vec<String>) -> Result<Vec<String>, rusqlite::Error> {
    let mut keyed = Vec::new();
    for id in ids {
        let key: (String, String, String, String, String, String, String) = conn.query_row(
            r#"SELECT lower(COALESCE(d.platform,'')), lower(COALESCE(d.product,'')),
                      lower(COALESCE(d.provider,'')), lower(COALESCE(d.channel,'')),
                      lower(COALESCE(pi.identifier_type,'')), lower(COALESCE(pi.value,'')),
                      lower(COALESCE(d.lifecycle,''))
               FROM documents d
               LEFT JOIN identifiers pi ON pi.target_id=d.target_id AND pi.primary_flag=1
               WHERE d.target_id=?"#,
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
        )?;
        keyed.push((key, id));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    Ok(keyed.into_iter().map(|(_, id)| id).collect())
}

fn resolve(conn: &Connection, query: &str) -> Result<Resolved, String> {
    let request = parse_query(query)?;
    if request.normalized.is_empty() {
        return Ok(Resolved { targets: vec![], stage: "none".into(), status: "no_match".into() });
    }
    let canonical: Result<String, _> = conn.query_row(
        "SELECT target_id FROM documents WHERE target_id=?",
        params![request.normalized],
        |row| row.get(0),
    );
    if let Ok(id) = canonical {
        return Ok(Resolved { targets: vec![id], stage: "canonical_identifier".into(), status: "direct".into() });
    }

    if let Some(value) = request.identifier_value.as_ref() {
        let (scope_sql, mut scope_args) = scope_clause(&request.scope, "d");
        let mut sql = String::from(
            "SELECT i.target_id FROM identifiers i JOIN documents d ON d.target_id=i.target_id WHERE ((i.case_sensitive=1 AND i.match_value=?) OR (i.case_sensitive=0 AND i.match_value=?))",
        );
        let mut args = vec![nfkc(value), fold(value)];
        if let Some(kind) = request.identifier_type_hint.as_ref() {
            sql.push_str(" AND i.identifier_type=?");
            args.push(kind.clone());
        }
        if !scope_sql.is_empty() {
            sql.push_str(" AND ");
            sql.push_str(&scope_sql);
            args.append(&mut scope_args);
        }
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params_from_iter(args.iter()), |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        let mut ids = BTreeSet::new();
        for row in rows {
            ids.insert(row.map_err(|e| e.to_string())?);
        }
        if !ids.is_empty() {
            let targets = stable_targets(conn, ids.into_iter().collect()).map_err(|e| e.to_string())?;
            let stage = if request.scope.is_empty() { "native_identifier" } else { "scoped_identifier" };
            return Ok(Resolved { status: status_for(&targets), targets, stage: stage.into() });
        }
    }

    let (scope_sql, mut scope_args) = scope_clause(&request.scope, "d");
    let mut alias_sql = String::from(
        "SELECT a.target_id FROM aliases a JOIN documents d ON d.target_id=a.target_id WHERE ((a.case_sensitive=1 AND a.match_value=?) OR (a.case_sensitive=0 AND a.match_value=?))",
    );
    let mut alias_args = vec![nfkc(&request.normalized), fold(&request.normalized)];
    if !scope_sql.is_empty() {
        alias_sql.push_str(" AND ");
        alias_sql.push_str(&scope_sql);
        alias_args.append(&mut scope_args);
    }
    let mut stmt = conn.prepare(&alias_sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params_from_iter(alias_args.iter()), |row| row.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    let mut alias_ids = BTreeSet::new();
    for row in rows {
        alias_ids.insert(row.map_err(|e| e.to_string())?);
    }
    if !alias_ids.is_empty() {
        let targets = stable_targets(conn, alias_ids.into_iter().collect()).map_err(|e| e.to_string())?;
        return Ok(Resolved { status: status_for(&targets), targets, stage: "alias".into() });
    }

    let lexical_text = request.terms.join(" ");
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in nfkc(&lexical_text).chars() {
        if ch.is_alphanumeric() || ch == '_' {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(fold(&current));
            current.clear();
        }
    }
    if !current.is_empty() {
        tokens.push(fold(&current));
    }
    if tokens.len() > 32 {
        return Err("lexical token bound exceeded".into());
    }
    if tokens.is_empty() {
        return Ok(Resolved { targets: vec![], stage: "none".into(), status: "no_match".into() });
    }
    let expression = tokens
        .iter()
        .map(|token| format!("\"{}\"", token.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" OR ");
    let (scope_sql, mut scope_args) = scope_clause(&request.scope, "d");
    let mut sql = String::from(
        "SELECT d.target_id FROM documents_fts JOIN documents d ON d.target_id=documents_fts.target_id WHERE documents_fts MATCH ?",
    );
    let mut args = vec![expression];
    if !scope_sql.is_empty() {
        sql.push_str(" AND ");
        sql.push_str(&scope_sql);
        args.append(&mut scope_args);
    }
    sql.push_str(" ORDER BY bm25(documents_fts) ASC, CASE WHEN d.title_norm=? THEN 0 ELSE 1 END ASC, d.title_norm ASC, d.target_id ASC LIMIT 20");
    args.push(fold(&lexical_text));
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params_from_iter(args.iter()), |row| row.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    let mut targets = Vec::new();
    for row in rows {
        targets.push(row.map_err(|e| e.to_string())?);
    }
    let stage = if targets.is_empty() { "none" } else { "lexical" };
    Ok(Resolved { status: status_for(&targets), targets, stage: stage.into() })
}

fn percentile(values: &mut [f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = (((values.len() - 1) as f64) * p).round() as usize;
    values[idx]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 || args[1] != "--workspace" || args[3] != "--output" {
        eprintln!("usage: atlas-phase553-rust --workspace PATH --output PATH");
        std::process::exit(2);
    }
    let workspace = PathBuf::from(&args[2]);
    let output = PathBuf::from(&args[4]);
    let expected: Expected = serde_json::from_slice(&fs::read(workspace.join("expected.json"))?)?;

    let compact = serde_json::to_vec(&expected.serialization_vector)?;
    let serialization_ok = base64::engine::general_purpose::STANDARD.encode(&compact) == expected.compact_json_base64
        && sha256_prefixed(&compact) == expected.compact_json_sha256;

    let probe = Connection::open_in_memory()?;
    let fts5 = probe.execute("CREATE VIRTUAL TABLE probe USING fts5(value)", []).is_ok();
    let index_path = workspace.join("search").join("atlas-search.sqlite3");
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI;
    let conn = Connection::open_with_flags(&index_path, flags)?;
    let quick: String = conn.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    let sqlite_version: String = conn.query_row("SELECT sqlite_version()", [], |row| row.get(0))?;
    let index_binding_ok = sha256_prefixed(&fs::read(&index_path)?) == expected.search_index_sha256;

    let mut query_evidence = BTreeMap::new();
    let mut search_ok = quick == "ok" && fts5 && index_binding_ok;
    let mut exact_samples = Vec::new();
    let mut lexical_samples = Vec::new();
    for query in &expected.queries {
        let mut baseline: Option<Resolved> = None;
        let mut samples = Vec::new();
        for _ in 0..40 {
            let started = Instant::now();
            let current = resolve(&conn, query).map_err(std::io::Error::other)?;
            samples.push(started.elapsed().as_secs_f64() * 1000.0);
            if let Some(first) = &baseline {
                if first.targets != current.targets || first.stage != current.stage || first.status != current.status {
                    search_ok = false;
                }
            } else {
                baseline = Some(current);
            }
        }
        let result = baseline.unwrap();
        let wanted = expected.query_expectations.get(query).unwrap();
        let pass = result.targets == wanted.targets && result.stage == wanted.stage && result.status == wanted.status;
        search_ok &= pass;
        if result.stage == "lexical" {
            lexical_samples.extend(samples.iter().copied());
        } else {
            exact_samples.extend(samples.iter().copied());
        }
        let p95 = percentile(&mut samples, 0.95);
        query_evidence.insert(query.clone(), json!({
            "pass": pass,
            "targets": result.targets,
            "stage": result.stage,
            "status": result.status,
            "p95_ms": p95,
        }));
    }
    let exact_p95 = percentile(&mut exact_samples, 0.95);
    let lexical_p95 = percentile(&mut lexical_samples, 0.95);

    let rustc = Command::new("rustc").arg("--version").output().ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
    let cargo_lock = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock")).unwrap_or_default();
    let binary_size = env::current_exe().ok().and_then(|p| fs::metadata(p).ok()).map(|m| m.len()).unwrap_or(0);

    // rust-tuf is deliberately exercised as a pinned build dependency in this spike,
    // but the Atlas-owned POUF v1 signed corpus is not claimed as passed. Upstream
    // itself labels 0.3.0-beta15 beta/unstable; therefore G-SC5 fails closed instead
    // of substituting a custom verifier or generic TUF example.
    let gates = BTreeMap::from([
        ("G-SC1", search_ok),
        ("G-SC2", serialization_ok),
        ("G-SC3", search_ok && exact_p95 < 100.0 && lexical_p95 < 300.0),
        ("G-SC4", fts5 && search_ok),
        ("G-SC5", false),
        ("G-SC6", false),
        ("G-SC7", false),
        ("G-SC8", true),
    ]);
    let eligible = gates.values().all(|v| *v);
    let evidence = json!({
        "evidence_schema_version": expected.evidence_schema_version,
        "candidate": "rust",
        "eligible": eligible,
        "gates": gates,
        "runtime": {
            "rustc": rustc,
            "os": env::consts::OS,
            "arch": env::consts::ARCH,
            "sqlite": sqlite_version,
            "fts5": fts5,
            "binary_size_bytes": binary_size,
        },
        "dependencies": {
            "rusqlite": "0.40.1 bundled",
            "rust-tuf": "0.3.0-beta15",
            "cargo_lock_sha256": sha256_prefixed(&cargo_lock),
        },
        "bindings": {
            "spc_bundle_digest": expected.spc_bundle_digest,
            "search_index_sha256": expected.search_index_sha256,
            "serialization_sha256": expected.compact_json_sha256,
        },
        "search": {
            "queries": query_evidence,
            "exact_p95_ms": exact_p95,
            "lexical_p95_ms": lexical_p95,
        },
        "pack": {
            "pass": false,
            "reason": "Atlas POUF v1 signed-fixture workflow not passed; rust-tuf 0.3.0-beta15 is upstream beta/unstable and is not accepted as a production trust root by existence alone."
        },
        "state": {
            "pass": false,
            "reason": "Production-equivalent Atlas durable activation/LKG state machine not implemented in the Rust finalist spike."
        },
        "known_limitations": [
            "Candidate is hard-gate ineligible because G-SC5/G-SC6/G-SC7 are not proven; no custom crypto/TUF substitute is used to manufacture a pass.",
            "Search/SQLite evidence remains useful for comparison even though the trust/runtime candidate is disqualified."
        ]
    });
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, serde_json::to_vec_pretty(&evidence)?.into_iter().chain([b'\n']).collect::<Vec<_>>())?;
    println!("{{\"candidate\":\"rust\",\"eligible\":{eligible}}}");
    // Candidate failure is evidence, not CI infrastructure failure: return success so
    // the cross-candidate validator can apply hard-gate disqualification explicitly.
    Ok(())
}
