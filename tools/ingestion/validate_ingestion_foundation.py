#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qsl, urlparse
import copy
import hashlib
import ipaddress
import json
import re
import subprocess
import sys

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]
INGESTION_SCHEMA_DIR = ROOT / "schemas" / "ingestion" / "v1"
CANONICAL_SCHEMA_DIR = ROOT / "schemas" / "v1"
FIXTURE_DIR = ROOT / "fixtures" / "phase-5.3"
BUNDLE_PATH = FIXTURE_DIR / "foundation-valid.json"
REGISTRY_DIR = ROOT / "model" / "registries"

INGESTION_CONTRACT_VERSION = "1.0.0"
CANONICAL_SCHEMA_VERSION = "1.0.0"
INGESTION_SCHEMA_URI_BASE = "https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/ingestion/v1/"
CANONICAL_SCHEMA_URI_BASE = "https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/v1/"

EXPECTED_ROOT_SCHEMAS = {
    "connector-definition.schema.json", "acquisition-run.schema.json", "raw-snapshot.schema.json",
    "parser-definition.schema.json", "parser-run.schema.json", "parsed-source-record.schema.json",
    "normalizer-definition.schema.json", "normalization-run.schema.json", "normalization-lineage.schema.json",
    "inventory-definition.schema.json", "inventory-diff.schema.json", "build-validation-report.schema.json",
    "review-decision.schema.json", "canonical-build-manifest.schema.json",
}
ARTIFACT_SCHEMA_MAP = {
    "connector-definition.json": "connector-definition.schema.json",
    "acquisition-run.json": "acquisition-run.schema.json",
    "raw-snapshot.json": "raw-snapshot.schema.json",
    "parser-definition.json": "parser-definition.schema.json",
    "parser-run.json": "parser-run.schema.json",
    "parsed-source-record.json": "parsed-source-record.schema.json",
    "normalizer-definition.json": "normalizer-definition.schema.json",
    "normalization-run.json": "normalization-run.schema.json",
    "normalization-lineage.json": "normalization-lineage.schema.json",
    "inventory-definition.json": "inventory-definition.schema.json",
    "inventory-diff.json": "inventory-diff.schema.json",
    "build-validation-report.json": "build-validation-report.schema.json",
    "review-decision.json": "review-decision.schema.json",
    "canonical-build-manifest.json": "canonical-build-manifest.schema.json",
}
IDENTITY_FIELDS = {
    "connector-definition.json": "connector_id", "acquisition-run.json": "acquisition_run_id",
    "raw-snapshot.json": "snapshot_id", "parser-definition.json": "parser_id",
    "parser-run.json": "parser_run_id", "parsed-source-record.json": "parsed_record_id",
    "normalizer-definition.json": "normalizer_id", "normalization-run.json": "normalization_run_id",
    "normalization-lineage.json": "lineage_id", "inventory-definition.json": "inventory_id",
    "inventory-diff.json": "inventory_diff_id", "build-validation-report.json": "validation_report_id",
    "review-decision.json": "review_decision_id", "canonical-build-manifest.json": "build_id",
}
CANONICAL_FAMILY_REFS = {
    "entity.schema.json", "claim.schema.json", "relationship.schema.json", "source.schema.json",
    "validation-record.schema.json", "version-record.schema.json", "coverage-snapshot.schema.json",
}
SUSPICIOUS_QUERY_KEYS = {
    "token", "access_token", "api_key", "apikey", "key", "sig", "signature", "session", "sessionid",
    "x-amz-signature", "x-amz-credential", "x-goog-signature", "x-goog-credential", "se", "sp", "sv",
}
FORBIDDEN_SECRET_FIELDS = {
    "api_key", "apikey", "password", "passwd", "bearer", "bearer_token", "access_token", "refresh_token",
    "cookie", "set_cookie", "authorization", "credential", "credentials", "client_secret", "secret", "private_key",
}
ALLOWED_SECURITY_FIELD_NAMES = {"credential_helpers", "auth_profile_ref"}
SECRET_VALUE_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b", re.I),
]
INTERNAL_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}
FORBIDDEN_SEARCH_PROJECTION_KEYS = {
    "numeric_sort_value", "numericSortValue", "search_rank", "search_tokens", "lexical_tokens",
    "embedding", "vector", "search_projection",
}
SEMANTIC_RELATIONSHIPS_REQUIRING_SUPPORT = {
    "INDICATES", "RELATED_TO", "EQUIVALENT_SIGNAL", "PRECEDES", "FOLLOWS", "MAPS_TO_ATTACK",
    "COUNTERED_BY", "DETECTED_BY", "HUNTED_BY", "INVESTIGATED_BY", "RESPONDED_BY",
    "REQUIRES_TELEMETRY", "DERIVED_FROM", "SUPPORTED_BY", "SUPERSEDES", "SUPERSEDED_BY",
    "VERSION_OF", "VALIDATED_BY",
}
MANDATORY_GATES = {f"G{i}" for i in range(1, 16)}
REVIEW_SUCCESS = {"approved", "approved-with-exceptions"}
RECORD_KIND_TO_COUNT = {
    "entity": "EntityRecord", "claim": "ClaimRecord", "relationship": "RelationshipRecord",
    "source": "SourceRecord", "validation": "ValidationRecord", "version": "VersionRecord",
    "coverage-snapshot": "CoverageSnapshot",
}


def _set_root(root: Path):
    global ROOT, INGESTION_SCHEMA_DIR, CANONICAL_SCHEMA_DIR, FIXTURE_DIR, BUNDLE_PATH, REGISTRY_DIR
    ROOT = Path(root)
    INGESTION_SCHEMA_DIR = ROOT / "schemas" / "ingestion" / "v1"
    CANONICAL_SCHEMA_DIR = ROOT / "schemas" / "v1"
    FIXTURE_DIR = ROOT / "fixtures" / "phase-5.3"
    BUNDLE_PATH = FIXTURE_DIR / "foundation-valid.json"
    REGISTRY_DIR = ROOT / "model" / "registries"


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_digest(value) -> str:
    if isinstance(value, bytes):
        payload = value
    elif isinstance(value, str):
        payload = value.encode("utf-8")
    else:
        payload = canonical_json(value).encode("utf-8")
    return "sha256-" + hashlib.sha256(payload).hexdigest()


def digest_without_field(record: dict, field: str) -> str:
    payload = copy.deepcopy(record)
    payload.pop(field, None)
    return sha256_digest(payload)


def stable_artifact_id(kind: str, payload) -> str:
    return f"atlas:{kind}:atlas.ingestion:{sha256_digest(payload)}"


def parse_datetime(value: str):
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must be offset-aware")
    return parsed


def timestamp_order_errors(record: dict, started_field="started_at", finished_field="finished_at", label="run"):
    errors = []
    try:
        started = parse_datetime(record[started_field])
        finished = parse_datetime(record[finished_field])
        if finished < started:
            errors.append(f"{label} finish precedes start")
    except (KeyError, ValueError) as exc:
        errors.append(f"{label} timestamp invalid: {exc}")
    return errors


def walk_refs(value):
    if isinstance(value, dict):
        if isinstance(value.get("$ref"), str):
            yield value["$ref"]
        for child in value.values():
            yield from walk_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_refs(child)


def load_schema_store(directory: Path, uri_base: str):
    store, by_name = {}, {}
    for path in sorted(directory.rglob("*.json")):
        schema = load_json(path)
        Draft202012Validator.check_schema(schema)
        rel = path.relative_to(directory).as_posix()
        expected = uri_base + rel
        if schema.get("$id") != expected:
            raise ValueError(f"{rel}: schema $id must be {expected}")
        for ref in walk_refs(schema):
            if ref.startswith("https://json-schema.org/"):
                continue
            if not ref.startswith(uri_base):
                raise ValueError(f"{rel}: non-canonical $ref {ref}")
        if expected in store:
            raise ValueError(f"duplicate schema $id: {expected}")
        store[expected], by_name[rel] = schema, schema
    return store, by_name


def build_validator(directory: Path, uri_base: str, root_name: str):
    store, by_name = load_schema_store(directory, uri_base)
    if root_name not in by_name:
        raise ValueError(f"missing root schema: {root_name}")
    registry = Registry()
    for uri, schema in store.items():
        registry = registry.with_resource(uri, Resource.from_contents(schema))
    return Draft202012Validator(by_name[root_name], registry=registry, format_checker=FormatChecker()), by_name


def ingestion_validator(schema_name: str):
    return build_validator(INGESTION_SCHEMA_DIR, INGESTION_SCHEMA_URI_BASE, schema_name)[0]


def canonical_root_validator():
    return build_validator(CANONICAL_SCHEMA_DIR, CANONICAL_SCHEMA_URI_BASE, "atlas-record.schema.json")[0]


def load_fixture_bundle():
    return load_json(BUNDLE_PATH)


def bundle_artifacts(bundle=None):
    bundle = bundle or load_fixture_bundle()
    return {f"{name}.json": value for name, value in bundle["artifacts"].items()}


def load_registries():
    out = {}
    for path in sorted(REGISTRY_DIR.glob("*.json")):
        data = load_json(path)
        out[data["registry"]] = {item["value"] for item in data["values"]}
    return out


def duplicate_identity_errors(named_records):
    errors, seen = [], {}
    for name, record, field in named_records:
        identity = record.get(field)
        if identity and identity in seen:
            errors.append(f"duplicate ingestion artifact identity {identity}: {seen[identity]} and {name}")
        elif identity:
            seen[identity] = name
    return errors


def validate_json_secret_surface(value, path="$"):
    errors = []
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.lower().replace("-", "_")
            if normalized in FORBIDDEN_SECRET_FIELDS and normalized not in ALLOWED_SECURITY_FIELD_NAMES:
                errors.append(f"{path}.{key}: secret-like manifest field is forbidden")
            errors.extend(validate_json_secret_surface(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for i, child in enumerate(value):
            errors.extend(validate_json_secret_surface(child, f"{path}[{i}]"))
    elif isinstance(value, str):
        if any(pattern.search(value) for pattern in SECRET_VALUE_PATTERNS):
            errors.append(f"{path}: secret-like value detected")
    return errors


def public_uri_errors(uri: str, allowed_hosts=None, allowed_path_prefixes=None):
    errors = []
    parsed = urlparse(uri)
    if parsed.scheme.lower() != "https":
        errors.append("public acquisition URI must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        errors.append("URI userinfo/embedded credentials are forbidden")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        errors.append("URI hostname is required")
    if host in INTERNAL_HOSTNAMES or host.endswith(".localhost"):
        errors.append("loopback/internal hostname is forbidden")
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_reserved or ip.is_multicast:
            errors.append("private/link-local/loopback/internal destination is forbidden")
    except ValueError:
        pass
    if allowed_hosts is not None and host not in {h.lower().rstrip(".") for h in allowed_hosts}:
        errors.append(f"host {host!r} is not allowlisted")
    query_keys = {k.lower() for k, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    suspicious = query_keys & SUSPICIOUS_QUERY_KEYS
    if suspicious:
        errors.append(f"signed/temporary credential query parameters are forbidden: {sorted(suspicious)}")
    if allowed_path_prefixes and not any(parsed.path.startswith(prefix) for prefix in allowed_path_prefixes):
        errors.append(f"path {parsed.path!r} is outside allowed path prefixes")
    return errors


def archive_entry_errors(path: str, *, is_symlink=False, symlink_target=None, is_device=False):
    errors = []
    normalized = path.replace("\\", "/")
    parts = [p for p in PurePosixPath(normalized).parts if p not in ("", ".")]
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
        errors.append("absolute archive extraction path is forbidden")
    if ".." in parts:
        errors.append("archive path traversal is forbidden")
    if is_device:
        errors.append("device-file extraction is forbidden")
    if is_symlink:
        target = (symlink_target or "").replace("\\", "/")
        tparts = [p for p in PurePosixPath(target).parts if p not in ("", ".")]
        if target.startswith("/") or re.match(r"^[A-Za-z]:/", target) or ".." in tparts:
            errors.append("symlink escape is forbidden")
    return errors


def acquisition_semantic_errors(connector, run):
    errors = []
    targets = connector.get("targets", [])
    target_keys = [t.get("target_key") for t in targets]
    if len(target_keys) != len(set(target_keys)):
        errors.append("connector target_key values must be unique")
    declared = {t["target_key"]: t for t in targets if t.get("target_key")}
    by_target = defaultdict(list)
    for resource in run.get("resource_results", []):
        key = resource.get("target_key")
        if key not in declared:
            errors.append(f"unknown resource_result target_key {key!r}")
            continue
        by_target[key].append(resource)
        if resource.get("required") != declared[key].get("required"):
            errors.append("resource required flag conflicts with connector target")
        status = resource.get("status")
        if status == "success":
            if not resource.get("snapshot_id"):
                errors.append("successful resource must reference snapshot_id")
            if resource.get("previous_snapshot_id"):
                errors.append("successful resource must not masquerade as not-modified")
        elif status == "not-modified":
            if resource.get("snapshot_id"):
                errors.append("HTTP not-modified must not create a fake new snapshot")
            if not resource.get("previous_snapshot_id"):
                errors.append("not-modified resource must reference previous valid snapshot")
        elif status in {"failed", "skipped"} and resource.get("snapshot_id"):
            errors.append("failed/skipped resource must not reference a new snapshot")

    for key, target in declared.items():
        results = by_target.get(key, [])
        if target.get("required") and not results:
            errors.append(f"required connector target absent from AcquisitionRun: {key}")
        if target.get("required") and results:
            usable = [r for r in results if (r.get("status") == "success" and r.get("snapshot_id")) or
                      (r.get("status") == "not-modified" and r.get("previous_snapshot_id") and not r.get("snapshot_id"))]
            if not usable and run.get("publication_eligible"):
                errors.append(f"required target {key} has no usable resource result and must make acquisition non-publishable")

    statuses = [r.get("status") for r in run.get("resource_results", [])]
    good = sum(s in {"success", "not-modified"} for s in statuses)
    bad = sum(s in {"failed", "skipped"} for s in statuses)
    result_status = run.get("result_status")
    if result_status == "success" and (bad or not any(s == "success" for s in statuses)):
        errors.append("AcquisitionRun success status is incoherent with resource results")
    if result_status == "failed":
        if run.get("publication_eligible"):
            errors.append("failed AcquisitionRun must not be publication eligible")
        if good:
            errors.append("failed AcquisitionRun cannot conceal usable resource results; use partial")
    if result_status == "partial" and not (good and bad):
        errors.append("partial AcquisitionRun must represent mixed usable and failed/skipped completion")
    if result_status == "not-modified" and (not statuses or any(s != "not-modified" for s in statuses)):
        errors.append("not-modified AcquisitionRun must contain only not-modified resource results")
    if any(t.get("required") and by_target.get(t["target_key"]) and
           not any((r.get("status") == "success" and r.get("snapshot_id")) or
                   (r.get("status") == "not-modified" and r.get("previous_snapshot_id") and not r.get("snapshot_id"))
                   for r in by_target[t["target_key"]]) for t in targets) and run.get("publication_eligible"):
        errors.append("required target failure must make acquisition non-publishable")

    counts = Counter(statuses)
    expected = {
        "resource_count": len(statuses),
        "success_count": counts["success"],
        "failed_count": counts["failed"],
        "not_modified_count": counts["not-modified"],
        "skipped_count": counts["skipped"],
    }
    for key, value in expected.items():
        if run.get("metrics", {}).get(key) != value:
            errors.append(f"acquisition metrics {key} does not match resource results")
    errors.extend(timestamp_order_errors(run, label="AcquisitionRun"))
    return errors


def find_forbidden_projection_keys(value, path="$"):
    errors = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_SEARCH_PROJECTION_KEYS:
                errors.append(f"{path}.{key}: search-engine projection field contaminates canonical data")
            errors.extend(find_forbidden_projection_keys(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for i, child in enumerate(value):
            errors.extend(find_forbidden_projection_keys(child, f"{path}[{i}]"))
    return errors


def relationship_provenance_errors(records):
    errors = []
    claims = {r.get("id") for r in records if r.get("record_kind") == "claim"}
    for record in records:
        if record.get("record_kind") == "relationship" and record.get("relationship_type") in SEMANTIC_RELATIONSHIPS_REQUIRING_SUPPORT:
            support = record.get("supporting_claim_ids") or []
            if not support:
                errors.append("material semantic relationship lacks supporting Claim/Evidence")
            elif any(cid not in claims for cid in support):
                errors.append("supporting claim does not resolve in candidate corpus")
    return errors


def search_readiness_errors(records):
    errors, native = [], []
    entities = [r for r in records if r.get("record_kind") == "entity" and r.get("entity_type") == "event"]
    ids = [r["id"] for r in entities]
    if len(ids) != len(set(ids)):
        errors.append("duplicate/collapsed canonical Event identity")
    for record in entities:
        errors.extend(find_forbidden_projection_keys(record))
        for item in record.get("native_identifiers", []):
            if item.get("type") == "event_id":
                if not isinstance(item.get("value"), str):
                    errors.append("numeric Event ID must remain a lossless string")
                native.append((record, item))
    same = [(r, n) for r, n in native if n.get("value") == "4688"]
    if len(same) < 2 or len({r["id"] for r, _ in same}) < 2 or len({canonical_json(n.get("context", {})) for _, n in same}) < 2:
        errors.append("same Event ID across provider/source contexts must not be merged")
    legacy = [(r, n) for r, n in native if n.get("value") == "592"]
    if not legacy or not any(r.get("lifecycle", {}).get("state") == "legacy" for r, _ in legacy):
        errors.append("legacy Event ID must remain independently representable")
    for record, _ in same:
        if any(a.get("value") == "592" for a in record.get("aliases", [])):
            errors.append("legacy/current telemetry identities must not collapse into aliases")
    return errors


def inventory_guardrail_errors(inventory, diff):
    errors = []
    if diff.get("inventory_id") != inventory.get("inventory_id"):
        errors.append("InventoryDiff inventory_id does not resolve")
    if inventory.get("digest") != digest_without_field(inventory, "digest"):
        errors.append("AuthoritativeInventoryDefinition digest does not bind complete semantic definition")
    expected_ids = inventory.get("scope_metadata", {}).get("expected_identities")
    if isinstance(expected_ids, list) and inventory.get("expected_identity_count") != len(expected_ids):
        errors.append("expected_identity_count does not match denominator")
    for layer_name in ("raw", "parsed", "canonical"):
        layer = diff.get(layer_name, {})
        for field in ("baseline_ref", "baseline_digest", "candidate_ref", "candidate_digest"):
            if not layer.get(field):
                errors.append(f"InventoryDiff {layer_name} layer lacks {field} audit binding")
    if diff.get("diff_digest") != digest_without_field(diff, "diff_digest"):
        errors.append("InventoryDiff digest mismatch")
    before, after = diff.get("canonical", {}).get("before_count", 0), diff.get("canonical", {}).get("after_count", 0)
    shrink = ((before - after) / before * 100) if before and after < before else 0
    growth = ((after - before) / before * 100) if before and after > before else (100 if before == 0 and after > 0 else 0)
    guard, evaluation = inventory.get("guardrails", {}), diff.get("guardrail_evaluation", {})
    if shrink > guard.get("max_unexplained_shrink_percent", 0) and not evaluation.get("shrink_explained") and not evaluation.get("blocked"):
        errors.append("unexplained inventory mass shrink must be blocked")
    if growth > guard.get("max_unexplained_growth_percent", 0) and not evaluation.get("growth_explained") and not evaluation.get("blocked"):
        errors.append("unexplained inventory explosion must be blocked")
    if diff.get("not_observed_is_removed") is not False:
        errors.append("NOT_OBSERVED must never be automatically treated as REMOVED")
    return errors


def review_decision_errors(review):
    errors = []
    if review.get("review_digest") != digest_without_field(review, "review_digest"):
        errors.append("ReviewDecision digest mismatch")
    approvals = review.get("approvals", [])
    qualifying = [a for a in approvals if a.get("status") == "approved"]
    actors = [a.get("actor_ref") for a in qualifying if a.get("actor_ref")]
    distinct = set(actors)
    if len(actors) != len(distinct):
        errors.append("duplicate approval actor refs do not count twice")
    outcome = review.get("outcome")
    required = review.get("required_approvals", 0)
    if outcome in REVIEW_SUCCESS and len(distinct) < required:
        errors.append("required_approvals not satisfied by distinct qualifying actors")
    if review.get("high_risk") and (required < 2 or len(distinct) < 2):
        errors.append("high_risk review requires four-eyes approval from at least two independent actors")
    if outcome in {"rejected", "needs-changes"}:
        errors.append("rejected / needs-changes review cannot satisfy approval for promotion")
    try:
        reviewed_at = parse_datetime(review["reviewed_at"])
        for approval in approvals:
            approved_at = parse_datetime(approval["approved_at"])
            if approved_at > reviewed_at:
                errors.append("approval timestamp occurs after ReviewDecision.reviewed_at")
    except (KeyError, ValueError) as exc:
        errors.append(f"review timestamp invalid: {exc}")
    return errors


def validation_report_errors(report, review=None):
    errors = []
    gates = report.get("gates", [])
    names = [g.get("gate") for g in gates]
    if len(names) != 15 or set(names) != MANDATORY_GATES or len(names) != len(set(names)):
        errors.append("BuildValidationReport must represent exactly one each of G1 through G15")
    if any(g.get("mandatory") is not True for g in gates):
        errors.append("Ingestion Contract v1 mandatory gates cannot self-declare mandatory=false")
    failures = sum(g.get("result") != "pass" for g in gates)
    declared_failures = sum(g.get("result") == "fail" for g in gates)
    if report.get("mandatory_failures") != declared_failures:
        errors.append("mandatory_failures does not match failed gates")
    if failures and report.get("publication_eligible"):
        errors.append("mandatory validation failures cannot be waived")
    if report.get("report_digest") != digest_without_field(report, "report_digest"):
        errors.append("BuildValidationReport digest mismatch")
    g15 = next((g for g in gates if g.get("gate") == "G15"), None)
    if g15 and g15.get("result") == "pass":
        if review is None:
            errors.append("G15 PASS requires a qualifying ReviewDecision")
        else:
            review_errors = review_decision_errors(review)
            if review.get("outcome") not in REVIEW_SUCCESS or any("required_approvals" in e or "four-eyes" in e or "cannot satisfy approval" in e for e in review_errors):
                errors.append("G15 PASS is inconsistent with ReviewDecision")
            try:
                if parse_datetime(report["created_at"]) < parse_datetime(review["reviewed_at"]):
                    errors.append("review/report temporal inversion: G15 report predates ReviewDecision")
            except (KeyError, ValueError) as exc:
                errors.append(f"G15 causal timestamp invalid: {exc}")
    return errors


def build_state_errors(build):
    errors = []
    state = build.get("state")
    if build.get("manifest_digest") != digest_without_field(build, "manifest_digest"):
        errors.append("CanonicalBuildManifest digest mismatch")
    if state == "PACK_READY":
        if build.get("pack_ready") is not True:
            errors.append("PACK_READY state and flag must agree")
        if build.get("last_known_good_preserved") is not True:
            errors.append("PACK_READY must preserve Last Known Good")
    elif build.get("pack_ready") is True:
        errors.append("non-PACK_READY build cannot set pack_ready=true")
    if state in {"FAILED", "QUARANTINED", "REJECTED"} and build.get("last_known_good_preserved") is not True:
        errors.append("failed build must never replace/destroy Last Known Good")
    if state in {"FAILED", "QUARANTINED", "REJECTED"}:
        deps = [
            ("parser_run_ids", "acquisition_run_ids"),
            ("normalization_run_ids", "parser_run_ids"),
            ("inventory_definition_ids", "normalization_run_ids"),
            ("inventory_diff_id", "inventory_definition_ids"),
            ("validation_report_id", "inventory_diff_id"),
            ("review_decision_id", "validation_report_id"),
        ]
        for later, earlier in deps:
            if build.get(later) and not build.get(earlier):
                errors.append(f"{state} manifest contains impossible forward reference: {later} without {earlier}")
    return errors


def review_and_pack_ready_errors(build, report, review, diff, norm_runs, actual_candidate_digest):
    errors = []
    errors.extend(build_state_errors(build))
    errors.extend(review_decision_errors(review))
    errors.extend(validation_report_errors(report, review))
    if review.get("candidate_build_id") != build.get("build_id"):
        errors.append("ReviewDecision candidate_build_id does not resolve")
    if review.get("candidate_corpus_digest") != actual_candidate_digest:
        errors.append("candidate changed after approval; ReviewDecision is invalidated")
    if build.get("candidate_corpus_digest") != actual_candidate_digest:
        errors.append("build candidate digest does not bind actual corpus")
    if review.get("inventory_diff_id") != diff.get("inventory_diff_id") or review.get("inventory_diff_digest") != diff.get("diff_digest"):
        errors.append("ReviewDecision must bind exact inventory diff id/digest")
    if build.get("inventory_diff_id") != diff.get("inventory_diff_id") or build.get("inventory_diff_digest") != diff.get("diff_digest"):
        errors.append("CanonicalBuildManifest inventory diff id/digest binding mismatch")
    if build.get("validation_report_id") != report.get("validation_report_id") or build.get("validation_report_digest") != report.get("report_digest"):
        errors.append("CanonicalBuildManifest validation report id/digest binding mismatch")
    if build.get("review_decision_id") != review.get("review_decision_id") or build.get("review_decision_digest") != review.get("review_digest"):
        errors.append("CanonicalBuildManifest review decision id/digest binding mismatch")
    if build.get("state") == "PACK_READY":
        if report.get("publication_eligible") is not True or any(g.get("result") != "pass" for g in report.get("gates", [])):
            errors.append("mandatory validation failure/eligibility blocks PACK_READY")
        if review.get("outcome") not in REVIEW_SUCCESS or review_decision_errors(review):
            errors.append("qualifying approved review required for PACK_READY")
        if diff.get("guardrail_evaluation", {}).get("blocked"):
            errors.append("blocked inventory guardrail prevents PACK_READY")
        if any((not r.get("publishable") or r.get("identity_outcomes", {}).get("AMBIGUOUS", 0) > 0) for r in norm_runs):
            errors.append("non-publishable/AMBIGUOUS normalization prevents PACK_READY")
    return errors


def _produced_psrs(bundle):
    artifact = bundle["artifacts"].get("parsed-source-record")
    if artifact is None:
        return []
    return artifact if isinstance(artifact, list) else [artifact]


def _snapshots(bundle):
    artifact = bundle["artifacts"].get("raw-snapshot")
    if artifact is None:
        return []
    return artifact if isinstance(artifact, list) else [artifact]


def cross_stage_ri_errors(bundle):
    errors = []
    a = bundle["artifacts"]
    connector = a["connector-definition"]
    run = a["acquisition-run"]
    parser_def = a["parser-definition"]
    parser_run = a["parser-run"]
    psrs = _produced_psrs(bundle)
    snapshots = _snapshots(bundle)
    norm_def = a["normalizer-definition"]
    norm = a["normalization-run"]
    lineage = a["normalization-lineage"]
    inventory = a["inventory-definition"]
    diff = a["inventory-diff"]
    report = a["build-validation-report"]
    review = a["review-decision"]
    build = a["canonical-build-manifest"]
    support = bundle.get("canonical_support", [])
    candidates = bundle.get("canonical_candidates", [])

    sources = {r["id"]: r for r in support if r.get("record_kind") == "source"}
    source = sources.get(connector.get("source_id"))
    if source is None:
        errors.append("ConnectorDefinition.source_id does not resolve to SourceRecord")
    else:
        if connector.get("refresh_policy_ref") != "source:freshness_policy" or "freshness_policy" not in source:
            errors.append("connector refresh_policy_ref does not resolve SourceRecord freshness_policy semantics")
        if connector.get("change_detection_policy_ref") != "source:change_detection_policy" or "change_detection_policy" not in source:
            errors.append("connector change_detection_policy_ref does not resolve SourceRecord change_detection_policy semantics")
        if connector.get("retention_policy", {}).get("source_policy_field") != "redistribution.policy" or "redistribution" not in source:
            errors.append("connector retention policy does not resolve SourceRecord redistribution semantics")

    if run.get("connector_id") != connector.get("connector_id"):
        errors.append("AcquisitionRun.connector_id mismatch")
    if run.get("connector_version") != connector.get("connector_version"):
        errors.append("AcquisitionRun.connector_version mismatch")
    if run.get("source_id") != connector.get("source_id"):
        errors.append("AcquisitionRun.source_id mismatch")
    binding = connector.get("parser_binding", {})
    if binding.get("parser_id") != parser_def.get("parser_id") or binding.get("parser_version") != parser_def.get("parser_version"):
        errors.append("ConnectorDefinition parser_binding does not resolve ParserDefinition")

    declared_targets = {t["target_key"]: t for t in connector.get("targets", [])}
    snapshot_by_id = {s["snapshot_id"]: s for s in snapshots}
    rr_success = [r for r in run.get("resource_results", []) if r.get("status") == "success"]
    for rr in rr_success:
        snapshot = snapshot_by_id.get(rr.get("snapshot_id"))
        if snapshot is None:
            errors.append("successful AcquisitionRun resource_result.snapshot_id does not resolve RawSnapshot")
            continue
        if snapshot.get("acquisition_run_id") != run.get("acquisition_run_id"):
            errors.append("RawSnapshot.acquisition_run_id does not resolve AcquisitionRun")
        if snapshot.get("source_id") != run.get("source_id"):
            errors.append("RawSnapshot.source_id mismatch")
        if snapshot.get("connector_id") != run.get("connector_id"):
            errors.append("RawSnapshot.connector_id mismatch")
        if snapshot.get("connector_version") != run.get("connector_version"):
            errors.append("RawSnapshot.connector_version mismatch")
        if snapshot.get("target_key") not in declared_targets:
            errors.append("RawSnapshot.target_key does not resolve ConnectorDefinition target")
        if snapshot.get("target_key") != rr.get("target_key") or snapshot.get("resource_key") != rr.get("resource_key"):
            errors.append("RawSnapshot target/resource identity mismatch with AcquisitionRun resource_result")
        if snapshot.get("requested_resource", {}).get("uri") != rr.get("requested_uri") or snapshot.get("resolved_resource", {}).get("uri") != rr.get("resolved_uri"):
            errors.append("RawSnapshot URI identity mismatch with AcquisitionRun resource_result")

    if not snapshots:
        errors.append("RawSnapshot corpus is empty")
    else:
        snapshot = snapshots[0]
        if parser_run.get("source_snapshot_id") != snapshot.get("snapshot_id"):
            errors.append("ParserRun.source_snapshot_id does not resolve RawSnapshot")
        if parser_run.get("input_blob_digest") != snapshot.get("raw_content_digest"):
            errors.append("ParserRun.input_blob_digest does not bind RawSnapshot raw_content_digest")

    if parser_run.get("parser_id") != parser_def.get("parser_id") or parser_run.get("parser_version") != parser_def.get("parser_version"):
        errors.append("ParserRun parser_id/version do not resolve ParserDefinition")
    for psr in psrs:
        if psr.get("parser_id") != parser_def.get("parser_id") or psr.get("parser_version") != parser_def.get("parser_version"):
            errors.append("ParsedSourceRecord parser_id/version do not resolve ParserDefinition")
        if psr.get("parser_id") != parser_run.get("parser_id") or psr.get("parser_version") != parser_run.get("parser_version"):
            errors.append("ParsedSourceRecord parser_id/version do not resolve ParserRun")
        if psr.get("psr_version") != parser_run.get("psr_version"):
            errors.append("ParserRun.psr_version mismatch with ParsedSourceRecord")
        if psr.get("source_snapshot_id") not in snapshot_by_id:
            errors.append("ParsedSourceRecord source_snapshot_id does not resolve")
    if parser_run.get("output_record_count") != len(psrs):
        errors.append("ParserRun.output_record_count does not match produced PSR count")
    rep = sha256_digest(sorted(
        [{"parsed_record_id": p["parsed_record_id"], "record_digest": p["record_digest"]} for p in psrs],
        key=lambda x: x["parsed_record_id"]))
    if parser_run.get("representation_digest") != rep:
        errors.append("ParserRun.representation_digest does not bind deterministic produced PSR set")
    errors.extend(timestamp_order_errors(parser_run, label="ParserRun"))

    if norm.get("parser_run_id") != parser_run.get("parser_run_id"):
        errors.append("NormalizationRun.parser_run_id does not resolve ParserRun")
    if norm.get("normalizer_id") != norm_def.get("normalizer_id") or norm.get("normalizer_version") != norm_def.get("normalizer_version"):
        errors.append("NormalizationRun normalizer_id/version do not resolve NormalizerDefinition")
    expected_psr_version = parser_run.get("psr_version")
    if norm.get("psr_version") != expected_psr_version or norm_def.get("psr_version") != expected_psr_version or any(p.get("psr_version") != expected_psr_version for p in psrs):
        errors.append("NormalizationRun psr_version is incompatible with parser/PSR/NormalizerDefinition")
    if lineage.get("normalizer_id") != norm.get("normalizer_id") or lineage.get("normalizer_version") != norm.get("normalizer_version"):
        errors.append("NormalizationLineage normalizer binding mismatch")
    if lineage.get("mapping_profile") != norm.get("mapping_profile"):
        errors.append("NormalizationLineage mapping_profile mismatch")
    psr_ids = {p["parsed_record_id"] for p in psrs}
    if any(x not in psr_ids for x in lineage.get("parsed_record_ids", [])):
        errors.append("NormalizationLineage parsed_record_ids contain unresolved PSR")
    snapshot_ids = set(snapshot_by_id)
    if any(x not in snapshot_ids for x in lineage.get("source_snapshot_ids", [])):
        errors.append("NormalizationLineage source_snapshot_ids contain unresolved RawSnapshot")
    candidate_ids = {r["id"] for r in candidates}
    if lineage.get("output_record_id") not in candidate_ids:
        errors.append("NormalizationLineage output_record_id does not resolve canonical candidate")
    expected_counts = Counter(RECORD_KIND_TO_COUNT.get(r.get("record_kind"), r.get("record_kind")) for r in candidates)
    if dict(expected_counts) != norm.get("output_counts"):
        errors.append("NormalizationRun.output_counts do not match candidate corpus")
    actual_candidate_digest = sha256_digest(sorted(candidates, key=lambda r: r["id"]))
    if norm.get("canonical_candidate_digest") != actual_candidate_digest:
        errors.append("NormalizationRun candidate digest mismatch")
    errors.extend(timestamp_order_errors(norm, label="NormalizationRun"))

    if report.get("build_id") != build.get("build_id"):
        errors.append("BuildValidationReport.build_id mismatch")
    if build.get("inventory_diff_id") != diff.get("inventory_diff_id"):
        errors.append("CanonicalBuildManifest.inventory_diff_id mismatch")
    if build.get("inventory_diff_digest") != diff.get("diff_digest"):
        errors.append("CanonicalBuildManifest.inventory_diff_digest mismatch")
    if build.get("validation_report_id") != report.get("validation_report_id"):
        errors.append("CanonicalBuildManifest.validation_report_id mismatch")
    if build.get("validation_report_digest") != report.get("report_digest"):
        errors.append("CanonicalBuildManifest.validation_report_digest mismatch")
    if build.get("review_decision_id") != review.get("review_decision_id"):
        errors.append("CanonicalBuildManifest.review_decision_id mismatch")
    if build.get("review_decision_digest") != review.get("review_digest"):
        errors.append("CanonicalBuildManifest.review_decision_digest mismatch")

    actual_source_ids = {run.get("source_id")}
    if set(build.get("source_ids", [])) != actual_source_ids or any(s not in sources for s in build.get("source_ids", [])):
        errors.append("CanonicalBuildManifest source_ids do not resolve exact acquisition sources")
    if set(build.get("acquisition_run_ids", [])) != {run.get("acquisition_run_id")}:
        errors.append("CanonicalBuildManifest acquisition_run_ids do not resolve exact supplied AcquisitionRun")
    if set(build.get("parser_run_ids", [])) != {parser_run.get("parser_run_id")}:
        errors.append("CanonicalBuildManifest parser_run_ids do not resolve exact supplied ParserRun")
    if set(build.get("normalization_run_ids", [])) != {norm.get("normalization_run_id")}:
        errors.append("CanonicalBuildManifest normalization_run_ids do not resolve exact supplied NormalizationRun")
    if set(build.get("inventory_definition_ids", [])) != {inventory.get("inventory_id")}:
        errors.append("CanonicalBuildManifest inventory_definition_ids do not resolve exact supplied inventory")

    raw_layer, parsed_layer, canonical_layer = diff.get("raw", {}), diff.get("parsed", {}), diff.get("canonical", {})
    if snapshots and (raw_layer.get("candidate_ref") != snapshots[0].get("snapshot_id") or raw_layer.get("candidate_digest") != snapshots[0].get("raw_content_digest")):
        errors.append("InventoryDiff raw candidate audit binding mismatch")
    if parsed_layer.get("candidate_ref") != parser_run.get("parser_run_id") or parsed_layer.get("candidate_digest") != parser_run.get("representation_digest"):
        errors.append("InventoryDiff parsed candidate audit binding mismatch")
    if canonical_layer.get("candidate_ref") != build.get("build_id") or canonical_layer.get("candidate_digest") != actual_candidate_digest:
        errors.append("InventoryDiff canonical candidate audit binding mismatch")
    if build.get("previous_last_known_good_build_id") and canonical_layer.get("baseline_ref") != build.get("previous_last_known_good_build_id"):
        errors.append("InventoryDiff canonical baseline does not bind Last Known Good build")

    for claim in [r for r in candidates if r.get("record_kind") == "claim"]:
        for evidence in claim.get("evidence", []):
            if evidence.get("source_snapshot_id") not in snapshot_ids:
                errors.append("Claim Evidence.source_snapshot_id does not resolve to RawSnapshot")
            if evidence.get("source_id") not in sources:
                errors.append("Claim Evidence.source_id does not resolve")
            source_snapshot = snapshot_by_id.get(evidence.get("source_snapshot_id"))
            if source_snapshot and evidence.get("source_version") != source_snapshot.get("source_version"):
                errors.append("Claim Evidence source_version mismatch")

    try:
        acq_finish = parse_datetime(run["finished_at"])
        parser_start = parse_datetime(parser_run["started_at"])
        parser_finish = parse_datetime(parser_run["finished_at"])
        norm_start = parse_datetime(norm["started_at"])
        norm_finish = parse_datetime(norm["finished_at"])
        review_time = parse_datetime(review["reviewed_at"])
        report_time = parse_datetime(report["created_at"])
        build_time = parse_datetime(build["created_at"])
        if parser_start < acq_finish:
            errors.append("ParserRun starts before AcquisitionRun finished")
        if norm_start < parser_finish:
            errors.append("NormalizationRun starts before ParserRun finished")
        if review_time < norm_finish:
            errors.append("ReviewDecision predates completed normalization")
        if report_time < review_time:
            errors.append("review/report temporal inversion")
        if build_time < report_time:
            errors.append("CanonicalBuildManifest created before validation report")
    except (KeyError, ValueError) as exc:
        errors.append(f"cross-stage timestamp invalid: {exc}")

    return errors


def tracked_repository_hygiene_errors(tracked_paths):
    errors = []
    temp_suffixes = (".tmp", ".bak", ".orig", ".rej", ".pyc", "~")
    sensitive_suffixes = {".pem", ".key", ".pfx", ".p12"}
    sensitive_names = {".env", "id_rsa", "id_ed25519", ".secrets"}
    for raw in tracked_paths:
        path = PurePosixPath(str(raw).replace("\\", "/"))
        parts = {p.lower() for p in path.parts}
        name = path.name.lower()
        if "__pycache__" in parts or ".pytest_cache" in parts:
            errors.append(f"tracked temporary/generated artifact detected: {path}")
        if name.endswith(temp_suffixes):
            errors.append(f"tracked temporary/checkpoint file detected: {path}")
        if path.suffix.lower() in sensitive_suffixes or name in sensitive_names:
            errors.append(f"tracked sensitive filename detected: {path}")
    return errors


def repository_hygiene_errors(tracked_paths):
    """Backward-compatible public helper; hygiene is evaluated only on tracked paths."""
    return tracked_repository_hygiene_errors(tracked_paths)


def _git_tracked_paths(root: Path):
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True, capture_output=True, text=False,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"unable to enumerate Git-tracked paths: {exc}") from exc
    return [p.decode("utf-8") for p in proc.stdout.split(b"\0") if p]


def _format_schema_errors(name, validator, record):
    return [f"{name}: {e.message}" for e in validator.iter_errors(record)]


def validate_repository(root: Path | None = None):
    if root is not None:
        _set_root(Path(root))
    errors = []

    try:
        _, ingest_schemas = load_schema_store(INGESTION_SCHEMA_DIR, INGESTION_SCHEMA_URI_BASE)
        roots = {n for n in ingest_schemas if "/" not in n}
        if roots != EXPECTED_ROOT_SCHEMAS:
            errors.append(f"ingestion schema discovery mismatch: {sorted(roots ^ EXPECTED_ROOT_SCHEMAS)}")
        if ingest_schemas.get("defs/common.schema.json", {}).get("$defs", {}).get("contract_version", {}).get("const") != INGESTION_CONTRACT_VERSION:
            errors.append("ingestion contract version is not pinned independently")
    except Exception as exc:
        errors.append(f"ingestion schema discovery/URI policy failed: {exc}")

    try:
        _, canonical_schemas = load_schema_store(CANONICAL_SCHEMA_DIR, CANONICAL_SCHEMA_URI_BASE)
        atlas_root = canonical_schemas["atlas-record.schema.json"]
        refs = {x["$ref"].rsplit("/", 1)[-1] for x in atlas_root.get("oneOf", [])}
        if len(atlas_root.get("oneOf", [])) != 7 or refs != CANONICAL_FAMILY_REFS:
            errors.append("AtlasRecord must remain exactly seven canonical families")
        if any("/schemas/ingestion/" in ref for schema in canonical_schemas.values() for ref in walk_refs(schema)):
            errors.append("canonical schemas/v1 must not depend on ingestion schemas")
    except Exception as exc:
        errors.append(f"canonical schema authority invalid: {exc}")

    if not BUNDLE_PATH.is_file():
        errors.append("missing fixtures/phase-5.3/foundation-valid.json")
        return errors
    bundle = load_fixture_bundle()
    artifacts = bundle_artifacts(bundle)
    for fixture, schema in ARTIFACT_SCHEMA_MAP.items():
        if fixture not in artifacts:
            errors.append(f"missing artifact fixture: {fixture}")
            continue
        try:
            errors.extend(_format_schema_errors(fixture, ingestion_validator(schema), artifacts[fixture]))
        except Exception as exc:
            errors.append(f"{fixture}: validator setup failed: {exc}")
    errors.extend(duplicate_identity_errors([(name, rec, IDENTITY_FIELDS[name]) for name, rec in artifacts.items() if name in IDENTITY_FIELDS]))
    for name, artifact in artifacts.items():
        errors.extend(f"{name}:{e}" for e in validate_json_secret_surface(artifact))

    if set(artifacts) == set(ARTIFACT_SCHEMA_MAP):
        connector = artifacts["connector-definition.json"]
        run = artifacts["acquisition-run.json"]
        policy = connector["security_policy"]
        if policy["tls_verify"] is not True or policy["block_private_destinations"] is not True or not policy["allowed_hosts"]:
            errors.append("public connector security policy must fail closed")
        for key in ("max_response_bytes", "max_decompressed_bytes", "max_archive_entries", "max_compression_ratio", "connect_timeout_seconds", "read_timeout_seconds"):
            if not policy.get(key):
                errors.append("public connector acquisition limits must be bounded")
        for target in connector["targets"]:
            errors.extend(public_uri_errors(target["resource_uri"], policy["allowed_hosts"], target.get("allowed_path_prefixes")))
        if any(policy["git_safety"].values()):
            errors.append("Git acquisition must remain data-only")
        errors.extend(acquisition_semantic_errors(connector, run))

        snapshots = _snapshots(bundle)
        for snapshot in snapshots:
            raw_path = FIXTURE_DIR / "raw" / snapshot["resource_key"]
            if raw_path.is_file():
                raw = raw_path.read_bytes()
                if sha256_digest(raw) != snapshot["raw_content_digest"] or len(raw) != snapshot["byte_length"]:
                    errors.append("RawSnapshot must bind exact raw bytes")
            expected_snapshot_id = stable_artifact_id("raw-snapshot", {
                "acquisition_run_id": snapshot["acquisition_run_id"], "target_key": snapshot["target_key"],
                "resource_key": snapshot["resource_key"], "raw_content_digest": snapshot["raw_content_digest"],
            })
            if snapshot["snapshot_id"] != expected_snapshot_id or snapshot["blob_ref"] != "blob:" + snapshot["raw_content_digest"]:
                errors.append("RawSnapshot identity/content addressing mismatch")
            for loc in (snapshot["requested_resource"], snapshot["resolved_resource"]):
                errors.extend(public_uri_errors(loc["uri"], policy["allowed_hosts"], connector["targets"][0].get("allowed_path_prefixes")))

        parser_def, psrs = artifacts["parser-definition.json"], _produced_psrs(bundle)
        if parser_def["unknown_field_policy"] != "preserve-and-report":
            errors.append("unknown structured fields must be preserved + reported")
        sec = parser_def["security_policy"]
        forbidden = ("network_access", "dns_access", "http_access", "git_access", "source_execution", "javascript_execution", "xml_external_entities", "dtd_external_resolution", "macros", "ai_enabled")
        if any(sec[k] is not False for k in forbidden):
            errors.append("parser must be offline/non-executing/XXE-safe/AI-free")
        for psr in psrs:
            psr_payload = {k: psr.get(k) for k in ("native_type", "native_key", "native_identifiers", "native_fields", "unknown_fields", "locator")}
            if psr["record_digest"] != sha256_digest(psr_payload):
                errors.append("ParsedSourceRecord deterministic digest mismatch")
            expected_psr_id = stable_artifact_id("parsed-source-record", {
                "source_snapshot_id": psr["source_snapshot_id"], "parser_id": psr["parser_id"],
                "parser_version": psr["parser_version"], "psr_version": psr["psr_version"],
                "native_type": psr["native_type"], "native_key": psr.get("native_key"), "record_digest": psr["record_digest"],
            })
            if psr["parsed_record_id"] != expected_psr_id:
                errors.append("ParsedSourceRecord identity is not deterministic")

        mapping = load_json(FIXTURE_DIR / "mapping-profile.json")
        registry_pin = load_json(FIXTURE_DIR / "registry-bundle-pin.json")
        if mapping["digest"] != digest_without_field(mapping, "digest") or registry_pin["digest"] != digest_without_field(registry_pin, "digest"):
            errors.append("mapping/registry pin digest mismatch")
        norm_def, norm = artifacts["normalizer-definition.json"], artifacts["normalization-run.json"]
        if norm_def["network_access"] is not False or norm_def["ai_enabled"] is not False:
            errors.append("normalizer must be deterministic/offline/AI-free")
        if norm["mapping_profile"] != {"id": mapping["id"], "version": mapping["version"], "digest": mapping["digest"]}:
            errors.append("normalization must pin mapping version+digest")
        if norm["registry_bundle"]["version"] != registry_pin["version"] or norm["registry_bundle"]["digest"] != registry_pin["digest"] or norm["canonical_schema_version"] != CANONICAL_SCHEMA_VERSION:
            errors.append("normalization must pin registry+canonical schema context")
        if norm["identity_outcomes"]["AMBIGUOUS"] > 0 and norm["publishable"]:
            errors.append("AMBIGUOUS normalization cannot be publishable")

        support, candidates, search = bundle["canonical_support"], bundle["canonical_candidates"], bundle["search_readiness"]
        try:
            canonical = canonical_root_validator()
            for record in support + candidates + search:
                errors.extend(_format_schema_errors(record.get("id", "canonical-fixture"), canonical, record))
            if canonical.is_valid(connector):
                errors.append("ingestion artifact accepted as eighth AtlasRecord")
        except Exception as exc:
            errors.append(f"canonical fixture validation failed: {exc}")
        registries = load_registries()
        for record in support + candidates + search:
            errors.extend(find_forbidden_projection_keys(record))
            if record.get("record_kind") == "entity":
                if record.get("entity_type") not in registries.get("entity-types", set()) or record.get("namespace") not in registries.get("namespaces", set()):
                    errors.append("canonical fixture registry mismatch")
                if any(n.get("type") not in registries.get("native-identifier-types", set()) for n in record.get("native_identifiers", [])):
                    errors.append("native identifier type is not registered")
            if record.get("record_kind") == "claim" and record.get("predicate") not in registries.get("claim-predicates", set()):
                errors.append("claim predicate is not registered")
        errors.extend(relationship_provenance_errors(candidates))
        errors.extend(search_readiness_errors(search))

        lineage = artifacts["normalization-lineage.json"]
        expected_lineage = stable_artifact_id("normalization-lineage", {k: v for k, v in lineage.items() if k not in {"lineage_id", "lineage_digest"}})
        if lineage["lineage_id"] != expected_lineage or lineage["lineage_digest"] != digest_without_field(lineage, "lineage_digest"):
            errors.append("NormalizationLineage deterministic identity/digest mismatch")

        inventory, diff = artifacts["inventory-definition.json"], artifacts["inventory-diff.json"]
        errors.extend(inventory_guardrail_errors(inventory, diff))
        report, review, build = artifacts["build-validation-report.json"], artifacts["review-decision.json"], artifacts["canonical-build-manifest.json"]
        actual_candidate_digest = sha256_digest(sorted(candidates, key=lambda r: r["id"]))
        errors.extend(review_and_pack_ready_errors(build, report, review, diff, [norm], actual_candidate_digest))
        errors.extend(cross_stage_ri_errors(bundle))

    try:
        tracked = _git_tracked_paths(ROOT)
        errors.extend(tracked_repository_hygiene_errors(tracked))
        for path in tracked:
            pp = PurePosixPath(path)
            if len(pp.parts) >= 3 and pp.parts[0] == "ingestion" and pp.parts[1] in {"connectors", "parsers", "normalizers"} and pp.name != "README.md":
                errors.append(f"broad/live ingestion implementation is not authorized: {path}")
    except RuntimeError as exc:
        errors.append(str(exc))

    for path in FIXTURE_DIR.rglob("*"):
        if path.is_file() and path.stat().st_size > 131072:
            errors.append(f"Phase 5.3 fixture unexpectedly large: {path.relative_to(ROOT)}")
    return errors


def main():
    errors = validate_repository()
    if errors:
        for error in errors:
            print(error)
        print(f"Phase 5.3.1 ingestion foundation validation FAILED with {len(errors)} error(s).")
        return 1
    print("Atlas Phase 5.3.1 ingestion foundation validation passed.")
    print("Ingestion contract 1.0.0; canonical schema remains 1.0.0 with seven AtlasRecord families; terminal boundary is PACK_READY.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
