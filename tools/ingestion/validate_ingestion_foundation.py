#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path, PurePosixPath
from urllib.parse import urlparse, parse_qsl
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
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"), re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
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
    expected_required = {t["target_key"]: t["required"] for t in connector["targets"]}
    required_failure = optional_failure = False
    for resource in run["resource_results"]:
        if resource["target_key"] in expected_required and resource["required"] != expected_required[resource["target_key"]]:
            errors.append("resource required flag conflicts with connector target")
        if resource["status"] == "failed":
            required_failure |= resource["required"]
            optional_failure |= not resource["required"]
        if resource["status"] == "not-modified":
            if resource.get("snapshot_id"):
                errors.append("HTTP not-modified must not create a fake new snapshot")
            if not resource.get("previous_snapshot_id"):
                errors.append("not-modified resource must reference previous valid snapshot")
    if required_failure and run["publication_eligible"]:
        errors.append("required target failure must make acquisition non-publishable")
    if run["result_status"] == "partial" and not (required_failure or optional_failure):
        errors.append("partial run must represent a failed resource")
    statuses = [r["status"] for r in run["resource_results"]]
    expected = {"resource_count": len(statuses), "success_count": statuses.count("success"),
                "failed_count": statuses.count("failed"), "not_modified_count": statuses.count("not-modified")}
    for key, value in expected.items():
        if run["metrics"].get(key) != value:
            errors.append(f"acquisition metrics {key} does not match resource results")
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
    if diff["inventory_id"] != inventory["inventory_id"]:
        errors.append("InventoryDiff inventory_id does not resolve")
    expected_digest = sha256_digest({"inventory_source_version": inventory["inventory_source_version"], "scope_metadata": inventory["scope_metadata"]})
    if inventory["digest"] != expected_digest:
        errors.append("AuthoritativeInventoryDefinition digest does not bind denominator")
    expected_ids = inventory.get("scope_metadata", {}).get("expected_identities")
    if isinstance(expected_ids, list) and inventory["expected_identity_count"] != len(expected_ids):
        errors.append("expected_identity_count does not match denominator")
    if diff["diff_digest"] != digest_without_field(diff, "diff_digest"):
        errors.append("InventoryDiff digest mismatch")
    before, after = diff["canonical"]["before_count"], diff["canonical"]["after_count"]
    shrink = ((before - after) / before * 100) if before and after < before else 0
    growth = ((after - before) / before * 100) if before and after > before else (100 if before == 0 and after > 0 else 0)
    guard, evaluation = inventory["guardrails"], diff["guardrail_evaluation"]
    if shrink > guard["max_unexplained_shrink_percent"] and not evaluation["shrink_explained"] and not evaluation["blocked"]:
        errors.append("unexplained inventory mass shrink must be blocked")
    if growth > guard["max_unexplained_growth_percent"] and not evaluation["growth_explained"] and not evaluation["blocked"]:
        errors.append("unexplained inventory explosion must be blocked")
    if diff["not_observed_is_removed"] is not False:
        errors.append("NOT_OBSERVED must never be automatically treated as REMOVED")
    return errors


def validation_report_errors(report):
    errors = []
    names = [g["gate"] for g in report["gates"]]
    if len(names) != 15 or set(names) != {f"G{i}" for i in range(1, 16)}:
        errors.append("BuildValidationReport must represent exactly G1 through G15")
    failures = sum(g["mandatory"] and g["result"] == "fail" for g in report["gates"])
    if report["mandatory_failures"] != failures:
        errors.append("mandatory_failures does not match gates")
    if failures and report["publication_eligible"]:
        errors.append("mandatory validation failures cannot be waived")
    if report["report_digest"] != digest_without_field(report, "report_digest"):
        errors.append("BuildValidationReport digest mismatch")
    return errors


def review_and_pack_ready_errors(build, report, review, diff, norm_runs, actual_candidate_digest):
    errors = []
    if review["review_digest"] != digest_without_field(review, "review_digest"):
        errors.append("ReviewDecision digest mismatch")
    if build["manifest_digest"] != digest_without_field(build, "manifest_digest"):
        errors.append("CanonicalBuildManifest digest mismatch")
    if review["candidate_build_id"] != build["build_id"]:
        errors.append("ReviewDecision candidate_build_id does not resolve")
    if review["candidate_corpus_digest"] != actual_candidate_digest:
        errors.append("candidate changed after approval; ReviewDecision is invalidated")
    if build["candidate_corpus_digest"] != actual_candidate_digest:
        errors.append("build candidate digest does not bind actual corpus")
    if review["inventory_diff_id"] != diff["inventory_diff_id"] or review["inventory_diff_digest"] != diff["diff_digest"]:
        errors.append("ReviewDecision must bind exact inventory diff id/digest")
    if build["inventory_diff_digest"] != diff["diff_digest"] or build["validation_report_digest"] != report["report_digest"] or build["review_decision_digest"] != review["review_digest"]:
        errors.append("CanonicalBuildManifest digest binding mismatch")
    success_review = review["outcome"] in {"approved", "approved-with-exceptions"}
    if build["pack_ready"] or build["state"] == "PACK_READY":
        if build["state"] != "PACK_READY" or build["pack_ready"] is not True:
            errors.append("PACK_READY state and flag must agree")
        if report["mandatory_failures"] or not report["publication_eligible"]:
            errors.append("mandatory validation failure/eligibility blocks PACK_READY")
        if not success_review:
            errors.append("approved review required for PACK_READY")
        if diff["guardrail_evaluation"]["blocked"]:
            errors.append("blocked inventory guardrail prevents PACK_READY")
        if not build["last_known_good_preserved"]:
            errors.append("PACK_READY must preserve Last Known Good")
        if any((not r["publishable"] or r["identity_outcomes"]["AMBIGUOUS"] > 0) for r in norm_runs):
            errors.append("non-publishable/AMBIGUOUS normalization prevents PACK_READY")
    if build["state"] in {"FAILED", "QUARANTINED", "REJECTED"} and not build["last_known_good_preserved"]:
        errors.append("failed build must never replace/destroy Last Known Good")
    return errors


def _format_schema_errors(name, validator, record):
    return [f"{name}: {e.message}" for e in validator.iter_errors(record)]


def git_tracked_paths(root: Path | None = None):
    root = Path(root or ROOT)
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return [PurePosixPath(p) for p in result.stdout.decode("utf-8").split("\0") if p]


def repository_hygiene_errors(tracked_paths):
    errors = []
    temp_suffixes = (".tmp", ".bak", ".orig", ".rej", ".pyc", "~")
    sensitive_suffixes = {".pem", ".key", ".pfx", ".p12"}
    sensitive_names = {".env", "id_rsa", "id_ed25519", ".secrets"}
    for raw_path in tracked_paths:
        path = PurePosixPath(str(raw_path).replace("\\", "/"))
        lowered_parts = {part.lower() for part in path.parts}
        lower_name = path.name.lower()
        if "__pycache__" in lowered_parts or ".pytest_cache" in lowered_parts:
            errors.append(f"tracked temporary/generated artifact detected: {path.as_posix()}")
        if lower_name.endswith(temp_suffixes):
            errors.append(f"tracked temporary/checkpoint file detected: {path.as_posix()}")
        if path.suffix.lower() in sensitive_suffixes or lower_name in sensitive_names:
            errors.append(f"tracked sensitive filename detected: {path.as_posix()}")
    return errors


def validate_repository(root: Path | None = None):
    global ROOT, INGESTION_SCHEMA_DIR, CANONICAL_SCHEMA_DIR, FIXTURE_DIR, BUNDLE_PATH, REGISTRY_DIR
    if root is not None:
        ROOT = Path(root)
        INGESTION_SCHEMA_DIR = ROOT / "schemas" / "ingestion" / "v1"
        CANONICAL_SCHEMA_DIR = ROOT / "schemas" / "v1"
        FIXTURE_DIR = ROOT / "fixtures" / "phase-5.3"
        BUNDLE_PATH = FIXTURE_DIR / "foundation-valid.json"
        REGISTRY_DIR = ROOT / "model" / "registries"
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
        errors.extend(acquisition_semantic_errors(connector, artifacts["acquisition-run.json"]))

        snapshot = artifacts["raw-snapshot.json"]
        raw_path = FIXTURE_DIR / "raw" / snapshot["resource_key"]
        if raw_path.is_file():
            raw = raw_path.read_bytes()
            if sha256_digest(raw) != snapshot["raw_content_digest"] or len(raw) != snapshot["byte_length"]:
                errors.append("RawSnapshot must bind exact raw bytes")
        expected_snapshot_id = stable_artifact_id("raw-snapshot", {"acquisition_run_id": snapshot["acquisition_run_id"], "target_key": snapshot["target_key"], "resource_key": snapshot["resource_key"], "raw_content_digest": snapshot["raw_content_digest"]})
        if snapshot["snapshot_id"] != expected_snapshot_id or snapshot["blob_ref"] != "blob:" + snapshot["raw_content_digest"]:
            errors.append("RawSnapshot identity/content addressing mismatch")
        if snapshot["acquisition_run_id"] != artifacts["acquisition-run.json"]["acquisition_run_id"]:
            errors.append("RawSnapshot acquisition run does not resolve")
        for loc in (snapshot["requested_resource"], snapshot["resolved_resource"]):
            errors.extend(public_uri_errors(loc["uri"], policy["allowed_hosts"], connector["targets"][0].get("allowed_path_prefixes")))

        parser_def, parser_run, psr = artifacts["parser-definition.json"], artifacts["parser-run.json"], artifacts["parsed-source-record.json"]
        if parser_def["unknown_field_policy"] != "preserve-and-report":
            errors.append("unknown structured fields must be preserved + reported")
        sec = parser_def["security_policy"]
        forbidden = ("network_access", "dns_access", "http_access", "git_access", "source_execution", "javascript_execution", "xml_external_entities", "dtd_external_resolution", "macros", "ai_enabled")
        if any(sec[k] is not False for k in forbidden):
            errors.append("parser must be offline/non-executing/XXE-safe/AI-free")
        if parser_run["source_snapshot_id"] != snapshot["snapshot_id"] or psr["source_snapshot_id"] != snapshot["snapshot_id"]:
            errors.append("parser/PSR snapshot linkage broken")
        if parser_run["parser_id"] != parser_def["parser_id"] or psr["parser_id"] != parser_def["parser_id"]:
            errors.append("parser definition linkage broken")
        psr_payload = {k: psr.get(k) for k in ("native_type", "native_key", "native_identifiers", "native_fields", "unknown_fields", "locator")}
        if psr["record_digest"] != sha256_digest(psr_payload):
            errors.append("ParsedSourceRecord deterministic digest mismatch")
        expected_psr_id = stable_artifact_id("parsed-source-record", {"source_snapshot_id": psr["source_snapshot_id"], "parser_id": psr["parser_id"], "parser_version": psr["parser_version"], "psr_version": psr["psr_version"], "native_type": psr["native_type"], "native_key": psr.get("native_key"), "record_digest": psr["record_digest"]})
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
        actual_candidate_digest = sha256_digest(sorted(candidates, key=lambda r: r["id"]))
        if norm["canonical_candidate_digest"] != actual_candidate_digest:
            errors.append("normalization candidate digest mismatch")

        lineage = artifacts["normalization-lineage.json"]
        if psr["parsed_record_id"] not in lineage["parsed_record_ids"] or snapshot["snapshot_id"] not in lineage["source_snapshot_ids"]:
            errors.append("NormalizationLineage cross-stage linkage broken")
        expected_lineage = stable_artifact_id("normalization-lineage", {k: v for k, v in lineage.items() if k not in {"lineage_id", "lineage_digest"}})
        if lineage["lineage_id"] != expected_lineage or lineage["lineage_digest"] != digest_without_field(lineage, "lineage_digest"):
            errors.append("NormalizationLineage deterministic identity/digest mismatch")

        inventory, diff = artifacts["inventory-definition.json"], artifacts["inventory-diff.json"]
        errors.extend(inventory_guardrail_errors(inventory, diff))
        report, review, build = artifacts["build-validation-report.json"], artifacts["review-decision.json"], artifacts["canonical-build-manifest.json"]
        errors.extend(validation_report_errors(report))
        errors.extend(review_and_pack_ready_errors(build, report, review, diff, [norm], actual_candidate_digest))

        snapshots = {snapshot["snapshot_id"]}
        sources = {r["id"] for r in support if r.get("record_kind") == "source"}
        for claim in [r for r in candidates if r.get("record_kind") == "claim"]:
            for evidence in claim.get("evidence", []):
                if evidence.get("source_snapshot_id") not in snapshots:
                    errors.append("Claim Evidence.source_snapshot_id does not resolve to RawSnapshot")
                if evidence.get("source_id") not in sources:
                    errors.append("Claim Evidence.source_id does not resolve")
                if evidence.get("source_version") != snapshot["source_version"]:
                    errors.append("Claim Evidence source_version mismatch")

        if artifacts["acquisition-run.json"]["acquisition_run_id"] not in build["acquisition_run_ids"] or parser_run["parser_run_id"] not in build["parser_run_ids"] or norm["normalization_run_id"] not in build["normalization_run_ids"] or inventory["inventory_id"] not in build["inventory_definition_ids"]:
            errors.append("CanonicalBuildManifest stage linkage incomplete")

    tracked_paths = git_tracked_paths(ROOT)
    if tracked_paths is None:
        errors.append("repository hygiene validation requires readable Git tracked-path context")
    else:
        errors.extend(repository_hygiene_errors(tracked_paths))
    for path in FIXTURE_DIR.rglob("*"):
        if path.is_file() and path.stat().st_size > 131072:
            errors.append(f"Phase 5.3 fixture unexpectedly large: {path.relative_to(ROOT)}")
    for sub in ("connectors", "parsers", "normalizers"):
        directory = ROOT / "ingestion" / sub
        if directory.exists():
            for path in directory.iterdir():
                if path.is_file() and path.name != "README.md":
                    errors.append(f"broad/live ingestion implementation is not authorized: {path.relative_to(ROOT)}")
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
