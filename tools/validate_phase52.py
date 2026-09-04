#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse, parse_qsl
from datetime import datetime
import copy
import hashlib
import json
import re
import sys

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas" / "v1"
FIXTURE_DIR = ROOT / "fixtures" / "phase-5.2"
REGISTRY_DIR = ROOT / "model" / "registries"
MIGRATION_MAP = ROOT / "migrations" / "phase-5.1-to-v1" / "migration-map.json"

SCHEMA_VERSION = "1.0.0"
SCHEMA_URI_BASE = "https://raw.githubusercontent.com/cyber-sentinel/Cyber-Sentinel-Atlas/main/schemas/v1/"
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
CANONICAL_ID_RE = re.compile(r"^atlas:([a-z0-9-]+):([a-z0-9-]+(?:\.[a-z0-9-]+)*):([a-z0-9][a-z0-9._-]*)$")
SHA_KEY_RE = re.compile(r"^sha256-[a-f0-9]{64}$")

REQUIRED_REGISTRIES = {
    "entity-types",
    "namespaces",
    "relationship-types",
    "native-identifier-types",
    "claim-predicates",
    "alias-kinds",
}
TELEMETRY_ENTITY_TYPES = {
    "event",
    "audit-record",
    "audit-action",
    "operation",
    "activity",
    "finding",
    "flow-record",
}
VERSION_CONSTRAINT_SUBJECT_TYPES = {
    "platform",
    "product",
    "telemetry-provider",
    "technology",
}
AUTHORITATIVE_TRANSFORMATIONS = {
    "direct-structured-import",
    "normalized-fact",
}
SUSPICIOUS_QUERY_KEYS = {
    "token",
    "access_token",
    "api_key",
    "apikey",
    "key",
    "sig",
    "signature",
    "session",
    "sessionid",
    "x-amz-signature",
    "x-amz-credential",
    "x-goog-signature",
}
SEMANTIC_RELATIONSHIPS_REQUIRING_SUPPORT = {
    "INDICATES",
    "RELATED_TO",
    "EQUIVALENT_SIGNAL",
    "PRECEDES",
    "FOLLOWS",
    "MAPS_TO_ATTACK",
    "COUNTERED_BY",
    "DETECTED_BY",
    "HUNTED_BY",
    "INVESTIGATED_BY",
    "RESPONDED_BY",
    "REQUIRES_TELEMETRY",
    "DERIVED_FROM",
    "SUPPORTED_BY",
    "SUPERSEDES",
    "SUPERSEDED_BY",
    "VERSION_OF",
    "VALIDATED_BY",
}
STRUCTURAL_RELATIONSHIPS = {
    "RUNS_ON",
    "EMITS",
    "HAS_FIELD",
    "HAS_TELEMETRY_PROVIDER",
    "HAS_TELEMETRY_SOURCE",
}


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def normalize_applicability(value):
    if not value:
        return None
    out = copy.deepcopy(value)
    for key in (
        "platform_ids",
        "product_ids",
        "provider_ids",
        "version_ids",
        "explanatory_claim_ids",
    ):
        if key in out:
            out[key] = sorted(out[key])
    if "version_constraints" in out:
        out["version_constraints"] = sorted(out["version_constraints"], key=canonical_json)
    return out


def claim_semantic_payload(record):
    payload = {
        "subject_id": record["subject_id"],
        "predicate": record["predicate"],
        "object": record["object"],
    }
    if record.get("applicability"):
        payload["applicability"] = normalize_applicability(record["applicability"])
    return payload


def relationship_semantic_payload(record):
    payload = {
        "from": record["from"],
        "relationship_type": record["relationship_type"],
        "to": record["to"],
    }
    if record.get("qualifier"):
        payload["qualifier"] = record["qualifier"]
    return payload


def sha_key(payload) -> str:
    return "sha256-" + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def parse_canonical_id(value: str):
    match = CANONICAL_ID_RE.fullmatch(value)
    if not match:
        raise ValueError(f"invalid canonical ID syntax: {value}")
    return match.groups()


def parse_dt(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("datetime must be offset-aware")
    return parsed


def _walk_refs(value):
    if isinstance(value, dict):
        if "$ref" in value:
            yield value["$ref"]
        for child in value.values():
            yield from _walk_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_refs(child)


def load_registries(registry_dir: Path | None = None):
    directory = registry_dir or REGISTRY_DIR
    registries = {}
    seen_names = {}
    for path in sorted(directory.glob("*.json")):
        data = load_json(path)
        name = data.get("registry")
        version = data.get("registry_version")
        values = data.get("values")
        if not isinstance(name, str) or not name:
            raise ValueError(f"registry field missing/invalid: {path}")
        if name in seen_names:
            raise ValueError(f"duplicate registry identity {name}: {seen_names[name]} and {path}")
        seen_names[name] = path
        if path.stem != name:
            raise ValueError(f"registry name {name} does not match filename {path.name}")
        if not isinstance(version, str) or not SEMVER_RE.fullmatch(version):
            raise ValueError(f"invalid registry_version for {name}: {version!r}")
        if not isinstance(values, list):
            raise ValueError(f"invalid registry values structure: {path}")
        extracted = [v.get("value") for v in values if isinstance(v, dict)]
        if len(extracted) != len(values) or any(not isinstance(v, str) or not v for v in extracted):
            raise ValueError(f"invalid registry values: {path}")
        if len(extracted) != len(set(extracted)):
            raise ValueError(f"duplicate registry values: {path}")
        registries[name] = set(extracted)
    missing = REQUIRED_REGISTRIES - set(registries)
    if missing:
        raise ValueError(f"missing required registries: {sorted(missing)}")
    return registries


def validate_schema_uri_policy(errors):
    for path in sorted(SCHEMA_DIR.rglob("*.json")):
        schema = load_json(path)
        relative = path.relative_to(SCHEMA_DIR).as_posix()
        expected_id = SCHEMA_URI_BASE + relative
        if schema.get("$id") != expected_id:
            errors.append(f"{relative}: schema $id must be {expected_id}")
        for ref in _walk_refs(schema):
            if ref.startswith("https://json-schema.org/"):
                continue
            if not ref.startswith(SCHEMA_URI_BASE):
                errors.append(f"{relative}: non-canonical $ref {ref}")


def load_schemas():
    schemas = {}
    by_path = {}
    uri_errors = []
    validate_schema_uri_policy(uri_errors)
    if uri_errors:
        raise ValueError("; ".join(uri_errors))
    for path in sorted(SCHEMA_DIR.rglob("*.json")):
        schema = load_json(path)
        Draft202012Validator.check_schema(schema)
        sid = schema.get("$id")
        if not sid:
            raise ValueError(f"schema missing $id: {path}")
        if sid in schemas:
            raise ValueError(f"duplicate schema $id: {sid}")
        schemas[sid] = schema
        by_path[path.relative_to(SCHEMA_DIR).as_posix()] = schema
    return schemas, by_path


def root_validator():
    store, by_path = load_schemas()
    root = by_path["atlas-record.schema.json"]
    registry = Registry()
    for uri, schema in store.items():
        registry = registry.with_resource(uri, Resource.from_contents(schema))
    return Draft202012Validator(root, registry=registry, format_checker=FormatChecker())


def fixture_record_paths():
    paths = []
    for sub in ("cross-domain", "support", "record-families"):
        paths.extend(sorted((FIXTURE_DIR / sub).glob("*.json")))
    return paths


def load_fixture_records():
    return [(path, load_json(path)) for path in fixture_record_paths()]


def all_applicability_blocks(record):
    blocks = []
    if isinstance(record.get("applicability"), dict):
        blocks.append(record["applicability"])
    if record.get("record_kind") == "entity":
        for native in record.get("native_identifiers", []):
            if isinstance(native.get("applicability"), dict):
                blocks.append(native["applicability"])
        for alias in record.get("aliases", []):
            if isinstance(alias.get("applicability"), dict):
                blocks.append(alias["applicability"])
    return blocks


def check_time_order(block, label, errors):
    start, end = block.get("valid_from"), block.get("valid_to")
    if start and end:
        try:
            if parse_dt(start) > parse_dt(end):
                errors.append(f"{label}: valid_from is after valid_to")
        except ValueError as exc:
            errors.append(f"{label}: invalid applicability/lifecycle datetime: {exc}")


def validate_time(record, errors):
    try:
        created = parse_dt(record["created_at"])
        updated = parse_dt(record["updated_at"])
    except ValueError as exc:
        errors.append(f"{record['id']}: invalid record datetime: {exc}")
        return
    if updated < created:
        errors.append(f"{record['id']}: updated_at precedes created_at")


def validate_id_component_consistency(record, registries, errors):
    try:
        rid_type, rid_ns, rid_key = parse_canonical_id(record["id"])
    except Exception as exc:
        errors.append(str(exc))
        return
    kind = record["record_kind"]
    expected_type = {
        "claim": "claim",
        "relationship": "relationship",
        "source": "source",
        "validation": "validation",
        "version": "version",
        "coverage-snapshot": "coverage-snapshot",
    }.get(kind, record.get("entity_type"))
    if rid_type != expected_type:
        errors.append(f"{record['id']}: ID type {rid_type!r} != expected {expected_type!r}")
    if rid_ns != record.get("namespace"):
        errors.append(f"{record['id']}: ID namespace does not match record.namespace")
    if rid_key != record.get("canonical_key"):
        errors.append(f"{record['id']}: ID canonical key does not match record.canonical_key")
    if kind == "entity" and record["entity_type"] not in registries["entity-types"]:
        errors.append(f"{record['id']}: unregistered entity_type {record['entity_type']}")
    if record.get("namespace") not in registries["namespaces"]:
        errors.append(f"{record['id']}: unregistered namespace {record.get('namespace')}")


def validate_registry_membership(record, registries, errors):
    if record["record_kind"] == "entity":
        for native in record.get("native_identifiers", []):
            if native["type"] not in registries["native-identifier-types"]:
                errors.append(f"{record['id']}: unregistered native identifier type {native['type']}")
            if native.get("namespace") and native["namespace"] not in registries["namespaces"]:
                errors.append(f"{record['id']}: unregistered native namespace {native['namespace']}")
        for alias in record.get("aliases", []):
            if alias["kind"] not in registries["alias-kinds"]:
                errors.append(f"{record['id']}: unregistered alias kind {alias['kind']}")
            scope = alias.get("scope", {})
            if scope.get("namespace") and scope["namespace"] not in registries["namespaces"]:
                errors.append(f"{record['id']}: alias uses unregistered namespace {scope['namespace']}")
            if scope.get("entity_type") and scope["entity_type"] not in registries["entity-types"]:
                errors.append(f"{record['id']}: alias uses unregistered entity_type {scope['entity_type']}")
    elif record["record_kind"] == "claim":
        if record["predicate"] not in registries["claim-predicates"]:
            errors.append(f"{record['id']}: unregistered claim predicate {record['predicate']}")
    elif record["record_kind"] == "relationship":
        if record["relationship_type"] not in registries["relationship-types"]:
            errors.append(f"{record['id']}: unregistered relationship type {record['relationship_type']}")
    seen_extensions = set()
    for extension in record.get("extensions", []):
        if extension["namespace"] not in registries["namespaces"]:
            errors.append(f"{record['id']}: unregistered extension namespace {extension['namespace']}")
        key = (extension["namespace"], extension["schema_version"])
        if key in seen_extensions:
            errors.append(f"{record['id']}: duplicate extension identity {key[0]}@{key[1]}")
        seen_extensions.add(key)


def validate_deterministic_identity(record, errors):
    if record["record_kind"] == "claim":
        expected = sha_key(claim_semantic_payload(record))
        if record["canonical_key"] != expected:
            errors.append(f"{record['id']}: claim deterministic identity mismatch")
    elif record["record_kind"] == "relationship":
        expected = sha_key(relationship_semantic_payload(record))
        if record["canonical_key"] != expected:
            errors.append(f"{record['id']}: relationship deterministic identity mismatch")


def validate_source_urls(record, errors):
    if record["record_kind"] != "source":
        return
    for url in record.get("canonical_urls", []):
        parsed = urlparse(url)
        if parsed.scheme.lower() != "https" or not parsed.netloc:
            errors.append(f"{record['id']}: canonical URL must use HTTPS")
        if parsed.username or parsed.password:
            errors.append(f"{record['id']}: canonical URL contains userinfo credentials")
        for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
            normalized = key.lower()
            if normalized in SUSPICIOUS_QUERY_KEYS or normalized.startswith(("x-amz-", "x-goog-")):
                errors.append(f"{record['id']}: canonical URL contains credential/signature query parameter {key}")


def collect_references(record):
    refs = []
    kind = record["record_kind"]
    for app in all_applicability_blocks(record):
        for key in ("platform_ids", "product_ids", "provider_ids", "version_ids", "explanatory_claim_ids"):
            refs.extend((value, key) for value in app.get(key, []))
        for constraint in app.get("version_constraints", []):
            refs.append((constraint["subject_id"], "version_constraint.subject_id"))
    if kind == "entity":
        refs.extend((value, "lifecycle.reason_claim_ids") for value in record.get("lifecycle", {}).get("reason_claim_ids", []))
        for alias in record.get("aliases", []):
            provider_id = alias.get("scope", {}).get("provider_id")
            if provider_id:
                refs.append((provider_id, "alias.scope.provider_id"))
    elif kind == "claim":
        refs.append((record["subject_id"], "claim.subject_id"))
        if record["object"]["kind"] == "entity-ref":
            refs.append((record["object"]["entity_id"], "claim.object.entity_id"))
        for evidence in record.get("evidence", []):
            refs.append((evidence["source_id"], "evidence.source_id"))
            if evidence.get("source_snapshot_id"):
                refs.append((evidence["source_snapshot_id"], "evidence.source_snapshot_id"))
    elif kind == "relationship":
        refs.extend([(record["from"], "relationship.from"), (record["to"], "relationship.to")])
        refs.extend((value, "relationship.supporting_claim_ids") for value in record.get("supporting_claim_ids", []))
    elif kind == "validation":
        refs.append((record["target_id"], "validation.target_id"))
    elif kind == "version":
        refs.append((record["subject_id"], "version.subject_id"))
        for evidence in record.get("evidence", []):
            refs.append((evidence["source_id"], "evidence.source_id"))
            if evidence.get("source_snapshot_id"):
                refs.append((evidence["source_snapshot_id"], "evidence.source_snapshot_id"))
    elif kind == "coverage-snapshot":
        refs.extend((value, "coverage.scope.subject_ids") for value in record.get("scope", {}).get("subject_ids", []))
    return refs


def _record(by_id, record_id):
    item = by_id.get(record_id)
    return item[1] if item else None


def _require_kind(owner_id, label, target_id, by_id, expected_kind, errors, entity_types=None):
    target = _record(by_id, target_id)
    if target is None:
        return
    if target.get("record_kind") != expected_kind:
        errors.append(f"{owner_id}: {label} must resolve to {expected_kind} record")
        return
    if entity_types and target.get("entity_type") not in entity_types:
        errors.append(f"{owner_id}: {label} must resolve to EntityRecord entity_type in {sorted(entity_types)}")


def validate_typed_references(record, by_id, errors):
    rid = record["id"]
    for app in all_applicability_blocks(record):
        for value in app.get("platform_ids", []):
            _require_kind(rid, "applicability.platform_ids", value, by_id, "entity", errors, {"platform"})
        for value in app.get("product_ids", []):
            _require_kind(rid, "applicability.product_ids", value, by_id, "entity", errors, {"product"})
        for value in app.get("provider_ids", []):
            _require_kind(rid, "applicability.provider_ids", value, by_id, "entity", errors, {"telemetry-provider"})
        for value in app.get("version_ids", []):
            _require_kind(rid, "applicability.version_ids", value, by_id, "version", errors)
        for value in app.get("explanatory_claim_ids", []):
            _require_kind(rid, "applicability.explanatory_claim_ids", value, by_id, "claim", errors)
        for constraint in app.get("version_constraints", []):
            _require_kind(rid, "version_constraint.subject_id", constraint["subject_id"], by_id, "entity", errors, VERSION_CONSTRAINT_SUBJECT_TYPES)
    kind = record["record_kind"]
    if kind == "entity":
        for value in record.get("lifecycle", {}).get("reason_claim_ids", []):
            _require_kind(rid, "lifecycle.reason_claim_ids", value, by_id, "claim", errors)
        for alias in record.get("aliases", []):
            provider_id = alias.get("scope", {}).get("provider_id")
            if provider_id:
                _require_kind(rid, "alias.scope.provider_id", provider_id, by_id, "entity", errors, {"telemetry-provider"})
    elif kind == "claim":
        if record.get("object", {}).get("kind") == "entity-ref":
            _require_kind(rid, "claim.object.entity_id", record["object"]["entity_id"], by_id, "entity", errors)
        for evidence in record.get("evidence", []):
            _require_kind(rid, "evidence.source_id", evidence["source_id"], by_id, "source", errors)
    elif kind == "relationship":
        for value in record.get("supporting_claim_ids", []):
            _require_kind(rid, "relationship.supporting_claim_ids", value, by_id, "claim", errors)
    elif kind == "version":
        subject = _record(by_id, record["subject_id"])
        if subject and subject.get("record_kind") not in {"entity", "source"}:
            errors.append(f"{rid}: version.subject_id must resolve to EntityRecord or SourceRecord")
        for evidence in record.get("evidence", []):
            _require_kind(rid, "evidence.source_id", evidence["source_id"], by_id, "source", errors)
    elif kind == "coverage-snapshot":
        for value in record.get("scope", {}).get("subject_ids", []):
            _require_kind(rid, "coverage.scope.subject_ids", value, by_id, "entity", errors)


def validate_structural_relationship(record, by_id, errors):
    if record.get("record_kind") != "relationship":
        return
    rid = record["id"]
    relationship_type = record["relationship_type"]
    if relationship_type == "HAS_TELEMETRY_PROVIDER":
        _require_kind(rid, "relationship.from", record["from"], by_id, "entity", errors, {"product"})
        _require_kind(rid, "relationship.to", record["to"], by_id, "entity", errors, {"telemetry-provider"})
    elif relationship_type == "HAS_TELEMETRY_SOURCE":
        _require_kind(rid, "relationship.from", record["from"], by_id, "entity", errors, {"telemetry-provider"})
        _require_kind(rid, "relationship.to", record["to"], by_id, "entity", errors, {"telemetry-source"})
    elif relationship_type == "EMITS":
        _require_kind(rid, "relationship.from", record["from"], by_id, "entity", errors, {"telemetry-source"})
        _require_kind(rid, "relationship.to", record["to"], by_id, "entity", errors, TELEMETRY_ENTITY_TYPES)
    elif relationship_type == "HAS_FIELD":
        _require_kind(rid, "relationship.from", record["from"], by_id, "entity", errors, TELEMETRY_ENTITY_TYPES)
        _require_kind(rid, "relationship.to", record["to"], by_id, "entity", errors, {"field"})
    elif relationship_type == "RUNS_ON":
        _require_kind(rid, "relationship.from", record["from"], by_id, "entity", errors)
        _require_kind(rid, "relationship.to", record["to"], by_id, "entity", errors)


def validate_native_identifiers(record, errors):
    if record.get("record_kind") != "entity":
        return
    native_identifiers = record.get("native_identifiers", [])
    if native_identifiers and not any(item.get("primary") is True for item in native_identifiers):
        errors.append(f"{record['id']}: non-empty native_identifiers requires at least one primary=true")
    seen = set()
    for item in native_identifiers:
        identity = canonical_json({"type":item.get("type"),"value":item.get("value"),"namespace":item.get("namespace"),"context":item.get("context"),"case_sensitive":item.get("case_sensitive"),"applicability":normalize_applicability(item.get("applicability"))})
        if identity in seen:
            errors.append(f"{record['id']}: duplicate native identifier semantic tuple")
        seen.add(identity)


def authoritative_claim_ok(record, by_id):
    if not record or record.get("record_kind") != "claim" or record.get("confidence") != "authoritative":
        return False
    for evidence in record.get("evidence", []):
        source = _record(by_id, evidence.get("source_id"))
        if (source and source.get("record_kind") == "source" and source.get("source_class") == "tier-a-authoritative" and evidence.get("reviewer_status") == "approved" and evidence.get("transformation_type") in AUTHORITATIVE_TRANSFORMATIONS):
            return True
    return False


def validate_trust(record, by_id, errors):
    if record.get("record_kind") == "claim" and record.get("confidence") == "authoritative":
        if not authoritative_claim_ok(record, by_id):
            errors.append(f"{record['id']}: authoritative claim requires approved Tier A direct/normalized evidence")
    if record.get("record_kind") == "relationship" and record.get("confidence") == "authoritative":
        if not any(authoritative_claim_ok(_record(by_id, claim_id), by_id) for claim_id in record.get("supporting_claim_ids", [])):
            errors.append(f"{record['id']}: authoritative relationship requires authoritative trusted supporting claim")


def _alias_values_equal(left, right):
    if left.get("case_sensitive") and right.get("case_sensitive"):
        return left["value"] == right["value"]
    return left["value"].casefold() == right["value"].casefold()


def _alias_scopes_overlap(left, right):
    left_scope = left.get("scope", {})
    right_scope = right.get("scope", {})
    for left_value, right_value in ((left_scope.get("namespace"), right_scope.get("namespace")), (left_scope.get("entity_type"), right_scope.get("entity_type")), (left_scope.get("provider_id"), right_scope.get("provider_id")), (left.get("locale"), right.get("locale"))):
        if left_value is not None and right_value is not None and left_value != right_value:
            return False
    return True


def validate_alias_collisions(records, errors):
    aliases = [(record["id"], alias) for _, record in records if record.get("record_kind") == "entity" for alias in record.get("aliases", [])]
    for index, (left_id, left_alias) in enumerate(aliases):
        for right_id, right_alias in aliases[index + 1:]:
            if left_id == right_id:
                continue
            if _alias_values_equal(left_alias, right_alias) and _alias_scopes_overlap(left_alias, right_alias):
                errors.append(f"ambiguous alias overlapping scope: {left_alias['value']!r} -> {left_id}, {right_id}")


def validate_coverage(record, errors):
    if record.get("record_kind") != "coverage-snapshot":
        return
    if "coverage_percent" in record:
        errors.append(f"{record['id']}: coverage_percent must remain derived/absent")
    allowed_bases = {"collected", "normalized", "validated", "published"} if record["metric_type"] == "telemetry" else {"covered", "validated"}
    basis = record.get("numerator_basis")
    if basis not in allowed_bases:
        errors.append(f"{record['id']}: invalid numerator_basis {basis!r}")
    elif record["state_counts"].get(basis) != record["numerator_count"]:
        errors.append(f"{record['id']}: numerator_count must equal state_counts[{basis!r}]")


def validate_semantics(records, registries):
    errors = []
    by_id = {}
    for path, record in records:
        rid = record.get("id")
        if rid in by_id:
            errors.append(f"duplicate canonical record ID: {rid} in {path} and {by_id[rid][0]}")
        else:
            by_id[rid] = (path, record)
    for _, record in records:
        rid = record["id"]
        validate_id_component_consistency(record, registries, errors)
        validate_registry_membership(record, registries, errors)
        validate_deterministic_identity(record, errors)
        validate_source_urls(record, errors)
        validate_time(record, errors)
        validate_native_identifiers(record, errors)
        validate_coverage(record, errors)
        if "lifecycle" in record:
            check_time_order(record["lifecycle"], rid + ".lifecycle", errors)
        for index, applicability in enumerate(all_applicability_blocks(record)):
            check_time_order(applicability, f"{rid}.applicability[{index}]", errors)
        if record["record_kind"] == "claim" and any(e["transformation_type"] == "ai-assisted-draft" for e in record.get("evidence", [])):
            if record["curation_status"] in {"validated", "published"} and not any(e.get("reviewer_status") == "approved" for e in record.get("evidence", [])):
                errors.append(f"{rid}: AI-assisted validated/published claim lacks approved review evidence")
        if record["record_kind"] == "relationship":
            relationship_type = record["relationship_type"]
            if relationship_type in SEMANTIC_RELATIONSHIPS_REQUIRING_SUPPORT and not record.get("supporting_claim_ids"):
                errors.append(f"{rid}: semantic relationship {relationship_type} requires supporting_claim_ids")
            if relationship_type not in (SEMANTIC_RELATIONSHIPS_REQUIRING_SUPPORT | STRUCTURAL_RELATIONSHIPS):
                errors.append(f"{rid}: relationship evidence policy not classified for {relationship_type}")
        if record["record_kind"] == "coverage-snapshot":
            if record["numerator_count"] > record["denominator_count"]:
                errors.append(f"{rid}: numerator_count exceeds denominator_count")
            counts = record["state_counts"]
            if record["metric_type"] == "telemetry" and counts["expected"] != record["denominator_count"]:
                errors.append(f"{rid}: telemetry expected count must equal denominator_count")
            if record["metric_type"] == "detection" and counts["in_scope"] != record["denominator_count"]:
                errors.append(f"{rid}: detection in_scope count must equal denominator_count")
    for _, record in records:
        for target, label in collect_references(record):
            if target not in by_id:
                errors.append(f"{record['id']}: unresolved {label} -> {target}")
    for _, record in records:
        validate_typed_references(record, by_id, errors)
        validate_structural_relationship(record, by_id, errors)
        validate_trust(record, by_id, errors)
    validate_alias_collisions(records, errors)
    return errors


def resolve_query(records, query, namespace=None):
    by_id = {record["id"]: record for _, record in records}
    if query in by_id:
        return [query]
    matches = set()
    for _, record in records:
        if record["record_kind"] != "entity":
            continue
        if namespace and record["namespace"] != namespace:
            continue
        if record["title"].casefold() == query.casefold():
            matches.add(record["id"])
        for native in record.get("native_identifiers", []):
            same = native["value"] == query if native["case_sensitive"] else native["value"].casefold() == query.casefold()
            if same:
                matches.add(record["id"])
        for alias in record.get("aliases", []):
            same = alias["value"] == query if alias["case_sensitive"] else alias["value"].casefold() == query.casefold()
            if not same:
                continue
            scope_namespace = alias.get("scope", {}).get("namespace")
            if namespace and scope_namespace and scope_namespace != namespace:
                continue
            matches.add(record["id"])
    return sorted(matches)


def validate_exact_resolution(records):
    errors = []
    cases = load_json(FIXTURE_DIR / "exact-resolution-cases.json")["cases"]
    for case in cases:
        actual = resolve_query(records, case["query"], case.get("namespace"))
        if actual != [case["expected_id"]]:
            errors.append(f"exact resolution {case['query']!r}: expected {[case['expected_id']]}, got {actual}")
    synthetic = copy.deepcopy(next(record for _, record in records if record["id"] == "atlas:event:microsoft.sysmon:1"))
    synthetic["id"] = "atlas:event:microsoft.sysmon:4688"
    synthetic["canonical_key"] = "4688"
    synthetic["title"] = "Synthetic Sysmon Event 4688 — Resolution Test Only"
    synthetic["native_identifiers"][0]["value"] = "4688"
    synthetic["aliases"] = [{"value":"4688","kind":"native","case_sensitive":False,"scope":{"namespace":"microsoft.sysmon"}}]
    synthetic_records = records + [(Path("<synthetic>"), synthetic)]
    bare = resolve_query(synthetic_records, "4688")
    expected = {"atlas:event:microsoft.windows.security:4688", "atlas:event:microsoft.sysmon:4688"}
    if set(bare) != expected:
        errors.append(f"hypothetical bare 4688 collision test failed: {bare}")
    if resolve_query(synthetic_records, "4688", "microsoft.windows.security") != ["atlas:event:microsoft.windows.security:4688"]:
        errors.append("Windows namespace collision resolution failed")
    if resolve_query(synthetic_records, "4688", "microsoft.sysmon") != ["atlas:event:microsoft.sysmon:4688"]:
        errors.append("Sysmon namespace collision resolution failed")
    return errors


def validate_migration(records):
    errors = []
    data = load_json(MIGRATION_MAP)
    migration_schema = load_json(MIGRATION_MAP.with_name("migration-map.schema.json"))
    Draft202012Validator.check_schema(migration_schema)
    for error in Draft202012Validator(migration_schema, format_checker=FormatChecker()).iter_errors(data):
        errors.append(f"migration-map schema: {error.message}")
    if data.get("deprecated_status_auto_migration") is not False:
        errors.append("migration map must explicitly disable Phase 5.1 deprecated status auto-migration")
    by_id = {record["id"]: record for _, record in records}
    seen_old = set()
    for mapping in data.get("mappings", []):
        for required in ("old_id", "new_id", "migration_type", "reason", "review_status"):
            if not mapping.get(required):
                errors.append(f"migration mapping missing {required}: {mapping}")
        if mapping["old_id"] in seen_old:
            errors.append(f"duplicate old_id in migration map: {mapping['old_id']}")
        seen_old.add(mapping["old_id"])
        try:
            parse_canonical_id(mapping["new_id"])
        except Exception as exc:
            errors.append(f"migration new_id invalid: {exc}")
            continue
        if mapping["new_id"] not in by_id:
            errors.append(f"migration new_id does not resolve in fixture corpus: {mapping['new_id']}")
            continue
        if mapping["migration_type"] == "legacy-canonical-id-alias":
            entity = by_id[mapping["new_id"]]
            aliases = entity.get("aliases", []) if entity["record_kind"] == "entity" else []
            if not any(alias["kind"] == "legacy-canonical-id" and alias["value"] == mapping["old_id"] for alias in aliases):
                errors.append(f"migration legacy alias not preserved on {mapping['new_id']}: {mapping['old_id']}")
    required_old = {"atlas:event:windows-security:4688", "atlas:event:sysmon:1", "atlas:attack:T1059.001"}
    missing = required_old - seen_old
    if missing:
        errors.append(f"migration inventory missing required Phase 5.1 IDs: {sorted(missing)}")
    return errors


def validate_legacy_schema_preservation():
    errors = []
    for relative in ("schemas/atlas-node.schema.json", "schemas/atlas-edge.schema.json"):
        if not (ROOT / relative).is_file():
            errors.append(f"Phase 5.1 legacy schema missing: {relative}")
    return errors


def validate_no_vendor_root_fields(records):
    errors = []
    forbidden = {"aws_event_name", "gcp_method_name", "azure_operation_name", "kubernetes_verb", "kubernetes_resource", "docker_action", "mongodb_audit_action", "event_id"}
    for _, record in records:
        overlap = forbidden.intersection(record.keys())
        if overlap:
            errors.append(f"{record['id']}: vendor/native fields leaked into canonical record root: {sorted(overlap)}")
    return errors


def validate_schema_records(records):
    validator = root_validator()
    errors = []
    for path, record in records:
        schema_errors = sorted(validator.iter_errors(record), key=lambda error: list(error.absolute_path))
        for error in schema_errors:
            location = "/".join(map(str, error.absolute_path))
            errors.append(f"{path.relative_to(ROOT)}:{location}: {error.message}")
    return errors


def main():
    errors = []
    try:
        registries = load_registries()
        records = load_fixture_records()
        errors.extend(validate_schema_records(records))
        errors.extend(validate_semantics(records, registries))
        errors.extend(validate_exact_resolution(records))
        errors.extend(validate_migration(records))
        errors.extend(validate_legacy_schema_preservation())
        errors.extend(validate_no_vendor_root_fields(records))
        validate_schema_uri_policy(errors)
    except Exception as exc:
        errors.append(f"validator exception: {type(exc).__name__}: {exc}")
    if errors:
        print("Phase 5.2 canonical model validation FAILED")
        for error in errors:
            print(f"- {error}")
        return 1
    kinds = sorted({record["record_kind"] for _, record in records})
    print("Phase 5.2 canonical model validation PASSED")
    print("record_families=" + ",".join(kinds))
    print(f"fixture_records={len(records)}")
    print("schema_version=" + SCHEMA_VERSION)
    print("schema_uri_base=" + SCHEMA_URI_BASE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
