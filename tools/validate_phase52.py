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

CANONICAL_ID_RE = re.compile(r"^atlas:([a-z0-9-]+):([a-z0-9-]+(?:\.[a-z0-9-]+)*):([a-z0-9][a-z0-9._-]*)$")
SHA_KEY_RE = re.compile(r"^sha256-[a-f0-9]{64}$")
SUSPICIOUS_QUERY_KEYS = {
    "token","access_token","api_key","apikey","key","sig","signature","session",
    "sessionid","x-amz-signature","x-amz-credential","x-goog-signature"
}
SEMANTIC_RELATIONSHIPS_REQUIRING_SUPPORT = {
    "INDICATES","RELATED_TO","EQUIVALENT_SIGNAL","MAPS_TO_ATTACK","COUNTERED_BY",
    "DETECTED_BY","HUNTED_BY","INVESTIGATED_BY","RESPONDED_BY","REQUIRES_TELEMETRY",
    "DERIVED_FROM","SUPPORTED_BY","SUPERSEDES","SUPERSEDED_BY","VERSION_OF","VALIDATED_BY"
}
STRUCTURAL_RELATIONSHIPS = {
    "RUNS_ON","EMITS","HAS_FIELD","PRECEDES","FOLLOWS",
    "HAS_TELEMETRY_PROVIDER","HAS_TELEMETRY_SOURCE"
}

def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))

def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def normalize_applicability(value):
    if not value:
        return None
    out = copy.deepcopy(value)
    for key in ("platform_ids","product_ids","provider_ids","version_ids","explanatory_claim_ids"):
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

def load_registries():
    registries = {}
    for path in sorted(REGISTRY_DIR.glob("*.json")):
        data = load_json(path)
        name = data.get("registry")
        values = data.get("values")
        if not name or not isinstance(values, list):
            raise ValueError(f"invalid registry structure: {path}")
        extracted = [v.get("value") for v in values if isinstance(v, dict)]
        if len(extracted) != len(values) or any(not v for v in extracted):
            raise ValueError(f"invalid registry values: {path}")
        if len(extracted) != len(set(extracted)):
            raise ValueError(f"duplicate registry values: {path}")
        registries[name] = set(extracted)
    return registries

def load_schemas():
    schemas = {}
    by_path = {}
    for path in sorted(SCHEMA_DIR.rglob("*.json")):
        schema = load_json(path)
        Draft202012Validator.check_schema(schema)
        sid = schema.get("$id")
        if not sid:
            raise ValueError(f"schema missing $id: {path}")
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
    for sub in ("cross-domain","support","record-families"):
        paths.extend(sorted((FIXTURE_DIR / sub).glob("*.json")))
    return paths

def load_fixture_records():
    return [(p, load_json(p)) for p in fixture_record_paths()]

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
            a = datetime.fromisoformat(start.replace("Z","+00:00"))
            b = datetime.fromisoformat(end.replace("Z","+00:00"))
            if a > b:
                errors.append(f"{label}: valid_from is after valid_to")
        except ValueError:
            pass

def validate_id_component_consistency(record, registries, errors):
    try:
        rid_type, rid_ns, rid_key = parse_canonical_id(record["id"])
    except Exception as exc:
        errors.append(str(exc))
        return

    kind = record["record_kind"]
    expected_type = {
        "claim":"claim",
        "relationship":"relationship",
        "source":"source",
        "validation":"validation",
        "version":"version",
        "coverage-snapshot":"coverage-snapshot",
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
        for a in record.get("aliases", []):
            if a["kind"] not in registries["alias-kinds"]:
                errors.append(f"{record['id']}: unregistered alias kind {a['kind']}")
            scope = a.get("scope", {})
            if scope.get("namespace") and scope["namespace"] not in registries["namespaces"]:
                errors.append(f"{record['id']}: alias uses unregistered namespace {scope['namespace']}")
            if scope.get("entity_type") and scope["entity_type"] not in registries["entity-types"]:
                errors.append(f"{record['id']}: alias uses unregistered entity_type {scope['entity_type']}")
        for extension in record.get("extensions", []):
            if extension["namespace"] not in registries["namespaces"]:
                errors.append(f"{record['id']}: unregistered extension namespace {extension['namespace']}")
    elif record["record_kind"] == "claim":
        if record["predicate"] not in registries["claim-predicates"]:
            errors.append(f"{record['id']}: unregistered claim predicate {record['predicate']}")
    elif record["record_kind"] == "relationship":
        if record["relationship_type"] not in registries["relationship-types"]:
            errors.append(f"{record['id']}: unregistered relationship type {record['relationship_type']}")

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
    for url in record["canonical_urls"]:
        parsed = urlparse(url)
        if parsed.username or parsed.password:
            errors.append(f"{record['id']}: canonical URL contains userinfo credentials")
        for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
            if key.lower() in SUSPICIOUS_QUERY_KEYS or key.lower().startswith(("x-amz-","x-goog-")):
                errors.append(f"{record['id']}: canonical URL contains credential/signature query parameter {key}")

def collect_references(record):
    refs = []
    kind = record["record_kind"]

    for app in all_applicability_blocks(record):
        for key in ("platform_ids","product_ids","provider_ids","version_ids","explanatory_claim_ids"):
            refs.extend((v, key) for v in app.get(key, []))
        for vc in app.get("version_constraints", []):
            refs.append((vc["subject_id"], "version_constraint.subject_id"))

    if kind == "entity":
        lifecycle = record.get("lifecycle", {})
        refs.extend((v, "lifecycle.reason_claim_ids") for v in lifecycle.get("reason_claim_ids", []))
        for a in record.get("aliases", []):
            pid = a.get("scope", {}).get("provider_id")
            if pid:
                refs.append((pid, "alias.scope.provider_id"))
    elif kind == "claim":
        refs.append((record["subject_id"], "claim.subject_id"))
        if record["object"]["kind"] == "entity-ref":
            refs.append((record["object"]["entity_id"], "claim.object.entity_id"))
        for ev in record["evidence"]:
            refs.append((ev["source_id"], "evidence.source_id"))
            if ev.get("source_snapshot_id"):
                refs.append((ev["source_snapshot_id"], "evidence.source_snapshot_id"))
    elif kind == "relationship":
        refs.extend([(record["from"], "relationship.from"), (record["to"], "relationship.to")])
        refs.extend((v, "relationship.supporting_claim_ids") for v in record.get("supporting_claim_ids", []))
    elif kind == "validation":
        refs.append((record["target_id"], "validation.target_id"))
    elif kind == "version":
        refs.append((record["subject_id"], "version.subject_id"))
        for ev in record["evidence"]:
            refs.append((ev["source_id"], "evidence.source_id"))
            if ev.get("source_snapshot_id"):
                refs.append((ev["source_snapshot_id"], "evidence.source_snapshot_id"))
    elif kind == "coverage-snapshot":
        refs.extend((v, "coverage.scope.subject_ids") for v in record["scope"].get("subject_ids", []))
    return refs

def validate_semantics(records, registries):
    errors = []
    by_id = {}
    for path, record in records:
        rid = record.get("id")
        if rid in by_id:
            errors.append(f"duplicate canonical record ID: {rid} in {path} and {by_id[rid][0]}")
        else:
            by_id[rid] = (path, record)

    for path, record in records:
        rid = record["id"]
        validate_id_component_consistency(record, registries, errors)
        validate_registry_membership(record, registries, errors)
        validate_deterministic_identity(record, errors)
        validate_source_urls(record, errors)

        if record["updated_at"] < record["created_at"]:
            errors.append(f"{rid}: updated_at precedes created_at")
        if "lifecycle" in record:
            check_time_order(record["lifecycle"], rid + ".lifecycle", errors)
        for i, app in enumerate(all_applicability_blocks(record)):
            check_time_order(app, f"{rid}.applicability[{i}]", errors)

        if record["record_kind"] == "claim":
            if any(ev["transformation_type"] == "ai-assisted-draft" for ev in record["evidence"]):
                if record["curation_status"] in {"validated","published"} and not any(ev["reviewer_status"] == "approved" for ev in record["evidence"]):
                    errors.append(f"{rid}: AI-assisted validated/published claim lacks approved review evidence")

        if record["record_kind"] == "relationship":
            rtype = record["relationship_type"]
            if rtype in SEMANTIC_RELATIONSHIPS_REQUIRING_SUPPORT and not record.get("supporting_claim_ids"):
                errors.append(f"{rid}: semantic relationship {rtype} requires supporting_claim_ids")
            if rtype not in SEMANTIC_RELATIONSHIPS_REQUIRING_SUPPORT | STRUCTURAL_RELATIONSHIPS:
                errors.append(f"{rid}: relationship evidence policy not classified for {rtype}")

        if record["record_kind"] == "coverage-snapshot":
            if record["numerator_count"] > record["denominator_count"]:
                errors.append(f"{rid}: numerator_count exceeds denominator_count")
            counts = record["state_counts"]
            if record["metric_type"] == "telemetry" and counts["expected"] != record["denominator_count"]:
                errors.append(f"{rid}: telemetry expected count must equal denominator_count")
            if record["metric_type"] == "detection" and counts["in_scope"] != record["denominator_count"]:
                errors.append(f"{rid}: detection in_scope count must equal denominator_count")

    for path, record in records:
        for target, label in collect_references(record):
            if target not in by_id:
                errors.append(f"{record['id']}: unresolved {label} -> {target}")
                continue
            target_record = by_id[target][1]
            if label == "evidence.source_id" and target_record["record_kind"] != "source":
                errors.append(f"{record['id']}: evidence source_id is not a SourceRecord: {target}")
            if label == "relationship.supporting_claim_ids" and target_record["record_kind"] != "claim":
                errors.append(f"{record['id']}: supporting_claim_id is not a ClaimRecord: {target}")
            if label.endswith("version_ids") and target_record["record_kind"] != "version":
                errors.append(f"{record['id']}: version_id is not a VersionRecord: {target}")

    alias_index = {}
    for _, record in records:
        if record["record_kind"] != "entity":
            continue
        for a in record.get("aliases", []):
            key = a["value"] if a["case_sensitive"] else a["value"].casefold()
            alias_index.setdefault(key, []).append((record["id"], a))
    for value, matches in alias_index.items():
        ids = {rid for rid, _ in matches}
        if len(ids) > 1 and any(not a.get("scope") for _, a in matches):
            errors.append(f"ambiguous alias without scope: {value!r} -> {sorted(ids)}")

    return errors

def resolve_query(records, query, namespace=None):
    by_id = {r["id"]: r for _, r in records}
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
        for ni in record.get("native_identifiers", []):
            same = ni["value"] == query if ni["case_sensitive"] else ni["value"].casefold() == query.casefold()
            if same:
                matches.add(record["id"])
        for a in record.get("aliases", []):
            same = a["value"] == query if a["case_sensitive"] else a["value"].casefold() == query.casefold()
            if not same:
                continue
            scope_ns = a.get("scope", {}).get("namespace")
            if namespace and scope_ns and scope_ns != namespace:
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

    synthetic = copy.deepcopy(next(r for _, r in records if r["id"] == "atlas:event:microsoft.sysmon:1"))
    synthetic["id"] = "atlas:event:microsoft.sysmon:4688"
    synthetic["canonical_key"] = "4688"
    synthetic["title"] = "Synthetic Sysmon Event 4688 — Resolution Test Only"
    synthetic["native_identifiers"][0]["value"] = "4688"
    synthetic["aliases"] = [{"value":"4688","kind":"native","case_sensitive":False,"scope":{"namespace":"microsoft.sysmon"}}]
    synthetic_records = records + [(Path("<synthetic>"), synthetic)]

    bare = resolve_query(synthetic_records, "4688")
    if set(bare) != {"atlas:event:microsoft.windows.security:4688","atlas:event:microsoft.sysmon:4688"}:
        errors.append(f"hypothetical bare 4688 collision test failed: {bare}")
    scoped_windows = resolve_query(synthetic_records, "4688", "microsoft.windows.security")
    scoped_sysmon = resolve_query(synthetic_records, "4688", "microsoft.sysmon")
    if scoped_windows != ["atlas:event:microsoft.windows.security:4688"]:
        errors.append(f"Windows namespace collision resolution failed: {scoped_windows}")
    if scoped_sysmon != ["atlas:event:microsoft.sysmon:4688"]:
        errors.append(f"Sysmon namespace collision resolution failed: {scoped_sysmon}")
    return errors

def validate_migration(records):
    errors = []
    data = load_json(MIGRATION_MAP)
    migration_schema = load_json(MIGRATION_MAP.with_name("migration-map.schema.json"))
    Draft202012Validator.check_schema(migration_schema)
    for err in Draft202012Validator(migration_schema, format_checker=FormatChecker()).iter_errors(data):
        errors.append(f"migration-map schema: {err.message}")
    if data.get("deprecated_status_auto_migration") is not False:
        errors.append("migration map must explicitly disable Phase 5.1 deprecated status auto-migration")

    by_id = {r["id"]: r for _, r in records}
    seen_old = set()
    for m in data.get("mappings", []):
        for required in ("old_id","new_id","migration_type","reason","review_status"):
            if not m.get(required):
                errors.append(f"migration mapping missing {required}: {m}")
        if m["old_id"] in seen_old:
            errors.append(f"duplicate old_id in migration map: {m['old_id']}")
        seen_old.add(m["old_id"])
        try:
            parse_canonical_id(m["new_id"])
        except Exception as exc:
            errors.append(f"migration new_id invalid: {exc}")
            continue
        if m["new_id"] not in by_id:
            errors.append(f"migration new_id does not resolve in fixture corpus: {m['new_id']}")
            continue
        if m["migration_type"] == "legacy-canonical-id-alias":
            entity = by_id[m["new_id"]]
            aliases = entity.get("aliases", []) if entity["record_kind"] == "entity" else []
            if not any(a["kind"] == "legacy-canonical-id" and a["value"] == m["old_id"] for a in aliases):
                errors.append(f"migration legacy alias not preserved on {m['new_id']}: {m['old_id']}")

    required_old = {"atlas:event:windows-security:4688","atlas:event:sysmon:1","atlas:attack:T1059.001"}
    missing = required_old - seen_old
    if missing:
        errors.append(f"migration inventory missing required Phase 5.1 IDs: {sorted(missing)}")
    return errors

def validate_legacy_schema_preservation():
    errors = []
    for rel in ("schemas/atlas-node.schema.json","schemas/atlas-edge.schema.json"):
        p = ROOT / rel
        if not p.is_file():
            errors.append(f"Phase 5.1 legacy schema missing: {rel}")
    return errors

def validate_no_vendor_root_fields(records):
    errors=[]
    forbidden = {"aws_event_name","gcp_method_name","azure_operation_name","kubernetes_verb","kubernetes_resource","docker_action","mongodb_audit_action","event_id"}
    for _, r in records:
        overlap = forbidden.intersection(r.keys())
        if overlap:
            errors.append(f"{r['id']}: vendor/native fields leaked into canonical record root: {sorted(overlap)}")
    return errors

def validate_schema_records(records):
    validator = root_validator()
    errors=[]
    for path, record in records:
        errs = sorted(validator.iter_errors(record), key=lambda e: list(e.absolute_path))
        for e in errs:
            loc = "/".join(map(str, e.absolute_path))
            errors.append(f"{path.relative_to(ROOT)}:{loc}: {e.message}")
    return errors

def main():
    errors=[]
    try:
        registries = load_registries()
        for name in ("entity-types","namespaces","relationship-types","native-identifier-types","claim-predicates","alias-kinds"):
            if name not in registries:
                errors.append(f"missing controlled registry: {name}")
        load_schemas()
        records = load_fixture_records()
        errors.extend(validate_schema_records(records))
        errors.extend(validate_semantics(records, registries))
        errors.extend(validate_exact_resolution(records))
        errors.extend(validate_migration(records))
        errors.extend(validate_legacy_schema_preservation())
        errors.extend(validate_no_vendor_root_fields(records))
    except Exception as exc:
        errors.append(f"validator exception: {type(exc).__name__}: {exc}")

    if errors:
        print("Phase 5.2 canonical model validation FAILED")
        for err in errors:
            print(f"- {err}")
        return 1

    kinds = sorted({r["record_kind"] for _, r in records})
    print("Phase 5.2 canonical model validation PASSED")
    print("record_families=" + ",".join(kinds))
    print(f"fixture_records={len(records)}")
    print("schema_version=" + SCHEMA_VERSION)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
