#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE_ID = "atlas:source:atlas.source:mitre-attack-enterprise-stix"
VERSION = "19.2"
COMMIT = "6cda5ad8462c79e14fbb872f4e09059b18e0cfc4"
TREE = "70b3126e8b7bc4fc59c4bd0ffde68564f34740a2"
BLOB = "8b8a9c8cc9e553f96f963b91265f50ee0854636d"
SIZE = 53835637
COLLECTION = "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019"
SNAPSHOT = "atlas:raw-snapshot:atlas.ingestion:attack-canary-fixture-v19.2"
RETRIEVED = "2026-09-05T00:00:00Z"
P = {
    "source": ROOT / "ingestion/source-profiles/mitre-attack-enterprise.source.json",
    "release": ROOT / "ingestion/source-profiles/mitre-attack-enterprise.release.json",
    "connector": ROOT / "ingestion/connectors/mitre-attack-enterprise.json",
    "parser_def": ROOT / "ingestion/parsers/mitre-attack-stix21.definition.json",
    "parser": ROOT / "ingestion/parsers/mitre_attack_stix.py",
    "normalizer_def": ROOT / "ingestion/normalizers/mitre-attack-enterprise.definition.json",
    "normalizer": ROOT / "ingestion/normalizers/mitre_attack.py",
    "mapping": ROOT / "ingestion/mappings/mitre-attack-enterprise-v1.json",
    "fixture": ROOT / "fixtures/phase-5.3/attack-canary-stix.json",
}


def mod(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def load(key):
    return json.loads(P[key].read_text(encoding="utf-8"))


def serr(validator, value, label):
    return [
        f"{label}:{'/'.join(map(str, error.absolute_path))}: {error.message}"
        for error in validator.iter_errors(value)
    ]


def lineage_digest(normalizer, lineage):
    body = copy.deepcopy(lineage)
    body.pop("lineage_id", None)
    body.pop("lineage_digest", None)
    return normalizer.sha256_digest(body)


def pin_errors(release, connector):
    errors = []
    for key, wanted in (
        ("release_version", VERSION),
        ("upstream_commit_sha", COMMIT),
        ("upstream_tree_sha", TREE),
        ("bundle_git_blob_sha1", BLOB),
        ("bundle_size_bytes", SIZE),
        ("collection_id", COLLECTION),
    ):
        if release.get(key) != wanted:
            errors.append(f"release pin mismatch: {key}")
    url = release.get("bundle_url", "")
    if f"/{COMMIT}/enterprise-attack/enterprise-attack-{VERSION}.json" not in url:
        errors.append("bundle URL is not exact-release pinned")
    if re.search(r"/(master|main|latest|HEAD)/", url, re.I):
        errors.append("floating production bundle ref")
    if release.get("index", {}).get("discovery_only") is not True:
        errors.append("floating index is not discovery-only")
    if len(connector.get("targets", [])) != 1 or connector["targets"][0].get("resource_uri") != url:
        errors.append("connector target is not pinned bundle")
    security = connector.get("security_policy", {})
    if security.get("redirect_limit") != 0:
        errors.append("pinned canary must use zero redirects")
    if min(security.get("max_response_bytes", 0), security.get("max_decompressed_bytes", 0)) < SIZE:
        errors.append("connector size bound below pinned bundle")
    return errors


def security_errors():
    errors = []
    for label, key, tokens in (
        ("parser", "parser", ["urllib", "requests", "socket", "subprocess", "os.system", "eval(", "exec("]),
        (
            "normalizer",
            "normalizer",
            ["urllib", "requests", "socket", "subprocess", "os.system", "eval(", "exec(", "openai", "anthropic"],
        ),
    ):
        text = P[key].read_text(encoding="utf-8")
        errors.extend(
            f"{label} deterministic core contains forbidden capability: {token}"
            for token in tokens
            if token in text
        )
    return errors


def semantic_view(records):
    out = copy.deepcopy(records)
    for _, record in out:
        for evidence in record.get("evidence", []):
            evidence.pop("source_snapshot_id", None)
    return out


def psr_contract_errors(foundation, records):
    """Enforce the merged Phase 5.3.1 deterministic PSR identity contract."""
    errors = []
    for index, record in enumerate(records):
        payload = {
            key: record.get(key)
            for key in (
                "native_type",
                "native_key",
                "native_identifiers",
                "native_fields",
                "unknown_fields",
                "locator",
            )
        }
        expected_digest = foundation.sha256_digest(payload)
        if record.get("record_digest") != expected_digest:
            errors.append(f"PSR[{index}] record_digest diverges from Phase 5.3.1 ingestion contract")

        expected_id = foundation.stable_artifact_id(
            "parsed-source-record",
            {
                "source_snapshot_id": record.get("source_snapshot_id"),
                "parser_id": record.get("parser_id"),
                "parser_version": record.get("parser_version"),
                "psr_version": record.get("psr_version"),
                "native_type": record.get("native_type"),
                "native_key": record.get("native_key"),
                "record_digest": record.get("record_digest"),
            },
        )
        if record.get("parsed_record_id") != expected_id:
            errors.append(f"PSR[{index}] identity diverges from Phase 5.3.1 ingestion contract")
    return errors


def validate_repository(root=ROOT):
    errors = []
    foundation = mod("foundation_attack", root / "tools/ingestion/validate_ingestion_foundation.py")
    phase52 = mod("phase52_attack", root / "tools/validate_phase52.py")
    parser = mod("attack_parser", P["parser"])
    normalizer = mod("attack_norm", P["normalizer"])
    source, release, connector, parser_def, normalizer_def, mapping, fixture = [
        load(key)
        for key in ("source", "release", "connector", "parser_def", "normalizer_def", "mapping", "fixture")
    ]

    errors += serr(phase52.root_validator(), source, "SourceRecord")
    for schema, value, label in (
        ("connector-definition.schema.json", connector, "Connector"),
        ("parser-definition.schema.json", parser_def, "ParserDefinition"),
        ("normalizer-definition.schema.json", normalizer_def, "NormalizerDefinition"),
    ):
        errors += serr(foundation.ingestion_validator(schema), value, label)

    errors += pin_errors(release, connector)
    errors += security_errors()
    errors += foundation.validate_json_secret_surface(
        [source, release, connector, parser_def, normalizer_def, mapping, fixture]
    )
    if source.get("id") != SOURCE_ID or connector.get("source_id") != SOURCE_ID or mapping.get("source_id") != SOURCE_ID:
        errors.append("source identity binding mismatch")
    if source.get("source_class") != "tier-a-authoritative" or source.get("official_status") != "official":
        errors.append("MITRE source authority classification mismatch")
    if source.get("license", {}).get("status") != "verified" or source.get("redistribution", {}).get("policy") != "allowed":
        errors.append("MITRE license disposition missing")
    if mapping.get("profile_digest") != normalizer.mapping_profile_digest(mapping):
        errors.append("mapping profile digest mismatch")
    if parser_def.get("parser_id") != parser.PARSER_ID or normalizer_def.get("normalizer_id") != normalizer.NORMALIZER_ID:
        errors.append("definition/implementation identity mismatch")
    if P["fixture"].stat().st_size > 32768:
        errors.append("committed ATT&CK fixture too large")

    attacks = [item for item in fixture.get("objects", []) if item.get("type") == "attack-pattern"]
    collections = [item for item in fixture.get("objects", []) if item.get("type") == "x-mitre-collection"]
    if len(attacks) != 1 or "description" in attacks[0]:
        errors.append("fixture must contain one prose-free attack-pattern")
    if len(collections) != 1 or collections[0].get("id") != COLLECTION or collections[0].get("x_mitre_version") != VERSION:
        errors.append("fixture collection/release mismatch")

    first = parser.parse_bundle(copy.deepcopy(fixture), source_id=SOURCE_ID, source_snapshot_id=SNAPSHOT)
    second = parser.parse_bundle(copy.deepcopy(fixture), source_id=SOURCE_ID, source_snapshot_id=SNAPSHOT)
    if first != second or parser.representation_digest(first) != parser.representation_digest(second):
        errors.append("parser replay is non-deterministic")

    psr_validator = foundation.ingestion_validator("parsed-source-record.schema.json")
    for index, record in enumerate(first):
        errors += serr(psr_validator, record, f"PSR[{index}]")
    errors += psr_contract_errors(foundation, first)

    technique = next(record for record in first if record["native_type"] == "attack-pattern")
    if technique.get("unknown_fields", {}).get("x_mitre_future_field") != "preserve-me":
        errors.append("unknown source field not preserved")

    first_normalized = normalizer.normalize_psr(
        first, mapping_profile=mapping, source_version=VERSION, retrieved_at=RETRIEVED
    )
    second_normalized = normalizer.normalize_psr(
        second, mapping_profile=mapping, source_version=VERSION, retrieved_at=RETRIEVED
    )
    if first_normalized != second_normalized:
        errors.append("normalizer replay is non-deterministic")
    entity = next(
        (record for record in first_normalized["records"] if record.get("record_kind") == "entity"),
        None,
    )
    if (
        not entity
        or entity.get("id") != "atlas:attack-technique:mitre.attack:t1059.001"
        or entity.get("lifecycle", {}).get("state") != "current"
    ):
        errors.append("T1059.001 canonical/lifecycle mapping mismatch")
    if first_normalized["quarantined"]:
        errors.append("valid canary technique quarantined")

    synthetic = copy.deepcopy(technique)
    synthetic["native_fields"]["description"] = "Synthetic ATT&CK description for provenance testing only."
    claim_result = normalizer.normalize_psr(
        [synthetic], mapping_profile=mapping, source_version=VERSION, retrieved_at=RETRIEVED
    )
    claims = [record for record in claim_result["records"] if record["record_kind"] == "claim"]
    if (
        len(claims) != 1
        or claims[0]["confidence"] == "authoritative"
        or claims[0]["evidence"][0].get("source_snapshot_id") != SNAPSHOT
    ):
        errors.append("claim provenance/trust mapping mismatch")

    combined = [(P["source"], source)] + [
        (root / f"generated/attack/{index}.json", record)
        for index, record in enumerate(claim_result["records"])
    ]
    errors += phase52.validate_schema_records(combined)
    errors += phase52.validate_semantics(semantic_view(combined), phase52.load_registries())

    lineage_validator = foundation.ingestion_validator("normalization-lineage.schema.json")
    for index, lineage in enumerate(first_normalized["lineage"]):
        errors += serr(lineage_validator, lineage, f"Lineage[{index}]")
        digest = lineage_digest(normalizer, lineage)
        if (
            lineage.get("lineage_digest") != digest
            or lineage.get("lineage_id") != f"atlas:normalization-lineage:atlas.ingestion:{digest}"
        ):
            errors.append("lineage digest/id mismatch")
    return errors


def main():
    errors = validate_repository()
    if errors:
        print("Phase 5.3.2 ATT&CK canary validation FAILED")
        for error in errors:
            print("- " + error)
        return 1
    print(f"Phase 5.3.2 ATT&CK canary validation PASSED: Enterprise {VERSION} @ {COMMIT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
