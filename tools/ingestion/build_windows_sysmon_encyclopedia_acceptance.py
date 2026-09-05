#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def mod(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


foundation = mod("ws_acceptance_foundation", ROOT / "tools/ingestion/validate_ingestion_foundation.py")
windows_parser = mod("ws_acceptance_windows_parser", ROOT / "ingestion/parsers/microsoft_windows_security_event_html.py")
windows_normalizer = mod("ws_acceptance_windows_normalizer", ROOT / "ingestion/normalizers/microsoft_windows_security_event_doc.py")
sysmon_parser = mod("ws_acceptance_sysmon_parser", ROOT / "ingestion/parsers/microsoft_sysmon_markdown.py")
sysmon_normalizer = mod("ws_acceptance_sysmon_normalizer", ROOT / "ingestion/normalizers/microsoft_sysmon_docs.py")

WINDOWS_SOURCE_ID = "atlas:source:atlas.source:microsoft-windows-security-auditing-4688-doc"
WINDOWS_SNAPSHOT_ID = "atlas:raw-snapshot:atlas.ingestion:windows-4688-acceptance"
SYSMON_SOURCE_ID = "atlas:source:atlas.source:microsoft-sysmon-docs"
SYSMON_SNAPSHOT_ID = "atlas:raw-snapshot:atlas.ingestion:sysmon-docs-acceptance"
RETRIEVED_AT = "2026-09-05T13:03:53Z"


def load(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def _event_ids(inventory: dict) -> set[str]:
    return {
        item["event_id"]
        for item in inventory.get("scope_metadata", {}).get("expected_identities", [])
        if isinstance(item, dict) and isinstance(item.get("event_id"), str)
    }


def _legacy_592() -> dict:
    return {
        "schema_version": "1.0.0",
        "record_kind": "entity",
        "id": "atlas:event:microsoft.windows.security:592",
        "record_revision": 1,
        "created_at": RETRIEVED_AT,
        "updated_at": RETRIEVED_AT,
        "curation_status": "draft",
        "entity_type": "event",
        "namespace": "microsoft.windows.security",
        "canonical_key": "592",
        "title": "Windows Security Event 592 (legacy acceptance identity)",
        "native_identifiers": [
            {
                "type": "event_id",
                "value": "592",
                "namespace": "microsoft.windows.security",
                "context": {
                    "channel": "Security",
                    "platform": "Windows",
                    "legacy_scheme": "pre-vista-security-event-id"
                },
                "case_sensitive": False,
                "primary": True,
                "components": {
                    "acceptance_fixture": True,
                    "current_provider_inventory_status": "not-observed",
                    "identity_preservation_rule": "NOT_OBSERVED != REMOVED"
                }
            }
        ],
        "lifecycle": {"state": "legacy"}
    }


def build_acceptance_corpus() -> dict:
    windows_mapping = load("ingestion/mappings/microsoft-windows-security-event-doc-v1.json")
    windows_release = load("ingestion/source-profiles/microsoft-windows-security-auditing-4688-doc.release.json")
    windows_inventory = load("ingestion/inventories/windows-security-auditing-provider-26100.33296.telemetry.json")
    windows_doc_inventory = load("ingestion/inventories/windows-security-4688-doc-learn-page-2022-01-24.documentation.json")
    windows_html = (ROOT / "fixtures/phase-5.3/windows-security-4688.synthetic.html").read_text(encoding="utf-8")
    windows_psr = windows_parser.parse_html(
        windows_html,
        source_id=WINDOWS_SOURCE_ID,
        source_snapshot_id=WINDOWS_SNAPSHOT_ID,
    )
    windows_result = windows_normalizer.normalize_psr(
        windows_psr,
        mapping_profile=copy.deepcopy(windows_mapping),
        source_version=windows_release["source_version"],
        retrieved_at=RETRIEVED_AT,
    )
    if len(windows_result["records"]) != 1:
        raise ValueError("Windows 4688 acceptance fixture must normalize to exactly one canonical entity")
    windows_4688 = copy.deepcopy(windows_result["records"][0])
    if windows_4688["canonical_key"] not in _event_ids(windows_inventory):
        raise ValueError("Windows 4688 documentation candidate is absent from current provider inventory")
    if windows_4688["canonical_key"] not in _event_ids(windows_doc_inventory):
        raise ValueError("Windows 4688 documentation candidate is absent from its declared documentation inventory")
    windows_4688["lifecycle"] = {"state": "current"}

    sysmon_mapping = load("ingestion/mappings/microsoft-sysmon-docs-v1.json")
    sysmon_release = load("ingestion/source-profiles/microsoft-sysmon-docs.release.json")
    sysmon_inventory = load("ingestion/inventories/sysmon-schema-15.21-4.91.telemetry.json")
    sysmon_doc_inventory = load("ingestion/inventories/sysmon-docs-15.21.documentation.json")
    sysmon_markdown = (ROOT / "fixtures/phase-5.3/sysmon-docs.synthetic.md").read_text(encoding="utf-8")
    sysmon_psr = sysmon_parser.parse_markdown(
        sysmon_markdown,
        source_id=SYSMON_SOURCE_ID,
        source_snapshot_id=SYSMON_SNAPSHOT_ID,
    )
    sysmon_result = sysmon_normalizer.normalize_psr(
        sysmon_psr,
        mapping_profile=copy.deepcopy(sysmon_mapping),
        source_version=sysmon_release["release_version"],
        retrieved_at=RETRIEVED_AT,
    )
    sysmon_one = next((copy.deepcopy(r) for r in sysmon_result["records"] if r["canonical_key"] == "1"), None)
    if sysmon_one is None:
        raise ValueError("Sysmon Event ID 1 acceptance fixture did not normalize")
    if "1" not in _event_ids(sysmon_inventory):
        raise ValueError("Sysmon Event ID 1 is absent from current schema inventory")
    if "1" not in _event_ids(sysmon_doc_inventory):
        raise ValueError("Sysmon Event ID 1 is absent from documentation inventory")
    sysmon_one["lifecycle"] = {"state": "current"}

    legacy_592 = _legacy_592()
    if "592" in _event_ids(windows_inventory):
        raise ValueError("legacy Windows Event ID 592 unexpectedly appears in current provider inventory")

    records = sorted([windows_4688, legacy_592, sysmon_one], key=lambda r: r["id"])
    lineages = sorted(
        [
            *[lineage for lineage in windows_result["lineage"] if lineage["output_record_id"] == windows_4688["id"]],
            *[lineage for lineage in sysmon_result["lineage"] if lineage["output_record_id"] == sysmon_one["id"]],
        ],
        key=lambda r: r["output_record_id"],
    )
    return {
        "acceptance_contract": "phase-5.3.3-windows-sysmon-encyclopedia-v1",
        "fixture_only": True,
        "pack_ready": False,
        "records": records,
        "lineage": lineages,
        "inventory_bindings": {
            "windows_provider": {
                "inventory_id": windows_inventory["inventory_id"],
                "digest": windows_inventory["digest"],
                "expected_identity_count": windows_inventory["expected_identity_count"],
            },
            "windows_documentation": {
                "inventory_id": windows_doc_inventory["inventory_id"],
                "digest": windows_doc_inventory["digest"],
                "expected_identity_count": windows_doc_inventory["expected_identity_count"],
            },
            "sysmon_schema": {
                "inventory_id": sysmon_inventory["inventory_id"],
                "digest": sysmon_inventory["digest"],
                "expected_identity_count": sysmon_inventory["expected_identity_count"],
            },
            "sysmon_documentation": {
                "inventory_id": sysmon_doc_inventory["inventory_id"],
                "digest": sysmon_doc_inventory["digest"],
                "expected_identity_count": sysmon_doc_inventory["expected_identity_count"],
            },
        },
        "acceptance_semantics": {
            "windows_4688_current_by_provider_inventory": True,
            "sysmon_1_current_by_schema_inventory": True,
            "legacy_592_preserved_when_not_observed": True,
            "legacy_592_is_alias_of_4688": False,
            "event_id_is_globally_unique": False,
            "phase54_search_projection_materialized": False,
            "documentation_and_telemetry_coverage_are_independent": True,
        },
        "candidate_digest": foundation.sha256_digest(records),
        "diagnostics": [
            "This is a deterministic production-like acceptance corpus built from sanitized fixtures plus digest-bound real inventory definitions; it is not released content and is not PACK_READY.",
            "The lifecycle overlay is permitted only after exact membership in the corresponding real provider/schema inventory is established.",
            "Legacy Event ID 592 remains an independent synthetic acceptance identity until a dedicated historical source ingestion path authors material historical claims."
        ],
    }


def main() -> int:
    result = build_acceptance_corpus()
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
