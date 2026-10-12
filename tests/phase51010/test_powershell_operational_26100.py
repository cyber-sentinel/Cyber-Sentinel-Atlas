#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
IDS = [
    "4100","4101","4102","4103","4104","4105","4106","8193","8194","8195","8196","8197","8198",
    "12039","24577","24578","24579","24580","24581","24582","24583","24584","24592","24593","24594",
    "24595","24596","24597","24598","24599","32777","32784","40961","40962","46358","53249","53250",
    "53251","53504","53505","53506","53507","53508",
]
SOURCE_ID = "atlas:source:atlas.source:microsoft-windows-powershell-operational-provider-26100"
RAW_SHA = "sha256-cdd3f6b37731ebc384e160743893ac3a53e9457e60b2b9438e4c5b585c793f25"
NORMALIZED_SHA = "sha256-48f42f368d6b1e3c6235a9a03252288ab4981cb64ba824664821842112a6aaf0"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


builder = load_module("powershell_builder", ROOT / "tools/content/build_powershell_operational_records.py")
validator = load_module("powershell_validator", ROOT / "tools/validate_phase52.py")


def records():
    return builder.build_records()


def by_id():
    return {item["id"]: item for item in records()}


def governed_events():
    events = []
    for path in sorted((ROOT / "content/encyclopedia").glob("powershell-operational-26100-batch*.json")):
        batch = json.loads(path.read_text(encoding="utf-8"))
        events.extend(batch["events"])
    return {str(item["native_event_id"]): item for item in events}


def test_01_canonical_records_validate_v1():
    pairs = [(ROOT / "content/encyclopedia/powershell-operational-26100-batch01.json", item) for item in records()]
    errors = validator.validate_schema_records(pairs)
    errors += validator.validate_semantics(pairs, validator.load_registries())
    assert errors == [], "\n".join(errors)


def test_02_exact_denominator_and_field_projection():
    data = by_id()
    event_ids = sorted([
        item["canonical_key"] for item in data.values()
        if item.get("record_kind") == "entity" and item.get("entity_type") == "event"
    ], key=int)
    assert event_ids == IDS
    fields = [
        item for item in data.values()
        if item.get("record_kind") == "entity" and item.get("entity_type") == "field"
    ]
    assert len(fields) == 71


def test_03_coverage_snapshot_is_43_of_43():
    snapshot = json.loads((ROOT / "content/encyclopedia/powershell-operational-26100-coverage.snapshot.json").read_text(encoding="utf-8"))
    assert snapshot["provider"] == "Microsoft-Windows-PowerShell"
    assert snapshot["channel"] == "Microsoft-Windows-PowerShell/Operational"
    assert snapshot["denominator_count"] == 43
    assert snapshot["provider_event_version_definition_count"] == 43
    assert snapshot["encyclopedia_grade_count"] == 43
    assert snapshot["remaining_count"] == 0
    assert snapshot["completion_ratio"] == "43/43"
    assert snapshot["completion_percent"] == 100.0
    assert [row["event_id"] for row in snapshot["events"]] == IDS
    assert all(row["coverage_state"] == "ENCYCLOPEDIA_GRADE" for row in snapshot["events"])


def test_04_high_value_field_shapes_are_exact():
    events = governed_events()
    expected = {
        "4104": {"MessageNumber", "MessageTotal", "ScriptBlockText", "ScriptBlockId", "Path"},
        "4105": {"ScriptBlockId", "RunspaceId"},
        "4106": {"ScriptBlockId", "RunspaceId"},
        "32784": {"SessionId", "PipelineId", "ErrorCode", "ErrorMessage", "StackTrace"},
        "53249": {"ScheduledJobDefName", "StartTime"},
        "53250": {"ScheduledJobDefName", "StopTime", "State"},
        "53251": {"Name", "Message", "StackTrace", "InnerException"},
    }
    for event_id, names in expected.items():
        assert {field["native_name"] for field in events[event_id]["fields"]} == names


def test_05_search_identities_support_analyst_scoping():
    pairs = [(ROOT / "content/encyclopedia/powershell-operational-26100-batch01.json", item) for item in records()]
    target = "atlas:event:microsoft.windows.powershell:4104"
    assert validator.resolve_query(pairs, "PowerShell 4104") == [target]
    assert validator.resolve_query(pairs, "PowerShell Event 4104") == [target]
    assert validator.resolve_query(pairs, "4104", namespace="microsoft.windows.powershell") == [target]


def test_06_logging_prerequisites_and_volume_are_explicit():
    events = governed_events()
    prereq_4103 = " ".join(events["4103"]["collection"]["prerequisites"])
    prereq_4104 = " ".join(events["4104"]["collection"]["prerequisites"])
    prereq_4105 = " ".join(events["4105"]["collection"]["prerequisites"])
    prereq_4106 = " ".join(events["4106"]["collection"]["prerequisites"])
    assert "Module Logging" in prereq_4103
    assert "Script Block Logging" in prereq_4104
    assert "Invocation Logging" in prereq_4105
    assert "Invocation Logging" in prereq_4106
    assert events["4105"]["collection"]["volume"] == "high"
    assert events["4106"]["collection"]["volume"] == "high"


def test_07_source_provenance_is_restricted_and_public_safe():
    source_path = ROOT / "content/encyclopedia/sources/microsoft-windows-powershell-operational-provider-26100.json"
    source = json.loads(source_path.read_text(encoding="utf-8"))
    assert source["id"] == SOURCE_ID
    assert source["source_class"] == "tier-a-authoritative"
    assert source["official_status"] == "official"
    assert source["redistribution"]["policy"] == "restricted"
    text = source_path.read_text(encoding="utf-8")
    assert RAW_SHA in text
    assert NORMALIZED_SHA in text
    assert "sec-ai-orchestrator-control" not in text
    assert "38159654021" not in text
    assert "11709088620" not in text


def test_08_inventory_is_bound_to_exact_provider_scope():
    path = ROOT / "ingestion/inventories/windows-powershell-operational-26100.telemetry.json"
    inv = json.loads(path.read_text(encoding="utf-8"))
    scope = inv["scope_metadata"]
    assert inv["expected_identity_count"] == 43
    assert scope["provider"] == "Microsoft-Windows-PowerShell"
    assert scope["channel"] == "Microsoft-Windows-PowerShell/Operational"
    assert scope["windows_build"] == "26100"
    assert scope["provider_event_version_definition_count"] == 43
    assert scope["provider_unique_event_id_count"] == 43
    assert scope["raw_artifact_sha256"] == RAW_SHA
    assert scope["normalized_private_inventory_sha256"] == NORMALIZED_SHA
    assert [row["event_id"] for row in scope["expected_identities"]] == IDS
    text = path.read_text(encoding="utf-8")
    assert "sec-ai-orchestrator-control" not in text
    assert "38159654021" not in text
    assert "11709088620" not in text


def test_09_every_event_and_field_is_source_backed():
    data = by_id()
    for event_id in IDS:
        subject = f"atlas:event:microsoft.windows.powershell:{event_id}"
        claims = [
            item for item in data.values()
            if item.get("record_kind") == "claim" and item.get("subject_id") == subject
        ]
        assert any(item.get("predicate") == "telemetry.represents" for item in claims)
        assert any(item.get("predicate") == "security.relevance" for item in claims)
        assert any(item.get("predicate") == "telemetry.requires-policy" for item in claims)
        assert all(SOURCE_ID in {ev.get("source_id") for ev in item.get("evidence", [])} for item in claims)

    field_claims = [
        item for item in data.values()
        if item.get("record_kind") == "claim" and item.get("predicate") == "telemetry.field-semantics"
    ]
    assert len(field_claims) == 71
    assert all(SOURCE_ID in {ev.get("source_id") for ev in item.get("evidence", [])} for item in field_claims)
