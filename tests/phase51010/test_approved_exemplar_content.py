#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load_module("encyclopedia_builder", ROOT / "tools/content/build_encyclopedia_records.py")
validator = load_module("phase52_validator", ROOT / "tools/validate_phase52.py")


def records_with_paths():
    records = builder.build_records()
    path = ROOT / "content/encyclopedia/approved-exemplars.json"
    return [(path, record) for record in records]


def by_id(records):
    return {record["id"]: record for _, record in records}


def test_01_exemplar_records_validate_canonical_v1():
    records = records_with_paths()
    errors = validator.validate_schema_records(records)
    errors += validator.validate_semantics(records, validator.load_registries())
    assert errors == [], "\n".join(errors)


def test_02_approved_event_identities_and_search_aliases():
    records = records_with_paths()
    assert validator.resolve_query(records, "4624") == ["atlas:event:microsoft.windows.security:4624"]
    assert validator.resolve_query(records, "Windows 4624") == ["atlas:event:microsoft.windows.security:4624"]
    assert validator.resolve_query(records, "Sysmon 3") == ["atlas:event:microsoft.sysmon:3"]
    assert validator.resolve_query(records, "NetworkConnect") == ["atlas:event:microsoft.sysmon:3"]


def test_03_sysmon_3_field_dictionary_is_complete_for_approved_exemplar():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:3."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 18
    expected = {
        "rulename", "utctime", "processguid", "processid", "image", "user",
        "protocol", "initiated", "sourceisipv6", "sourceip", "sourcehostname",
        "sourceport", "sourceportname", "destinationisipv6", "destinationip",
        "destinationhostname", "destinationport", "destinationportname",
    }
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected


def test_04_windows_4624_field_dictionary_matches_approved_exemplar():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.windows.security:4624."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 28
    required = {
        "4624.logon-information.logon-type",
        "4624.logon-information.restricted-admin-mode",
        "4624.logon-information.remote-credential-guard",
        "4624.logon-information.virtual-account",
        "4624.logon-information.elevated-token",
        "4624.impersonation-level",
        "4624.new-logon.logon-id",
        "4624.new-logon.linked-logon-id",
        "4624.new-logon.logon-guid",
        "4624.process-information.process-id",
        "4624.network-information.source-network-address",
        "4624.authentication.authentication-package",
        "4624.authentication.key-length",
    }
    actual = {value.rsplit(":", 1)[-1] for value in fields}
    assert required <= actual


def test_05_every_field_has_one_semantics_claim_and_has_field_relationship():
    records = by_id(records_with_paths())
    fields = [r for r in records.values() if r.get("record_kind") == "entity" and r.get("entity_type") == "field"]
    claims = [r for r in records.values() if r.get("record_kind") == "claim" and r.get("predicate") == "telemetry.field-semantics"]
    rels = [r for r in records.values() if r.get("record_kind") == "relationship" and r.get("relationship_type") == "HAS_FIELD"]

    field_ids = {r["id"] for r in fields}
    claim_subjects = {r["subject_id"] for r in claims if r["subject_id"] in field_ids}
    relationship_targets = {r["to"] for r in rels}

    assert len(field_ids) == 46
    assert claim_subjects == field_ids
    assert relationship_targets == field_ids


def test_06_windows_4624_logon_dictionary_is_complete_for_approved_values():
    records = by_id(records_with_paths())
    event_claims = [
        r for r in records.values()
        if r.get("record_kind") == "claim"
        and r.get("subject_id") == "atlas:event:microsoft.windows.security:4624"
        and r.get("predicate") == "telemetry.field-semantics"
    ]
    dictionaries = [
        r["object"]["value"].get("event_value_dictionaries", {})
        for r in event_claims
        if r.get("object", {}).get("kind") == "json"
    ]
    logon = next(value["logon_type"] for value in dictionaries if "logon_type" in value)
    assert [row["value"] for row in logon] == [0, 2, 3, 4, 5, 7, 8, 9, 10, 11]


def test_07_uws_is_reference_only_not_claim_prose_source():
    records = by_id(records_with_paths())
    source = records["atlas:source:atlas.source:ultimate-windows-security-event-4624"]
    assert source["redistribution"]["policy"] == "prohibited"
    claims = [r for r in records.values() if r.get("record_kind") == "claim"]
    uws_evidence = [
        r for r in claims
        if any(e.get("source_id") == source["id"] for e in r.get("evidence", []))
    ]
    assert len(uws_evidence) == 1
    assert uws_evidence[0]["predicate"] == "telemetry.source"
    assert uws_evidence[0]["object"]["value"]["redistribution"] == "source-link-and-coverage-benchmark-only"


def test_08_sysmon_schema_refresh_warning_is_explicit():
    records = by_id(records_with_paths())
    claims = [
        r for r in records.values()
        if r.get("record_kind") == "claim"
        and r.get("predicate") == "telemetry.field-semantics"
        and r.get("subject_id", "").startswith("atlas:field:microsoft.sysmon:3.")
    ]
    assert claims
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "PENDING_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
            print(f"PASS {name}")
