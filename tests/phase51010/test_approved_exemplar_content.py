#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SYSMON_STRUCTURAL_DIGESTS = ROOT / "ingestion" / "inventories" / "sysmon-schema-15.22-4.91.structural-digests.json"


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
    assert validator.resolve_query(records, "Sysmon 1") == ["atlas:event:microsoft.sysmon:1"]
    assert validator.resolve_query(records, "ProcessCreate") == ["atlas:event:microsoft.sysmon:1"]
    assert validator.resolve_query(records, "Sysmon 2") == ["atlas:event:microsoft.sysmon:2"]
    assert validator.resolve_query(records, "FileCreateTime") == ["atlas:event:microsoft.sysmon:2"]
    assert validator.resolve_query(records, "Sysmon 3") == ["atlas:event:microsoft.sysmon:3"]
    assert validator.resolve_query(records, "NetworkConnect") == ["atlas:event:microsoft.sysmon:3"]
    assert validator.resolve_query(records, "Sysmon 4") == ["atlas:event:microsoft.sysmon:4"]
    assert validator.resolve_query(records, "ServiceStateChange") == ["atlas:event:microsoft.sysmon:4"]
    assert validator.resolve_query(records, "Sysmon 5") == ["atlas:event:microsoft.sysmon:5"]
    assert validator.resolve_query(records, "ProcessTerminate") == ["atlas:event:microsoft.sysmon:5"]
    assert validator.resolve_query(records, "Sysmon 6") == ["atlas:event:microsoft.sysmon:6"]
    assert validator.resolve_query(records, "DriverLoad") == ["atlas:event:microsoft.sysmon:6"]
    assert validator.resolve_query(records, "Sysmon 7") == ["atlas:event:microsoft.sysmon:7"]
    assert validator.resolve_query(records, "ImageLoad") == ["atlas:event:microsoft.sysmon:7"]
    assert validator.resolve_query(records, "Sysmon 8") == ["atlas:event:microsoft.sysmon:8"]
    assert validator.resolve_query(records, "CreateRemoteThread") == ["atlas:event:microsoft.sysmon:8"]
    assert validator.resolve_query(records, "Sysmon 9") == ["atlas:event:microsoft.sysmon:9"]
    assert validator.resolve_query(records, "RawAccessRead") == ["atlas:event:microsoft.sysmon:9"]
    assert validator.resolve_query(records, "Sysmon 10") == ["atlas:event:microsoft.sysmon:10"]
    assert validator.resolve_query(records, "ProcessAccess") == ["atlas:event:microsoft.sysmon:10"]
    assert validator.resolve_query(records, "Sysmon 11") == ["atlas:event:microsoft.sysmon:11"]
    assert validator.resolve_query(records, "FileCreate") == ["atlas:event:microsoft.sysmon:11"]
    assert validator.resolve_query(records, "Sysmon 12") == ["atlas:event:microsoft.sysmon:12"]
    assert validator.resolve_query(records, "Registry object added or deleted") == ["atlas:event:microsoft.sysmon:12"]
    assert validator.resolve_query(records, "Sysmon 13") == ["atlas:event:microsoft.sysmon:13"]
    assert validator.resolve_query(records, "Registry value set") == ["atlas:event:microsoft.sysmon:13"]
    assert validator.resolve_query(records, "Sysmon 14") == ["atlas:event:microsoft.sysmon:14"]
    assert validator.resolve_query(records, "Registry object renamed") == ["atlas:event:microsoft.sysmon:14"]
    assert validator.resolve_query(records, "Sysmon 15") == ["atlas:event:microsoft.sysmon:15"]
    assert validator.resolve_query(records, "Sysmon 16") == ["atlas:event:microsoft.sysmon:16"]
    assert validator.resolve_query(records, "ServiceConfigurationChange") == ["atlas:event:microsoft.sysmon:16"]
    assert validator.resolve_query(records, "Sysmon 17") == ["atlas:event:microsoft.sysmon:17"]
    assert validator.resolve_query(records, "Pipe Created") == ["atlas:event:microsoft.sysmon:17"]
    assert validator.resolve_query(records, "Sysmon 18") == ["atlas:event:microsoft.sysmon:18"]
    assert validator.resolve_query(records, "Pipe Connected") == ["atlas:event:microsoft.sysmon:18"]
    assert validator.resolve_query(records, "Sysmon 19") == ["atlas:event:microsoft.sysmon:19"]
    assert validator.resolve_query(records, "WmiEventFilter") == ["atlas:event:microsoft.sysmon:19"]
    assert validator.resolve_query(records, "Sysmon 20") == ["atlas:event:microsoft.sysmon:20"]
    assert validator.resolve_query(records, "WmiEventConsumer") == ["atlas:event:microsoft.sysmon:20"]
    assert validator.resolve_query(records, "Sysmon 21") == ["atlas:event:microsoft.sysmon:21"]
    assert validator.resolve_query(records, "WmiEventConsumerToFilter") == ["atlas:event:microsoft.sysmon:21"]
    assert validator.resolve_query(records, "Sysmon 22") == ["atlas:event:microsoft.sysmon:22"]
    assert validator.resolve_query(records, "DNSEvent") == ["atlas:event:microsoft.sysmon:22"]
    assert validator.resolve_query(records, "Sysmon 23") == ["atlas:event:microsoft.sysmon:23"]
    assert validator.resolve_query(records, "File Delete archived") == ["atlas:event:microsoft.sysmon:23"]
    assert validator.resolve_query(records, "Sysmon 24") == ["atlas:event:microsoft.sysmon:24"]
    assert validator.resolve_query(records, "ClipboardChange") == ["atlas:event:microsoft.sysmon:24"]
    assert validator.resolve_query(records, "Sysmon 25") == ["atlas:event:microsoft.sysmon:25"]
    assert validator.resolve_query(records, "ProcessTampering") == ["atlas:event:microsoft.sysmon:25"]
    assert validator.resolve_query(records, "Sysmon 26") == ["atlas:event:microsoft.sysmon:26"]
    assert validator.resolve_query(records, "FileDeleteDetected") == ["atlas:event:microsoft.sysmon:26"]
    assert validator.resolve_query(records, "Sysmon 27") == ["atlas:event:microsoft.sysmon:27"]
    assert validator.resolve_query(records, "FileBlockExecutable") == ["atlas:event:microsoft.sysmon:27"]
    assert validator.resolve_query(records, "Sysmon 28") == ["atlas:event:microsoft.sysmon:28"]
    assert validator.resolve_query(records, "FileBlockShredding") == ["atlas:event:microsoft.sysmon:28"]
    assert validator.resolve_query(records, "FileCreateStreamHash") == ["atlas:event:microsoft.sysmon:15"]


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

    assert len(field_ids) == 308
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


def test_08_sysmon_schema_refresh_validation_is_explicit():
    records = by_id(records_with_paths())
    claims = [
        r for r in records.values()
        if r.get("record_kind") == "claim"
        and r.get("predicate") == "telemetry.field-semantics"
        and r.get("subject_id", "").startswith("atlas:field:microsoft.sysmon:3.")
    ]
    assert claims
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_NETWORK_CONNECT / ")


def test_09_sysmon_1_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:1."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 23
    expected = {
        "rulename", "utctime", "processguid", "processid", "image",
        "fileversion", "description", "product", "company", "originalfilename",
        "commandline", "currentdirectory", "user", "logonguid", "logonid",
        "terminalsessionid", "integritylevel", "hashes", "parentprocessguid",
        "parentprocessid", "parentimage", "parentcommandline", "parentuser",
    }
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 23
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_CREATE_PROCESS / ")



def test_10_sysmon_2_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:2."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 9
    expected = {
        "rulename", "utctime", "processguid", "processid", "image",
        "targetfilename", "creationutctime", "previouscreationutctime", "user",
    }
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 9
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_FILE_TIME / ")



def test_10b_sysmon_4_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:4."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 4
    expected = {"utctime", "state", "version", "schemaversion"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 4
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_SERVICE_STATE_CHANGE / ")


def test_10c_sysmon_5_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:5."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 6
    expected = {"rulename", "utctime", "processguid", "processid", "image", "user"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 6
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_PROCESS_TERMINATE / ")


def test_10d_sysmon_6_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:6."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 7
    expected = {"rulename", "utctime", "imageloaded", "hashes", "signed", "signature", "signaturestatus"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 7
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_DRIVER_LOAD / ")


def test_10e_sysmon_7_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:7."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 16
    expected = {
        "rulename", "utctime", "processguid", "processid", "image", "imageloaded",
        "fileversion", "description", "product", "company", "originalfilename",
        "hashes", "signed", "signature", "signaturestatus", "user"
    }
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 16
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_IMAGE_LOAD / ")


def test_10f_sysmon_8_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:8."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 14
    expected = {
        "rulename", "utctime", "sourceprocessguid", "sourceprocessid", "sourceimage",
        "targetprocessguid", "targetprocessid", "targetimage", "newthreadid",
        "startaddress", "startmodule", "startfunction", "sourceuser", "targetuser"
    }
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 14
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_CREATE_REMOTE_THREAD / ")


def test_10g_sysmon_9_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:9."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 7
    expected = {"rulename", "utctime", "processguid", "processid", "image", "device", "user"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 7
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_RAWACCESS_READ / ")


def test_10h_sysmon_10_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:10."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 13
    expected = {
        "rulename", "utctime", "sourceprocessguid", "sourceprocessid", "sourcethreadid",
        "sourceimage", "targetprocessguid", "targetprocessid", "targetimage",
        "grantedaccess", "calltrace", "sourceuser", "targetuser"
    }
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 13
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_ACCESS_PROCESS / ")


def test_10i_sysmon_11_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:11."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 8
    expected = {"rulename", "utctime", "processguid", "processid", "image", "targetfilename", "creationutctime", "user"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 8
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_FILE_CREATE / ")


def test_10j_sysmon_12_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:12."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 8
    expected = {"rulename", "eventtype", "utctime", "processguid", "processid", "image", "targetobject", "user"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 8
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_REG_KEY / ")


def test_10k_sysmon_13_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:13."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 9
    expected = {"rulename", "eventtype", "utctime", "processguid", "processid", "image", "targetobject", "details", "user"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 9
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_REG_SETVALUE / ")


def test_10l_sysmon_14_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:14."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 9
    expected = {"rulename", "eventtype", "utctime", "processguid", "processid", "image", "targetobject", "newname", "user"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 9
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_REG_NAME / ")


def test_10m_sysmon_15_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:15."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 10
    expected = {"rulename", "utctime", "processguid", "processid", "image", "targetfilename", "creationutctime", "hash", "contents", "user"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 10
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_FILE_CREATE_STREAM_HASH / ")


def test_10n_sysmon_16_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:16."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 3
    expected = {"utctime", "configuration", "configurationfilehash"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 3
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_SERVICE_CONFIGURATION_CHANGE / ")


def test_10o_sysmon_17_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:17."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 8
    expected = {"rulename", "eventtype", "utctime", "processguid", "processid", "pipename", "image", "user"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 8
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_CREATE_NAMEDPIPE / ")


def test_10p_sysmon_18_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:18."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 8
    expected = {"rulename", "eventtype", "utctime", "processguid", "processid", "pipename", "image", "user"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 8
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_CONNECT_NAMEDPIPE / ")


def test_10q_sysmon_19_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:19."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 8
    expected = {"rulename", "eventtype", "utctime", "operation", "user", "eventnamespace", "name", "query"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 8
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_WMI_FILTER / ")


def test_10r_sysmon_20_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:20."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 8
    expected = {"rulename", "eventtype", "utctime", "operation", "user", "name", "type", "destination"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 8
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_WMI_CONSUMER / ")


def test_10s_sysmon_21_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:21."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 7
    expected = {"rulename", "eventtype", "utctime", "operation", "user", "consumer", "filter"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 7
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_WMI_BINDING / ")


def test_10t_sysmon_22_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:22."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 9
    expected = {"rulename", "utctime", "processguid", "processid", "queryname", "querystatus", "queryresults", "image", "user"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 9
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_DNS_QUERY / ")


def test_10u_sysmon_23_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:23."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 10
    expected = {"rulename", "utctime", "processguid", "processid", "user", "image", "targetfilename", "hashes", "isexecutable", "archived"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 10
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_FILE_DELETE / ")


def test_10v_sysmon_24_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:24."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 10
    expected = {"rulename", "utctime", "processguid", "processid", "image", "session", "clientinfo", "hashes", "archived", "user"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 10
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_CLIPBOARD / ")


def test_10w_sysmon_25_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:25."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 7
    expected = {"rulename", "utctime", "processguid", "processid", "image", "type", "user"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected

    claims = [
        record for record in records.values()
        if record.get("record_kind") == "claim"
        and record.get("predicate") == "telemetry.field-semantics"
        and record.get("subject_id", "").startswith(prefix)
    ]
    assert len(claims) == 7
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [
            item for item in record["evidence"]
            if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"
        ]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_PROCESS_IMAGE_TAMPERING / ")


def test_10x_sysmon_26_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:26."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 9
    expected = {"rulename", "utctime", "processguid", "processid", "user", "image", "targetfilename", "hashes", "isexecutable"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected
    claims = [record for record in records.values() if record.get("record_kind") == "claim" and record.get("predicate") == "telemetry.field-semantics" and record.get("subject_id", "").startswith(prefix)]
    assert len(claims) == 9
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [item for item in record["evidence"] if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_FILE_DELETE_DETECTED / ")


def test_10y_sysmon_27_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:27."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 8
    expected = {"rulename", "utctime", "processguid", "processid", "user", "image", "targetfilename", "hashes"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected
    claims = [record for record in records.values() if record.get("record_kind") == "claim" and record.get("predicate") == "telemetry.field-semantics" and record.get("subject_id", "").startswith(prefix)]
    assert len(claims) == 8
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [item for item in record["evidence"] if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_FILE_BLOCK_EXE / ")


def test_10z_sysmon_28_field_dictionary_and_schema_evidence_are_complete():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.sysmon:28."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 9
    expected = {"rulename", "utctime", "processguid", "processid", "user", "image", "targetfilename", "hashes", "isexecutable"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected
    claims = [record for record in records.values() if record.get("record_kind") == "claim" and record.get("predicate") == "telemetry.field-semantics" and record.get("subject_id", "").startswith(prefix)]
    assert len(claims) == 9
    for record in claims:
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [item for item in record["evidence"] if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_FILE_BLOCK_SHREDDING / ")

def test_10aa_sysmon_29_field_dictionary_and_schema_evidence_are_complete():
    prefix = "atlas:field:microsoft.sysmon:29."
    fields = [record["subject"] for record in RECORDS if record.get("predicate") == "has_field" and record.get("subject", "").startswith(prefix)]
    expected = {"rulename", "utctime", "processguid", "processid", "user", "image", "targetfilename", "hashes"}
    assert {value.rsplit(":", 1)[-1].split(".", 1)[1] for value in fields} == expected
    event = next(item for item in APPROVED["events"] if item["id"] == "atlas:event:microsoft.sysmon:29")
    assert event["source_version"] == "15.22"
    assert event["schema_locator"] == "SYSMONEVENT_FILE_EXE_DETECTED"
    for record in RECORDS:
        if record.get("subject") not in fields:
            continue
        assert record["object"]["value"]["structural_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
        schema_evidence = [item for item in record["evidence"] if item.get("source_id") == "atlas:source:atlas.source:microsoft-sysmon-schema-export"]
        assert len(schema_evidence) == 1
        assert schema_evidence[0]["source_version"] == "sysmon-15.22-schema-4.91"
        assert schema_evidence[0]["locator"]["other"].startswith("SYSMONEVENT_FILE_EXE_DETECTED / ")


def test_11_sysmon_approved_field_sets_match_controlled_15_22_structural_digests():
    approved = json.loads((ROOT / "content" / "encyclopedia" / "approved-exemplars.json").read_text(encoding="utf-8"))
    manifest = json.loads(SYSMON_STRUCTURAL_DIGESTS.read_text(encoding="utf-8"))
    assert manifest["source_version"] == "sysmon-15.22-schema-4.91"
    assert manifest["event_count"] == 30
    by_event = {item["event_id"]: item for item in manifest["events"]}

    for event in approved["events"]:
        if event.get("namespace") != "microsoft.sysmon":
            continue
        structural = by_event[event["native_event_id"]]
        native_names = [field["native_name"] for field in event["fields"]]
        digest = "sha256-" + hashlib.sha256("\n".join(native_names).encode("utf-8")).hexdigest()
        assert len(native_names) == structural["field_count"]
        assert digest == structural["field_names_sha256"]
        assert event["schema_locator"] == structural["event_name"]
        assert event["overview"]["schema_event_version"] == structural["event_version"]



def test_20_windows_4688_field_dictionary_matches_approved_exemplar():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.windows.security:4688."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 15
    required = {
        "4688.creator-subject.security-id",
        "4688.creator-subject.logon-id",
        "4688.target-subject.security-id",
        "4688.target-subject.logon-id",
        "4688.process-information.new-process-id",
        "4688.process-information.new-process-name",
        "4688.process-information.token-elevation-type",
        "4688.process-information.mandatory-label",
        "4688.process-information.creator-process-id",
        "4688.process-information.creator-process-name",
        "4688.process-information.process-command-line",
    }
    actual = {value.rsplit(":", 1)[-1] for value in fields}
    assert required <= actual


def test_21_windows_4688_value_dictionaries_and_uws_boundary():
    records = by_id(records_with_paths())
    event_claims = [
        r for r in records.values()
        if r.get("record_kind") == "claim"
        and r.get("subject_id") == "atlas:event:microsoft.windows.security:4688"
        and r.get("predicate") == "telemetry.field-semantics"
    ]
    dictionaries = [
        r["object"]["value"].get("event_value_dictionaries", {})
        for r in event_claims
        if r.get("object", {}).get("kind") == "json"
    ]
    token = next(value["token_elevation_type"] for value in dictionaries if "token_elevation_type" in value)
    assert [row["value"] for row in token] == ["%%1936", "%%1937", "%%1938"]
    integrity = next(value["mandatory_integrity_level"] for value in dictionaries if "mandatory_integrity_level" in value)
    assert [row["sid"] for row in integrity] == [
        "S-1-16-0",
        "S-1-16-4096",
        "S-1-16-8192",
        "S-1-16-8448",
        "S-1-16-12288",
        "S-1-16-16384",
        "S-1-16-20480",
    ]

    source = records["atlas:source:atlas.source:ultimate-windows-security-event-4688"]
    assert source["redistribution"]["policy"] == "prohibited"
    uws_evidence = [
        r for r in records.values()
        if r.get("record_kind") == "claim"
        and any(e.get("source_id") == source["id"] for e in r.get("evidence", []))
    ]
    assert len(uws_evidence) == 1
    assert uws_evidence[0]["predicate"] == "telemetry.source"
    assert uws_evidence[0]["object"]["value"]["redistribution"] == "source-link-and-coverage-benchmark-only"


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
            print(f"PASS {name}")
