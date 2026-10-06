#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; IDS=["1100","1101","1102","1104","1105","1108"]; STRUCTURAL="atlas:source:atlas.source:microsoft-windows-eventlog-provider-26100-1100-series"
def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
builder=load_module("eventlog1100_builder",ROOT/"tools/content/build_encyclopedia_records.py"); validator=load_module("eventlog1100_validator",ROOT/"tools/validate_phase52.py")
def records(): return builder.build_records()
def by_id(): return {item["id"]:item for item in records()}
def blueprint_by_native():
    doc=json.loads((ROOT/"content/encyclopedia/approved-exemplars.json").read_text(encoding="utf-8")); return {str(item["native_event_id"]):item for item in doc["events"] if item.get("namespace")=="microsoft.windows.security"}
def test_01_batch_records_validate_canonical_v1():
    pairs=[(ROOT/"content/encyclopedia/approved-exemplars.json",item) for item in records()]; errors=validator.validate_schema_records(pairs); errors+=validator.validate_semantics(pairs,validator.load_registries()); assert errors==[],"\n".join(errors)
def test_02_eventlog_provider_and_search_identities():
    pairs=[(ROOT/"content/encyclopedia/approved-exemplars.json",item) for item in records()]; data=by_id()
    for event_id in IDS:
        rid=f"atlas:event:microsoft.windows.security:{event_id}"; assert rid in data; context=data[rid]["native_identifiers"][0]["context"]; assert context["provider"]=="Microsoft-Windows-Eventlog"; assert context["channel"]=="Security"; assert validator.resolve_query(pairs,event_id)==[rid]
def test_03_version_aware_field_shapes_match_provider_inventory():
    bp=blueprint_by_native(); expected={"1100":{"0":0},"1101":{"0":1},"1102":{"0":4,"1":6},"1104":{"0":0},"1105":{"0":2},"1108":{"0":3}}
    for event_id,want in expected.items(): assert {row["version"]:row["field_count"] for row in bp[event_id]["overview"]["event_versions"]}==want
    assert bp["1100"]["fields"]==[] and bp["1104"]["fields"]==[]; assert {f["native_name"] for f in bp["1101"]["fields"]}=={"Reason"}; assert {f["native_name"] for f in bp["1105"]["fields"]}=={"Channel","BackupPath"}; assert {f["native_name"] for f in bp["1108"]["fields"]}=={"ErrorCode","EventID","PubID"}; assert {f["native_name"] for f in bp["1102"]["fields"] if f.get("versions")==["1"]}=={"ClientProcessId","ClientProcessStartKey"}
def test_04_structural_provider_evidence_is_attached():
    data=by_id()
    for event_id in IDS:
        subject=f"atlas:event:microsoft.windows.security:{event_id}"; represents=[item for item in data.values() if item.get("record_kind")=="claim" and item.get("subject_id")==subject and item.get("predicate")=="telemetry.represents"]; assert len(represents)==1; assert STRUCTURAL in {ev["source_id"] for ev in represents[0]["evidence"]}
    for event_id in ["1101","1102","1105","1108"]:
        prefix=f"atlas:field:microsoft.windows.security:{event_id}."; claims=[item for item in data.values() if item.get("record_kind")=="claim" and item.get("predicate")=="telemetry.field-semantics" and str(item.get("subject_id","")).startswith(prefix)]; assert claims
        for item in claims: assert STRUCTURAL in {ev["source_id"] for ev in item["evidence"]}
def test_05_uws_is_reference_only_and_not_semantic_authority():
    data=by_id()
    for event_id in IDS:
        source_id=f"atlas:source:atlas.source:ultimate-windows-security-event-{event_id}"; source=data[source_id]; assert source["redistribution"]["policy"]=="prohibited"; subject=f"atlas:event:microsoft.windows.security:{event_id}"; claims=[item for item in data.values() if item.get("record_kind")=="claim" and item.get("subject_id")==subject and item.get("predicate")=="telemetry.source" and any(ev.get("source_id")==source_id for ev in item.get("evidence",[]))]; assert len(claims)==1; assert claims[0]["object"]["value"]["redistribution"]=="source-link-and-coverage-benchmark-only"
def test_06_benchmark_progress_is_separate_from_security_auditing_denominator():
    m=json.loads((ROOT/"content/encyclopedia/coverage-manifest.json").read_text(encoding="utf-8")); b=m["windows_security_log_review_benchmark"]; assert (b["listed_unique_event_id_count"],b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(422,16,406,"16/422",3.79); assert b["covered_event_ids"][:6]==IDS; w=next(item for item in m["families"] if item["id"]=="windows-security-auditing"); assert (w["denominator_count"],w["encyclopedia_grade_count"],w["remaining_count"])==(423,10,413)
def test_07_structural_inventory_is_bound_to_exact_discovery_evidence():
    inv=json.loads((ROOT/"ingestion/inventories/windows-eventlog-security-1100-series-26100.telemetry.json").read_text(encoding="utf-8")); s=inv["scope_metadata"]; assert inv["expected_identity_count"]==6; assert (s["provider"],s["channel"],s["windows_build"])==("Microsoft-Windows-Eventlog","Security","26100"); assert (s["workflow_run_id"],s["artifact_id"])==(37458952335,11411012754); assert s["artifact_digest"]=="sha256:cc93b81627495898362de99e71a39fa7f213a57cc9ed842e6deee779c52968f0"; assert s["raw_artifact_sha256"]=="sha256-6b8bd9a58483296a67e6762fb4840ca7275e83c3109d74b99f6ca6d393d230b0"; assert s["provider_event_version_definition_count"]==7; assert [row["event_id"] for row in s["expected_identities"]]==IDS
