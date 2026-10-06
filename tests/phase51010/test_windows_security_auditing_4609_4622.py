#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
IDS=["4609","4610","4611","4612","4614","4615","4616","4618","4621","4622"]
STRUCTURAL="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-4609-4622"
def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
builder=load_module("securitybatch_builder",ROOT/"tools/content/build_encyclopedia_records.py"); validator=load_module("securitybatch_validator",ROOT/"tools/validate_phase52.py")
def records(): return builder.build_records()
def by_id(): return {item["id"]:item for item in records()}
def blueprints():
    doc=json.loads((ROOT/"content/encyclopedia/approved-exemplars.json").read_text(encoding="utf-8")); return {str(item["native_event_id"]):item for item in doc["events"] if item.get("namespace")=="microsoft.windows.security"}
def test_01_batch_records_validate_canonical_v1():
    pairs=[(ROOT/"content/encyclopedia/approved-exemplars.json",item) for item in records()]; errors=validator.validate_schema_records(pairs)+validator.validate_semantics(pairs,validator.load_registries()); assert errors==[],"\n".join(errors)
def test_02_all_ids_are_security_auditing_and_searchable():
    pairs=[(ROOT/"content/encyclopedia/approved-exemplars.json",item) for item in records()]; data=by_id()
    for eid in IDS:
        rid=f"atlas:event:microsoft.windows.security:{eid}"; assert rid in data; ctx=data[rid]["native_identifiers"][0]["context"]; assert (ctx["provider"],ctx["channel"])==("Microsoft-Windows-Security-Auditing","Security"); assert validator.resolve_query(pairs,eid)==[rid]
def test_03_provider_structural_shapes_are_exact():
    bp=blueprints(); expected={"4609":{"0":0},"4610":{"0":1},"4611":{"0":5},"4612":{"0":1},"4614":{"0":1},"4615":{"0":8},"4616":{"0":10,"1":8},"4618":{"0":8},"4621":{"0":1},"4622":{"0":1}}
    for eid,want in expected.items(): assert {row["version"]:row["field_count"] for row in bp[eid]["overview"]["event_versions"]}==want
    assert bp["4609"]["fields"]==[]; v4616={f["native_name"]:f for f in bp["4616"]["fields"]}; assert v4616["PreviousDate"]["versions"]==["0"] and v4616["NewDate"]["versions"]==["0"]; assert v4616["PreviousTime"]["versions"]==["0","1"] and "FILETIME" in v4616["PreviousTime"]["type"]; assert bp["4618"]["fields"][0]["native_name"]=="EventId" and "not the outer Windows Event ID 4618" in bp["4618"]["fields"][0]["meaning"]
def test_04_structural_evidence_is_attached():
    data=by_id()
    for eid in IDS:
        subject=f"atlas:event:microsoft.windows.security:{eid}"; claims=[x for x in data.values() if x.get("record_kind")=="claim" and x.get("subject_id")==subject and x.get("predicate")=="telemetry.represents"]; assert len(claims)==1; assert STRUCTURAL in {ev["source_id"] for ev in claims[0]["evidence"]}
def test_05_uws_remains_reference_only():
    data=by_id()
    for eid in IDS: assert data[f"atlas:source:atlas.source:ultimate-windows-security-event-{eid}"]["redistribution"]["policy"]=="prohibited"
def test_06_coverage_moves_both_benchmark_and_provider_numerator():
    m=json.loads((ROOT/"content/encyclopedia/coverage-manifest.json").read_text()); b=m["windows_security_log_review_benchmark"]; assert b["listed_unique_event_id_count"]==422 and set(IDS).issubset(set(b["covered_event_ids"])) and b["encyclopedia_grade_listed_id_count"]>=26; w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert w["denominator_count"]==423 and w["encyclopedia_grade_count"]>=20 and w["remaining_count"]==423-w["encyclopedia_grade_count"]

def test_07_discovery_evidence_is_checksum_bound():
    inv=json.loads((ROOT/"ingestion/inventories/windows-security-auditing-4609-4622-26100.telemetry.json").read_text(encoding="utf-8")); s=inv["scope_metadata"]; assert inv["expected_identity_count"]==10; assert (s["provider"],s["channel"],s["windows_build"])==("Microsoft-Windows-Security-Auditing","Security","26100"); assert (s["workflow_run_id"],s["artifact_id"])==(37467608335,11415372410); assert s["artifact_digest"]=="sha256:a3909e3fbbe11ed1c22eae1deafa40f070da772045f89b18d3843ecfaa0860b4"; assert s["raw_artifact_sha256"]=="sha256-0c27de466bc79e429a97fc2e0649d0d0e0a7d109de975ff79b10a056f80542a4"; assert s["provider_event_version_definition_count"]==11; assert [x["event_id"] for x in s["expected_identities"]]==IDS
def test_08_4616_versions_are_not_flattened():
    inv=json.loads((ROOT/"ingestion/inventories/windows-security-auditing-4609-4622-26100.telemetry.json").read_text(encoding="utf-8")); row=next(x for x in inv["scope_metadata"]["expected_identities"] if x["event_id"]=="4616"); assert [v["version"] for v in row["versions"]]==[0,1] and [v["field_count"] for v in row["versions"]]==[10,8]; v0={f["name"]:(f["in_type"],f["out_type"]) for f in row["versions"][0]["fields"]}; v1={f["name"]:(f["in_type"],f["out_type"]) for f in row["versions"][1]["fields"]}; assert v0["PreviousTime"]==("win:UnicodeString","xs:string") and v1["PreviousTime"]==("win:FILETIME","xs:dateTime") and "PreviousDate" in v0 and "PreviousDate" not in v1
