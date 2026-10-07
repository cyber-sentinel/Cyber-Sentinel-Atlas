#!/usr/bin/env python3
from __future__ import annotations
import importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
IDS=['4664', '4665', '4666', '4667', '4668', '4670', '4671', '4673', '4674', '4675']
STRUCTURAL='atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-4664-4675'
EXPECTED={'4664': {'0': 7}, '4665': {'0': 6}, '4666': {'0': 11}, '4667': {'0': 5}, '4668': {'0': 6}, '4670': {'0': 12}, '4671': {'0': 5}, '4673': {'0': 9}, '4674': {'0': 12}, '4675': {'0': 8}}
def mod(n,p):
 s=importlib.util.spec_from_file_location(n,p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
builder=mod("b",ROOT/"tools/content/build_encyclopedia_records.py"); validator=mod("v",ROOT/"tools/validate_phase52.py")
def records(): return builder.build_records()
def bp():
 d=json.loads((ROOT/"content/encyclopedia/approved-exemplars.json").read_text()); return {str(x["native_event_id"]):x for x in d["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_01_canonical():
 pairs=[(ROOT/"content/encyclopedia/approved-exemplars.json",x) for x in records()]; e=validator.validate_schema_records(pairs)+validator.validate_semantics(pairs,validator.load_registries()); assert e==[],"\n".join(e)
def test_02_search_and_scope():
 pairs=[(ROOT/"content/encyclopedia/approved-exemplars.json",x) for x in records()]; data={x["id"]:x for x in records()}
 for eid in IDS:
  rid=f"atlas:event:microsoft.windows.security:{eid}"; assert validator.resolve_query(pairs,eid)==[rid]; c=data[rid]["native_identifiers"][0]["context"]; assert (c["provider"],c["channel"])==("Microsoft-Windows-Security-Auditing","Security")
def test_03_versions_exact():
 d=bp()
 for eid,want in EXPECTED.items(): assert {r["version"]:r["field_count"] for r in d[eid]["overview"]["event_versions"]}==want
def test_04_semantics():
 d=bp(); assert d["4664"]["overview"]["event_type"]=="Success"; assert d["4671"]["overview"]["event_type"]=="Defined / not generated"; assert d["4673"]["overview"]["event_type"]=="Success/Failure"; assert d["4674"]["overview"]["event_type"]=="Success/Failure"
def test_05_evidence_and_redistribution():
 data={x["id"]:x for x in records()}
 for eid in IDS:
  cs=[x for x in data.values() if x.get("record_kind")=="claim" and x.get("subject_id")==f"atlas:event:microsoft.windows.security:{eid}" and x.get("predicate")=="telemetry.represents"]; assert len(cs)==1 and STRUCTURAL in {e["source_id"] for e in cs[0]["evidence"]}; assert data[f"atlas:source:atlas.source:ultimate-windows-security-event-{eid}"]["redistribution"]["policy"]=="prohibited"
def test_06_coverage():
 m=json.loads((ROOT/"content/encyclopedia/coverage-manifest.json").read_text()); b=m["windows_security_log_review_benchmark"]; assert b["listed_unique_event_id_count"]==422 and set(IDS).issubset(set(b["covered_event_ids"])) and b["encyclopedia_grade_listed_id_count"]>=56; w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert w["denominator_count"]==423 and w["encyclopedia_grade_count"]>=50 and w["remaining_count"]==423-w["encyclopedia_grade_count"]
def test_07_discovery_binding():
 x=json.loads((ROOT/"ingestion/inventories/windows-security-auditing-4664-4675-26100.telemetry.json").read_text()); s=x["scope_metadata"]; assert (s["workflow_run_id"],s["artifact_id"],s["provider_event_version_definition_count"],s["provider_unique_event_id_count"])==(37522839076,11440968647,10,10); assert s["artifact_digest"]=='sha256:cac4ba75a3f404967bfc8a487be3075a407107628ae6c0d4b4b346898d40c3e0' and s["raw_artifact_sha256"]=='sha256-0dce574b1c2915ac46bec36a7059d59d5e278f0694797c08a422ae131858cd36'
