#!/usr/bin/env python3
from __future__ import annotations
import importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
IDS=['4626', '4627', '4634', '4646', '4647', '4649', '4650', '4651', '4652', '4653']
STRUCTURAL='atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-4626-4653'
COUNTS={'4626': 13, '4627': 12, '4634': 5, '4646': 1, '4647': 4, '4649': 13, '4650': 17, '4651': 23, '4652': 22, '4653': 16}
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
def test_03_shapes():
 d=bp()
 for eid,c in COUNTS.items(): assert d[eid]["overview"]["event_versions"][0]["field_count"]==c
 assert d["4652"]["overview"]["event_type"]=="Failure" and d["4653"]["overview"]["event_type"]=="Failure" and d["4646"]["fields"][0]["native_name"]=="notification"
def test_04_evidence():
 data={x["id"]:x for x in records()}
 for eid in IDS:
  cs=[x for x in data.values() if x.get("record_kind")=="claim" and x.get("subject_id")==f"atlas:event:microsoft.windows.security:{eid}" and x.get("predicate")=="telemetry.represents"]; assert len(cs)==1 and STRUCTURAL in {e["source_id"] for e in cs[0]["evidence"]}; assert data[f"atlas:source:atlas.source:ultimate-windows-security-event-{eid}"]["redistribution"]["policy"]=="prohibited"
def test_05_coverage():
 m=json.loads((ROOT/"content/encyclopedia/coverage-manifest.json").read_text()); b=m["windows_security_log_review_benchmark"]; assert (b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(36,386,"36/422",8.53); w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert (w["denominator_count"],w["encyclopedia_grade_count"],w["remaining_count"])==(423,30,393)
def test_06_discovery_binding():
 x=json.loads((ROOT/"ingestion/inventories/windows-security-auditing-4626-4653-26100.telemetry.json").read_text()); s=x["scope_metadata"]; assert (s["workflow_run_id"],s["artifact_id"],s["provider_event_version_definition_count"])==(37489364839,11425305259,10); assert s["artifact_digest"]=='sha256:867925039bbf2338fcb87574f2ab788434df233528a0c3f41f9d8b38521d7417' and s["raw_artifact_sha256"]=='sha256-dda97115ed3461171de433b0bfb7d2c52d45032aa7d004f27facf7d1fd52356a'; rows={r["event_id"]:r for r in s["expected_identities"]}; assert rows["4652"]["versions"][0]["field_count"]==22 and rows["4653"]["versions"][0]["field_count"]==16
