#!/usr/bin/env python3
from __future__ import annotations
import importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
IDS=['4689', '4690', '4691', '4692', '4693', '4694', '4695', '4696', '4697', '4698']
STRUCTURAL='atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-4689-4698'
EXPECTED={'4689': {'0': 7}, '4690': {'0': 8}, '4691': {'0': 9}, '4692': {'0': 8}, '4693': {'0': 9}, '4694': {'0': 9}, '4695': {'0': 9}, '4696': {'0': 12}, '4697': {'0': 9, '1': 12}, '4698': {'0': 6, '1': 11}}
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
 for eid,want in EXPECTED.items(): assert {str(r["version"]):r["field_count"] for r in d[eid]["overview"]["event_versions"]}==want
 assert EXPECTED["4697"]=={"0":9,"1":12} and EXPECTED["4698"]=={"0":6,"1":11}
def test_04_semantics():
 d=bp(); assert d["4689"]["overview"]["event_type"]=="Success"; assert d["4692"]["overview"]["event_type"]=="Success/Failure"; assert d["4696"]["overview"]["event_type"]=="Success / deprecated"; assert d["4697"]["overview"]["event_type"]=="Success"; assert d["4698"]["overview"]["event_type"]=="Success"
def test_05_evidence_and_redistribution():
 data={x["id"]:x for x in records()}
 for eid in IDS:
  cs=[x for x in data.values() if x.get("record_kind")=="claim" and x.get("subject_id")==f"atlas:event:microsoft.windows.security:{eid}" and x.get("predicate")=="telemetry.represents"]; assert len(cs)==1 and STRUCTURAL in {e["source_id"] for e in cs[0]["evidence"]}; assert data[f"atlas:source:atlas.source:ultimate-windows-security-event-{eid}"]["redistribution"]["policy"]=="prohibited"
def test_06_coverage():
 m=json.loads((ROOT/"content/encyclopedia/coverage-manifest.json").read_text()); b=m["windows_security_log_review_benchmark"]; assert (b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(66,356,"66/422",15.64); assert set(IDS).issubset(set(b["covered_event_ids"])); w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert (w["denominator_count"],w["encyclopedia_grade_count"],w["remaining_count"])==(423,60,363)
def test_07_discovery_binding():
 x=json.loads((ROOT/"ingestion/inventories/windows-security-auditing-4689-4698-26100.telemetry.json").read_text()); s=x["scope_metadata"]; assert (s["workflow_run_id"],s["artifact_id"],s["provider_event_version_definition_count"],s["provider_unique_event_id_count"])==(37602920128,11473885860,12,10); assert s["artifact_digest"]=='sha256:532f141c53f9af4bbe5553c969444ee57322c7c98bbe0c04a391670c48e0ec83' and s["raw_artifact_sha256"]=='sha256-42f992beda2ee6963d14ea2e475722a4a99324332c900a763167d6f9a55079b1'
