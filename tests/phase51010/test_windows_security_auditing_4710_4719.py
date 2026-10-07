#!/usr/bin/env python3
from __future__ import annotations
import importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
IDS=['4710', '4711', '4712', '4713', '4714', '4715', '4716', '4717', '4718', '4719']
STRUCTURAL='atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-4710-4719'
EXPECTED={'4710': {'0': 2}, '4711': {'0': 1}, '4712': {'0': 1}, '4713': {'0': 5}, '4714': {'0': 5}, '4715': {'0': 6}, '4716': {'0': 10}, '4717': {'0': 6}, '4718': {'0': 6}, '4719': {'0': 8, '1': 10}}
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
 assert EXPECTED["4710"]=={"0":2} and EXPECTED["4711"]=={"0":1} and EXPECTED["4712"]=={"0":1}
 assert EXPECTED["4719"]=={"0":8,"1":10}
def test_04_semantics_and_opaque_parameters():
 d=bp(); assert d["4712"]["overview"]["event_type"]=="Failure"
 assert d["4714"]["overview"]["subcategory"]=="Audit Other Policy Change Events"
 assert d["4716"]["overview"]["subcategory"]=="Audit Authentication Policy Change"
 assert d["4719"]["overview"]["subcategory"]=="Audit Policy Change"
 for eid in ("4710","4711","4712"):
  details=" ".join(x["meaning"] for x in d[eid]["fields"] if x["native_name"].startswith("param")); assert "opaque" in details.lower()
def test_05_evidence_and_redistribution():
 data={x["id"]:x for x in records()}
 for eid in IDS:
  cs=[x for x in data.values() if x.get("record_kind")=="claim" and x.get("subject_id")==f"atlas:event:microsoft.windows.security:{eid}" and x.get("predicate")=="telemetry.represents"]; assert len(cs)==1 and STRUCTURAL in {e["source_id"] for e in cs[0]["evidence"]}; assert data[f"atlas:source:atlas.source:ultimate-windows-security-event-{eid}"]["redistribution"]["policy"]=="prohibited"
def test_06_coverage():
 m=json.loads((ROOT/"content/encyclopedia/coverage-manifest.json").read_text()); b=m["windows_security_log_review_benchmark"]; assert (b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(86,336,"86/422",20.38); assert set(IDS).issubset(set(b["covered_event_ids"])); w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert (w["denominator_count"],w["encyclopedia_grade_count"],w["remaining_count"])==(423,80,343)
def test_07_discovery_binding():
 x=json.loads((ROOT/"ingestion/inventories/windows-security-auditing-4710-4719-26100.telemetry.json").read_text()); s=x["scope_metadata"]; assert (s["workflow_run_id"],s["artifact_id"],s["provider_event_version_definition_count"],s["provider_unique_event_id_count"])==(37624523330,11483148487,11,10); assert s["artifact_digest"]=='sha256:291987d9ae9b9dc664c5f5eec89f7319329d9b37b9a00e2e5abfa23dd96b47c8' and s["raw_artifact_sha256"]=='sha256-555591bdecf81f19d6c015f4b16768f2de795077e73d930b591fe94b51508af8'
