#!/usr/bin/env python3
from __future__ import annotations
import importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
IDS=['4699', '4700', '4701', '4702', '4703', '4704', '4705', '4706', '4707', '4709']
STRUCTURAL='atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-4699-4709'
EXPECTED={'4699': {'0': 6, '1': 11}, '4700': {'0': 6, '1': 11}, '4701': {'0': 6, '1': 11}, '4702': {'0': 6, '1': 11}, '4703': {'0': 12}, '4704': {'0': 6}, '4705': {'0': 6}, '4706': {'0': 10}, '4707': {'0': 6}, '4709': {'0': 3}}
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
 for eid in ("4699","4700","4701","4702"): assert EXPECTED[eid]=={"0":6,"1":11}
 assert EXPECTED["4703"]=={"0":12} and EXPECTED["4706"]=={"0":10} and EXPECTED["4709"]=={"0":3}
def test_04_semantics():
 d=bp()
 for eid in IDS: assert d[eid]["overview"]["event_type"]=="Success"
 assert d["4703"]["overview"]["subcategory"]=="Audit Authorization Policy Change"
 assert d["4706"]["overview"]["subcategory"]=="Audit Authentication Policy Change"
 assert d["4709"]["overview"]["subcategory"]=="Audit Filtering Platform Policy Change"
def test_05_evidence_and_redistribution():
 data={x["id"]:x for x in records()}
 for eid in IDS:
  cs=[x for x in data.values() if x.get("record_kind")=="claim" and x.get("subject_id")==f"atlas:event:microsoft.windows.security:{eid}" and x.get("predicate")=="telemetry.represents"]; assert len(cs)==1 and STRUCTURAL in {e["source_id"] for e in cs[0]["evidence"]}; assert data[f"atlas:source:atlas.source:ultimate-windows-security-event-{eid}"]["redistribution"]["policy"]=="prohibited"
def test_06_coverage():
 m=json.loads((ROOT/"content/encyclopedia/coverage-manifest.json").read_text()); b=m["windows_security_log_review_benchmark"]; assert b["listed_unique_event_id_count"]==422 and set(IDS).issubset(set(b["covered_event_ids"])) and b["encyclopedia_grade_listed_id_count"]>=76; w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert w["denominator_count"]==423 and w["encyclopedia_grade_count"]>=70 and w["remaining_count"]==423-w["encyclopedia_grade_count"]
def test_07_discovery_binding():
 x=json.loads((ROOT/"ingestion/inventories/windows-security-auditing-4699-4709-26100.telemetry.json").read_text()); s=x["scope_metadata"]; assert (s["workflow_run_id"],s["artifact_id"],s["provider_event_version_definition_count"],s["provider_unique_event_id_count"])==(37610244718,11478270373,14,10); assert s["artifact_digest"]=='sha256:9fedb9a65977712bec90d23589773d9f97ff5b2167054819c3de7d12602cc7de' and s["raw_artifact_sha256"]=='sha256-b486c1cb4b2380e14e9eba77fc79efa09734faff9ff90a221a6ad3f0acc42633'
