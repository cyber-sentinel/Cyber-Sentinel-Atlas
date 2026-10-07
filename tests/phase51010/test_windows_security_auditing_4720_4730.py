#!/usr/bin/env python3
from __future__ import annotations
import importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
IDS=['4720', '4722', '4723', '4724', '4725', '4726', '4727', '4728', '4729', '4730']
STRUCTURAL='atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-4720-4730'
EXPECTED={'4720': {'0': 26}, '4722': {'0': 7}, '4723': {'0': 8}, '4724': {'0': 7}, '4725': {'0': 7}, '4726': {'0': 8}, '4727': {'0': 10}, '4728': {'0': 10, '1': 11}, '4729': {'0': 10}, '4730': {'0': 8}}
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
 assert EXPECTED["4720"]=={"0":26} and EXPECTED["4728"]=={"0":10,"1":11}
 assert {f["native_name"]:f for f in d["4728"]["fields"]}["MembershipExpirationTime"]["versions"]==["1"]
def test_04_semantics():
 d=bp(); assert d["4723"]["overview"]["event_type"]=="Success/Failure" and d["4724"]["overview"]["event_type"]=="Success/Failure"
 for eid in ("4720","4722","4723","4724","4725","4726"): assert d[eid]["overview"]["subcategory"]=="Audit User Account Management"
 for eid in ("4727","4728","4729","4730"): assert d[eid]["overview"]["subcategory"]=="Audit Security Group Management"
def test_05_evidence_and_redistribution():
 data={x["id"]:x for x in records()}
 for eid in IDS:
  cs=[x for x in data.values() if x.get("record_kind")=="claim" and x.get("subject_id")==f"atlas:event:microsoft.windows.security:{eid}" and x.get("predicate")=="telemetry.represents"]; assert len(cs)==1 and STRUCTURAL in {e["source_id"] for e in cs[0]["evidence"]}; assert data[f"atlas:source:atlas.source:ultimate-windows-security-event-{eid}"]["redistribution"]["policy"]=="prohibited"
def test_06_coverage():
 m=json.loads((ROOT/"content/encyclopedia/coverage-manifest.json").read_text()); b=m["windows_security_log_review_benchmark"]; assert (b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(96,326,"96/422",22.75); assert set(IDS).issubset(set(b["covered_event_ids"])); w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert (w["denominator_count"],w["encyclopedia_grade_count"],w["remaining_count"])==(423,90,333)
def test_07_discovery_binding():
 x=json.loads((ROOT/"ingestion/inventories/windows-security-auditing-4720-4730-26100.telemetry.json").read_text()); s=x["scope_metadata"]; assert (s["workflow_run_id"],s["artifact_id"],s["provider_event_version_definition_count"],s["provider_unique_event_id_count"])==(37628383060,11484872075,11,10); assert s["artifact_digest"]=='sha256:3392082db05683036a210341decced6439940f89be9891ee65082ad51011a48e' and s["raw_artifact_sha256"]=='sha256-52a8b607bc78e3fdc2f93f49d7f2b665211e130a744ddbfa798d6811b7f0a5ad'
