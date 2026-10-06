#!/usr/bin/env python3
from __future__ import annotations
import importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
IDS=['4654', '4655', '4656', '4657', '4658', '4659', '4660', '4661', '4662', '4663']
STRUCTURAL='atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-4654-4663'
EXPECTED={'4654': {'0': 19, '1': 21}, '4655': {'0': 4}, '4656': {'0': 15, '1': 17}, '4657': {'0': 14}, '4658': {'0': 8}, '4659': {'0': 13}, '4660': {'0': 9}, '4661': {'0': 16, '1': 17}, '4662': {'0': 14}, '4663': {'0': 12, '1': 13}}
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
def test_03_versions_are_exact_and_not_flattened():
 d=bp()
 for eid,want in EXPECTED.items(): assert {r["version"]:r["field_count"] for r in d[eid]["overview"]["event_versions"]}==want
 assert {f["native_name"]:f for f in d["4654"]["fields"]}["TunnelId"]["versions"]==["1"]
 assert {f["native_name"]:f for f in d["4656"]["fields"]}["AccessReason"]["versions"]==["1"]
 assert {f["native_name"]:f for f in d["4661"]["fields"]}["AccessReason"]["versions"]==["1"]
 assert {f["native_name"]:f for f in d["4663"]["fields"]}["ResourceAttributes"]["versions"]==["1"]
def test_04_semantic_distinctions_and_aliases():
 d=bp(); assert d["4654"]["overview"]["event_type"]=="Failure"; assert d["4656"]["overview"]["event_type"]=="Success/Failure"; assert d["4661"]["overview"]["event_type"]=="Success/Failure"; assert d["4662"]["overview"]["event_type"]=="Success/Failure"; assert "general object access" in " ".join(d["4656"]["aliases"]); assert "SAM or directory service" in " ".join(d["4661"]["aliases"])
def test_05_evidence_and_redistribution():
 data={x["id"]:x for x in records()}
 for eid in IDS:
  cs=[x for x in data.values() if x.get("record_kind")=="claim" and x.get("subject_id")==f"atlas:event:microsoft.windows.security:{eid}" and x.get("predicate")=="telemetry.represents"]; assert len(cs)==1 and STRUCTURAL in {e["source_id"] for e in cs[0]["evidence"]}; assert data[f"atlas:source:atlas.source:ultimate-windows-security-event-{eid}"]["redistribution"]["policy"]=="prohibited"
def test_06_coverage():
 m=json.loads((ROOT/"content/encyclopedia/coverage-manifest.json").read_text()); b=m["windows_security_log_review_benchmark"]; assert (b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(46,376,"46/422",10.9); assert set(IDS).issubset(set(b["covered_event_ids"])); w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert (w["denominator_count"],w["encyclopedia_grade_count"],w["remaining_count"])==(423,40,383)
def test_07_discovery_binding():
 x=json.loads((ROOT/"ingestion/inventories/windows-security-auditing-4654-4663-26100.telemetry.json").read_text()); s=x["scope_metadata"]; assert (s["workflow_run_id"],s["artifact_id"],s["provider_event_version_definition_count"],s["provider_unique_event_id_count"])==(37501843050,11430091652,14,10); assert s["artifact_digest"]=='sha256:d22a526b900daaa1ffe82773075b5945c30b1411d5a4c18df9b3ef5d19abf898' and s["raw_artifact_sha256"]=='sha256-135c03313f17821eb27e163a18c352cdd4f036ecb2b41ef361e977073311c050'
