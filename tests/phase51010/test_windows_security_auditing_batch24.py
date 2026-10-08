import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['4948', '4949', '4950', '4951', '4952', '4953', '4954', '4956', '4957', '4958'];LISTED=['4948', '4949', '4950', '4951', '4952', '4953', '4954', '4956', '4957', '4958'];EXPECTED={'4948': {'0': 3}, '4949': {'0': 0}, '4950': {'0': 3}, '4951': {'0': 3}, '4952': {'0': 3}, '4953': {'0': 4}, '4954': {'0': 0}, '4956': {'0': 1}, '4957': {'0': 3}, '4958': {'0': 4}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch24"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=240;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=246 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch24-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37826533823 and x["artifact_id"]==11572030801 and x["artifact_digest"]=='sha256:7487421dbe1b7233cd686b43c24a0abca4c9ffa79e77bcbe3747abd522659aef' and x["raw_artifact_sha256"]=='sha256-4d9dccb89353aae13623fdc3713e09acd1408886cdd2f2461c9cfcea478aac4d' and x["uws_benchmark_verification"]["workflow_run_id"]==37826876988
