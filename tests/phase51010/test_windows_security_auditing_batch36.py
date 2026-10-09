import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['5450', '5451', '5452', '5453', '5456', '5457', '5458', '5459', '5460', '5461'];LISTED=['5450', '5451', '5452', '5453', '5456', '5457', '5458', '5459', '5460', '5461'];EXPECTED={'5450': {'0': 10}, '5451': {'0': 24, '1': 26}, '5452': {'0': 8, '1': 12}, '5453': {'0': 0}, '5456': {'0': 1}, '5457': {'0': 2}, '5458': {'0': 1}, '5459': {'0': 2}, '5460': {'0': 1}, '5461': {'0': 2}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch36"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=360;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=365 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch36-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37940285199 and x["artifact_id"]==11621611909 and x["artifact_digest"]=='sha256:171933e211aff9f0db96d20f62995c1247151abf36b106a9e41c8c8b0e05e6a5' and x["raw_artifact_sha256"]=='sha256-abc8d452e3bf4cfe4f3d2591b1e975ae056b31a0cd29977b6802b900771442e6' and x["uws_benchmark_verification"]["workflow_run_id"]==37940429829
