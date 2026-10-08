import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['4876', '4877', '4878', '4879', '4880', '4881', '4882', '4883', '4884', '4885'];EXPECTED={'4876': {'0': 5}, '4877': {'0': 4}, '4878': {'0': 0}, '4879': {'0': 0}, '4880': {'0': 4}, '4881': {'0': 4}, '4882': {'0': 5}, '4883': {'0': 5}, '4884': {'0': 6}, '4885': {'0': 5}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch19"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=190;b=m["windows_security_log_review_benchmark"];assert b["encyclopedia_grade_listed_id_count"]>=196 and set(IDS).issubset(set(map(str,b["covered_event_ids"])))
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch19-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37721122416 and x["artifact_id"]==11525347875 and x["artifact_digest"]=='sha256:e3ab983a4d0837ec9fb3632062bbe9126c9fbd46924368404653fdaf1f5aaa35' and x["raw_artifact_sha256"]=='sha256-3030328b56a31a24a544ce2179a8fe0bb313bf615cc01bdf4506238b9b173148' and x["uws_benchmark_verification"]["workflow_run_id"]==37722312601
