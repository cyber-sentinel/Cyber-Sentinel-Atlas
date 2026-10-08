import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['4786', '4787', '4788', '4789', '4790', '4791', '4792', '4793', '4794', '4797'];EXPECTED={'4786': {'0': 10}, '4787': {'0': 10}, '4788': {'0': 10}, '4789': {'0': 8}, '4790': {'0': 10}, '4791': {'0': 10}, '4792': {'0': 8}, '4793': {'0': 7}, '4794': {'0': 6}, '4797': {'0': 7}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch15"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=150;b=m["windows_security_log_review_benchmark"];assert b["encyclopedia_grade_listed_id_count"]>=156 and set(IDS).issubset(set(map(str,b["covered_event_ids"])))
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch15-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37721122416 and x["artifact_id"]==11525259954 and x["artifact_digest"]=='sha256:e30e67f748a8634df865766b77efb10028290884fcc232521ee355656f112dd5' and x["raw_artifact_sha256"]=='sha256-13189ed2c3541f366aadd294395a41c90b356049d4225dfcdc77d11fa6d66119' and x["uws_benchmark_verification"]["workflow_run_id"]==37721608338
