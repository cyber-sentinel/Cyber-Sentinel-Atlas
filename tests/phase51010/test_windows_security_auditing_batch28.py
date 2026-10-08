import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['5040', '5041', '5042', '5043', '5044', '5045', '5046', '5047', '5048', '5049'];LISTED=['5040', '5041', '5042', '5043', '5044', '5045', '5046', '5047', '5048', '5049'];EXPECTED={'5040': {'0': 3}, '5041': {'0': 3}, '5042': {'0': 3}, '5043': {'0': 3}, '5044': {'0': 3}, '5045': {'0': 3}, '5046': {'0': 3}, '5047': {'0': 3}, '5048': {'0': 3}, '5049': {'0': 3}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch28"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=280;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=286 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch28-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37826533823 and x["artifact_id"]==11571896010 and x["artifact_digest"]=='sha256:59d39e533b0f4d28f0bd7694667cf66d88da89d677bb67817db617ff6dbba049' and x["raw_artifact_sha256"]=='sha256-4469714b27c41464ff3d1a533e462944bc6b2a24fd37ff92e4087d85418b2885' and x["uws_benchmark_verification"]["workflow_run_id"]==37826876988
