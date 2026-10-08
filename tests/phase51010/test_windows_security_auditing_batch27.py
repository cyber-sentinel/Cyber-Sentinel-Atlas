import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['5029', '5030', '5031', '5032', '5033', '5034', '5035', '5037', '5038', '5039'];LISTED=['5029', '5030', '5031', '5032', '5033', '5034', '5035', '5037', '5038', '5039'];EXPECTED={'5029': {'0': 1}, '5030': {'0': 1}, '5031': {'0': 2}, '5032': {'0': 1}, '5033': {'0': 0}, '5034': {'0': 0}, '5035': {'0': 1}, '5037': {'0': 1}, '5038': {'0': 1}, '5039': {'0': 8}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch27"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=270;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=276 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch27-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37826533823 and x["artifact_id"]==11572130629 and x["artifact_digest"]=='sha256:b91df2c426099ca2a3253a6202c41747bdc50851f13711a34fbd97f6c35ebbcb' and x["raw_artifact_sha256"]=='sha256-3b576f7ee17ab1efb3e8d614bf571ab785ee7b4eb63d3f7bd302bff01c280336' and x["uws_benchmark_verification"]["workflow_run_id"]==37826876988
