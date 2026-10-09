import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['5122', '5123', '5124', '5125', '5126', '5127', '5136', '5137', '5138', '5139'];LISTED=['5122', '5123', '5124', '5125', '5126', '5127', '5136', '5137', '5138', '5139'];EXPECTED={'5122': {'0': 6}, '5123': {'0': 6}, '5124': {'0': 5}, '5125': {'0': 4, '1': 7}, '5126': {'0': 2}, '5127': {'0': 8}, '5136': {'0': 15}, '5137': {'0': 11}, '5138': {'0': 12}, '5139': {'0': 12}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch31"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=310;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=316 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch31-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37826533823 and x["artifact_id"]==11570998870 and x["artifact_digest"]=='sha256:526cbbf84d079c97b4dbb2c1a3275eff99d309f84daa3520d99328ab74ff562a' and x["raw_artifact_sha256"]=='sha256-d3808e37e906e4aec4920d5c2ed411a126bb418def87143d8de2401c6d01c7b2' and x["uws_benchmark_verification"]["workflow_run_id"]==37826876988
