import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['5050', '5051', '5056', '5057', '5058', '5059', '5060', '5061', '5062', '5063'];LISTED=['5050', '5051', '5056', '5057', '5058', '5059', '5060', '5061', '5062', '5063'];EXPECTED={'5050': {'0': 3}, '5051': {'0': 8}, '5056': {'0': 6}, '5057': {'0': 8}, '5058': {'0': 11, '1': 13}, '5059': {'0': 10, '1': 12}, '5060': {'0': 10}, '5061': {'0': 10}, '5062': {'0': 2}, '5063': {'0': 8}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch29"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=290;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=296 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch29-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37826533823 and x["artifact_id"]==11571367536 and x["artifact_digest"]=='sha256:5f7d8a17cc916cce17440ab70468bd17ced559b7bdc6b1c6bedc0b0788e5141f' and x["raw_artifact_sha256"]=='sha256-98a99908321882125fcb198318de713dcd735452624f86ecf5dd694b335990af' and x["uws_benchmark_verification"]["workflow_run_id"]==37826876988
