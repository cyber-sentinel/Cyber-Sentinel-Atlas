import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['4908', '4909', '4910', '4911', '4912', '4913', '4928', '4929', '4930', '4931'];LISTED=['4908', '4909', '4910', '4911', '4912', '4913', '4928', '4929', '4930', '4931'];EXPECTED={'4908': {'0': 1}, '4909': {'0': 2}, '4910': {'0': 6}, '4911': {'0': 12}, '4912': {'0': 9}, '4913': {'0': 12}, '4928': {'0': 6, '1': 6}, '4929': {'0': 6, '1': 6}, '4930': {'0': 6, '1': 6}, '4931': {'0': 6, '1': 6}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch22"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=220;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=226 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch22-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37826533823 and x["artifact_id"]==11572290428 and x["artifact_digest"]=='sha256:7705ed4e14a85fc4ac9dc2b5198f0be2374390f54e76dad08f601520c9ff16c0' and x["raw_artifact_sha256"]=='sha256-83a8e629b71ee1451abde3bd3df64f44b8e3f0a80819a5ece7cdd67f0954cc6c' and x["uws_benchmark_verification"]["workflow_run_id"]==37826876988
