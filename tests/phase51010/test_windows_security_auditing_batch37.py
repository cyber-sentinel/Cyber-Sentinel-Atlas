import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['5462', '5463', '5464', '5465', '5466', '5467', '5468', '5471', '5472', '5473'];LISTED=['5462', '5463', '5464', '5465', '5466', '5467', '5468', '5471', '5472', '5473'];EXPECTED={'5462': {'0': 2}, '5463': {'0': 0}, '5464': {'0': 0}, '5465': {'0': 0}, '5466': {'0': 0}, '5467': {'0': 0}, '5468': {'0': 0}, '5471': {'0': 1}, '5472': {'0': 2}, '5473': {'0': 1}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch37"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=370;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=375 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch37-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37940285199 and x["artifact_id"]==11620498047 and x["artifact_digest"]=='sha256:7f7e4ce88047187de3bab090c917983ee0a670b160d26716598b2afc67e3e350' and x["raw_artifact_sha256"]=='sha256-31bc1109d42737c825b49bb08874069088370a5006bd71ef14f9db45bae00184' and x["uws_benchmark_verification"]["workflow_run_id"]==37940429829
