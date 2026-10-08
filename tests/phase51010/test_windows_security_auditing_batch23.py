import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['4932', '4933', '4934', '4935', '4936', '4937', '4944', '4945', '4946', '4947'];LISTED=['4932', '4933', '4934', '4935', '4936', '4937', '4944', '4945', '4946', '4947'];EXPECTED={'4932': {'0': 6, '1': 6}, '4933': {'0': 7, '1': 7}, '4934': {'0': 7}, '4935': {'0': 2}, '4936': {'0': 3}, '4937': {'0': 5, '1': 5}, '4944': {'0': 7}, '4945': {'0': 3}, '4946': {'0': 3}, '4947': {'0': 3}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch23"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=230;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=236 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch23-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37826533823 and x["artifact_id"]==11571840931 and x["artifact_digest"]=='sha256:d036bc0a6e918bada7589840a9b0a4bda9507ad58cd1a16b7c302f9ffe48eea3' and x["raw_artifact_sha256"]=='sha256-7d056ca04f2bb5ee6147a6d2dd8c7fbdf348e4a3ec8781bdb2aae882782e206c' and x["uws_benchmark_verification"]["workflow_run_id"]==37826876988
