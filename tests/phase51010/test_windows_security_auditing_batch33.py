import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['5150', '5151', '5152', '5153', '5154', '5155', '5156', '5157', '5158', '5159'];LISTED=['5150', '5151', '5152', '5153', '5154', '5155', '5156', '5157', '5158', '5159'];EXPECTED={'5150': {'0': 10}, '5151': {'0': 10}, '5152': {'0': 11, '1': 12}, '5153': {'0': 11, '1': 12}, '5154': {'0': 8}, '5155': {'0': 8}, '5156': {'0': 11, '1': 15}, '5157': {'0': 11, '1': 13, '2': 16, '3': 19}, '5158': {'0': 8}, '5159': {'0': 8}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch33"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=330;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=336 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch33-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37826533823 and x["artifact_id"]==11571881176 and x["artifact_digest"]=='sha256:d133f6d114e6d6c9e7b0d82bc20e82c5cf405fd8485fd079360b92c2a2d535d5' and x["raw_artifact_sha256"]=='sha256-af93f971d9f9c054a3e7f3ba0de866c5577d75b0bf71b864a941625734ac4464' and x["uws_benchmark_verification"]["workflow_run_id"]==37826876988
