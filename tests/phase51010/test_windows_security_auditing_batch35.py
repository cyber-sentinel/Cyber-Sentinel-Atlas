import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['5382', '5440', '5441', '5442', '5443', '5444', '5446', '5447', '5448', '5449'];LISTED=['5382', '5440', '5441', '5442', '5443', '5444', '5446', '5447', '5448', '5449'];EXPECTED={'5382': {'0': 13}, '5440': {'0': 9}, '5441': {'0': 14}, '5442': {'0': 3}, '5443': {'0': 5}, '5444': {'0': 6}, '5446': {'0': 13}, '5447': {'0': 18}, '5448': {'0': 7}, '5449': {'0': 9}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch35"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=350;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=355 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch35-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37826533823 and x["artifact_id"]==11572415222 and x["artifact_digest"]=='sha256:a932656d53bbdf83d0f73a486d9eb86fcac2a689aa0a51a8496e4ae22a2a5360' and x["raw_artifact_sha256"]=='sha256-9d43a0ca4126bbfd34a6c75bec110bab8d85bad2a8d9a1aabaae0da74a39569a' and x["uws_benchmark_verification"]["workflow_run_id"]==37826876988
