import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['5140', '5141', '5142', '5143', '5144', '5145', '5146', '5147', '5148', '5149'];LISTED=['5140', '5141', '5142', '5143', '5144', '5145', '5146', '5147', '5148', '5149'];EXPECTED={'5140': {'0': 7, '1': 11}, '5141': {'0': 12}, '5142': {'0': 6}, '5143': {'0': 15}, '5144': {'0': 6}, '5145': {'0': 13}, '5146': {'0': 11}, '5147': {'0': 11}, '5148': {'0': 1}, '5149': {'0': 2}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch32"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=320;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=326 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch32-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37826533823 and x["artifact_id"]==11571183142 and x["artifact_digest"]=='sha256:b13e89466be2fba17762acf79b700d38c92190868148698a60e90385dde1c486' and x["raw_artifact_sha256"]=='sha256-a7a16af7296ae96f11d0a37eab76e22f90f9e97a4747db0935ba3f52ed3a484b' and x["uws_benchmark_verification"]["workflow_run_id"]==37826876988
