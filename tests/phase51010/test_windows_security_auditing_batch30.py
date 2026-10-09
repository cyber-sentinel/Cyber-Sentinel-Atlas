import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['5064', '5065', '5066', '5067', '5068', '5069', '5070', '5071', '5120', '5121'];LISTED=['5064', '5065', '5066', '5067', '5068', '5069', '5070', '5071', '5120', '5121'];EXPECTED={'5064': {'0': 8}, '5065': {'0': 9}, '5066': {'0': 11}, '5067': {'0': 11}, '5068': {'0': 12}, '5069': {'0': 12}, '5070': {'0': 12}, '5071': {'0': 5}, '5120': {'0': 0}, '5121': {'0': 0}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch30"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=300;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=306 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch30-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37826533823 and x["artifact_id"]==11571646681 and x["artifact_digest"]=='sha256:415c842941dddf531deb6575a65a64a2abd662548c18ea5bb4542fa6b8ccc340' and x["raw_artifact_sha256"]=='sha256-ce02e7912ad7563649f1ad522b7dd73d3d61eacd96d3a4b7be7bd6c35d639932' and x["uws_benchmark_verification"]["workflow_run_id"]==37826876988
