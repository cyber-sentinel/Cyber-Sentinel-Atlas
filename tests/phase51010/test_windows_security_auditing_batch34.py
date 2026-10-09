import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['5160', '5168', '5169', '5170', '5376', '5377', '5378', '5379', '5380', '5381'];LISTED=['5168', '5169', '5170', '5376', '5377', '5378', '5379', '5380', '5381'];EXPECTED={'5160': {'0': 23}, '5168': {'0': 9}, '5169': {'0': 16}, '5170': {'0': 16}, '5376': {'0': 4, '1': 7}, '5377': {'0': 4, '1': 7}, '5378': {'0': 8}, '5379': {'0': 11}, '5380': {'0': 10}, '5381': {'0': 8}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch34"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=340;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=345 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch34-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37826533823 and x["artifact_id"]==11572065728 and x["artifact_digest"]=='sha256:83085deee6c0d0bc02fbfeed560a1ea33d1faa62bf3fc47899886968a2997282' and x["raw_artifact_sha256"]=='sha256-d739c9729cc25910931474d0294363ab8ffae2617021a2a8dbae51ae45524c76' and x["uws_benchmark_verification"]["workflow_run_id"]==37826876988
