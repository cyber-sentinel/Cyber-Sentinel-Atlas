import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['6429', '6430', '8191'];LISTED=['8191'];EXPECTED={'6429': {'0': 10}, '6430': {'0': 5}, '8191': {'0': 0}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch43"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=423;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=422 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch43-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37940285199 and x["artifact_id"]==11621052291 and x["artifact_digest"]=='sha256:0cc2978746143c6391764699b47ef07951b436818c43905735deeecc42c79d5b' and x["raw_artifact_sha256"]=='sha256-c35318e418f7e37f0acd2b1c3ccbe999d4f4da9a550333261b71726f893fcddb' and x["uws_benchmark_verification"]["workflow_run_id"]==37940429829
