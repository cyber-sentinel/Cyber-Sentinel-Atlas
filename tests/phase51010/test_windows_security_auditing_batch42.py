import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['6419', '6420', '6421', '6422', '6423', '6424', '6425', '6426', '6427', '6428'];LISTED=['6419', '6420', '6421', '6422', '6423', '6424'];EXPECTED={'6419': {'0': 11}, '6420': {'0': 11}, '6421': {'0': 11}, '6422': {'0': 11}, '6423': {'0': 11}, '6424': {'0': 11}, '6425': {'0': 8}, '6426': {'0': 13}, '6427': {'0': 15}, '6428': {'0': 14}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch42"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=420;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=421 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch42-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37940285199 and x["artifact_id"]==11620962096 and x["artifact_digest"]=='sha256:3e653ead3785e5b2a13ddb9addda72d81f0d5b15fe9af56b4efe59ad7314fcce' and x["raw_artifact_sha256"]=='sha256-978c6f058f4fa1a196e4359465f42907a0c5293cb50a2d5a71c38dc559178fd4' and x["uws_benchmark_verification"]["workflow_run_id"]==37940429829
