import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['6404', '6405', '6406', '6407', '6408', '6409', '6410', '6416', '6417', '6418'];LISTED=['6404', '6405', '6406', '6407', '6408', '6409', '6410', '6416', '6417', '6418'];EXPECTED={'6404': {'0': 2}, '6405': {'0': 2}, '6406': {'0': 2}, '6407': {'0': 1}, '6408': {'0': 2}, '6409': {'0': 1}, '6410': {'0': 1}, '6416': {'0': 8, '1': 11}, '6417': {'0': 2}, '6418': {'0': 3}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch41"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=410;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=415 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch41-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37940285199 and x["artifact_id"]==11620503072 and x["artifact_digest"]=='sha256:c4ec0e24217c1b75575bad270cc45ff0bc82fb0c7f14b9e5dbb22beb554bd8d1' and x["raw_artifact_sha256"]=='sha256-d872d1a553a5d50b115a772aa9611ac3eeed6dd1b7941180a2c217c91d49bbf4' and x["uws_benchmark_verification"]["workflow_run_id"]==37940429829
