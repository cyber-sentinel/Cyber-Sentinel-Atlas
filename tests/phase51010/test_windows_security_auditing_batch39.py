import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['5712', '5888', '5889', '5890', '6144', '6145', '6272', '6273', '6274', '6275'];LISTED=['5712', '5888', '5889', '5890', '6144', '6145', '6272', '6273', '6274', '6275'];EXPECTED={'5712': {'0': 12, '1': 13, '2': 15}, '5888': {'0': 7}, '5889': {'0': 7}, '5890': {'0': 7}, '6144': {'0': 2}, '6145': {'0': 2}, '6272': {'0': 26, '1': 27, '2': 24}, '6273': {'0': 26, '1': 27, '2': 26}, '6274': {'0': 26, '1': 25}, '6275': {'0': 26, '1': 25}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch39"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=390;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=395 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch39-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37940285199 and x["artifact_id"]==11620937252 and x["artifact_digest"]=='sha256:9f54306d7c21257e346a67d0c3b5067d0abf366606ae04bc40460dfbe2777264' and x["raw_artifact_sha256"]=='sha256-b7302d8599ab53c9c77d5b17dc5f8fe6a46af98ffa034c4dafd265f8cf684e33' and x["uws_benchmark_verification"]["workflow_run_id"]==37940429829
