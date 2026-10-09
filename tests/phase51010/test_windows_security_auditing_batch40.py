import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['6276', '6277', '6278', '6279', '6280', '6281', '6400', '6401', '6402', '6403'];LISTED=['6276', '6277', '6278', '6279', '6280', '6281', '6400', '6401', '6402', '6403'];EXPECTED={'6276': {'0': 29}, '6277': {'0': 30}, '6278': {'0': 29}, '6279': {'0': 4}, '6280': {'0': 4}, '6281': {'0': 1}, '6400': {'0': 1}, '6401': {'0': 1}, '6402': {'0': 1}, '6403': {'0': 1}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch40"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=400;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=405 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch40-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37940285199 and x["artifact_id"]==11620453080 and x["artifact_digest"]=='sha256:8074ec18e713f76b18970c259aa64ef7535ead8bef07c1339aed26523bdb930b' and x["raw_artifact_sha256"]=='sha256-03e73da43fcbd2cb38182a7b5baeac31f11fb89d09a86255debb491eaac81da5' and x["uws_benchmark_verification"]["workflow_run_id"]==37940429829
