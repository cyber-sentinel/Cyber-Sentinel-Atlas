import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['4886', '4887', '4888', '4889', '4890', '4891', '4892', '4893', '4894', '4895'];EXPECTED={'4886': {'0': 3, '1': 12}, '4887': {'0': 6, '1': 12}, '4888': {'0': 6, '1': 9}, '4889': {'0': 6, '1': 9}, '4890': {'0': 6}, '4891': {'0': 7}, '4892': {'0': 8}, '4893': {'0': 3}, '4894': {'0': 5}, '4895': {'0': 3}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch20"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=200;b=m["windows_security_log_review_benchmark"];assert b["encyclopedia_grade_listed_id_count"]>=206 and set(IDS).issubset(set(map(str,b["covered_event_ids"])))
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch20-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37742066466 and x["artifact_id"]==11534570319 and x["artifact_digest"]=='sha256:a032750e844bbfc13be8a9a3b6f3e68192b832a4d48b8a85efc983b2a8f28bfc' and x["raw_artifact_sha256"]=='sha256-a203576c6c0b5f4b8044b69085ef9e2b3bc4c69bb130c6ecc1c96c4aacf67edf' and x["uws_benchmark_verification"]["workflow_run_id"]==37742066466
