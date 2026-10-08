import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['4776', '4777', '4778', '4779', '4780', '4781', '4782', '4783', '4784', '4785'];EXPECTED={'4776': {'0': 4}, '4777': {'0': 4}, '4778': {'0': 6}, '4779': {'0': 6}, '4780': {'0': 8}, '4781': {'0': 9}, '4782': {'0': 6}, '4783': {'0': 10}, '4784': {'0': 10}, '4785': {'0': 10, '1': 11}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch14"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=140;b=m["windows_security_log_review_benchmark"];assert b["encyclopedia_grade_listed_id_count"]>=146 and set(IDS).issubset(set(map(str,b["covered_event_ids"])))
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch14-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37721122416 and x["artifact_id"]==11526186354 and x["artifact_digest"]=='sha256:22889d43749600942e8ba5d37677eea06fb496f1d3d73da19691d25d2e2c8567' and x["raw_artifact_sha256"]=='sha256-5136f700c0cf5cf27d146baf3aef8c3e407c56b5a4a08a2d0404cc0474e81d72' and x["uws_benchmark_verification"]["workflow_run_id"]==37721608338
