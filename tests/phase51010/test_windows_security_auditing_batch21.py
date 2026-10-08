import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['4896', '4897', '4898', '4899', '4900', '4902', '4904', '4905', '4906', '4907'];EXPECTED={'4896': {'0': 7}, '4897': {'0': 1}, '4898': {'0': 8}, '4899': {'0': 8}, '4900': {'0': 10}, '4902': {'0': 2}, '4904': {'0': 8}, '4905': {'0': 8}, '4906': {'0': 1}, '4907': {'0': 12}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch21"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=210;b=m["windows_security_log_review_benchmark"];assert b["encyclopedia_grade_listed_id_count"]>=216 and set(IDS).issubset(set(map(str,b["covered_event_ids"])))
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch21-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37781472457 and x["artifact_id"]==11551708383 and x["artifact_digest"]=='sha256:fc2dbf864b95c6deb8278a08b51ddf68dc3287ec319422bfd71d838666b24b4e' and x["raw_artifact_sha256"]=='sha256-cd360ae1ab1b6ec613c234958c4a96324bd914d3447e97e4cd4c307626a189c0' and x["uws_benchmark_verification"]["workflow_run_id"]==37781472457
