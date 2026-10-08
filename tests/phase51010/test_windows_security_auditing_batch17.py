import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['4820', '4821', '4822', '4823', '4824', '4825', '4826', '4830', '4864', '4865'];EXPECTED={'4820': {'0': 18}, '4821': {'0': 14}, '4822': {'0': 3}, '4823': {'0': 5}, '4824': {'0': 11}, '4825': {'0': 4}, '4826': {'0': 16}, '4830': {'0': 11}, '4864': {'0': 8}, '4865': {'0': 13}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch17"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=170;b=m["windows_security_log_review_benchmark"];assert b["encyclopedia_grade_listed_id_count"]>=176 and set(IDS).issubset(set(map(str,b["covered_event_ids"])))
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch17-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37721122416 and x["artifact_id"]==11525737578 and x["artifact_digest"]=='sha256:3ba2669b0b87915d0223fd36ce57f8fd346ac84cdcdbab8a08db6cc5b9b41000' and x["raw_artifact_sha256"]=='sha256-490d869c6208d401189a4890f7bff8a7d17b65add87cdab13c33e1ffb6d4acb1' and x["uws_benchmark_verification"]["workflow_run_id"]==37721608338
