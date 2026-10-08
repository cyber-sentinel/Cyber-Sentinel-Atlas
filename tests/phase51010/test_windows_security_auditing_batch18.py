import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['4866', '4867', '4868', '4869', '4870', '4871', '4872', '4873', '4874', '4875'];EXPECTED={'4866': {'0': 13}, '4867': {'0': 13}, '4868': {'0': 5}, '4869': {'0': 5}, '4870': {'0': 6}, '4871': {'0': 7}, '4872': {'0': 5}, '4873': {'0': 9}, '4874': {'0': 6}, '4875': {'0': 4}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch18"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=180;b=m["windows_security_log_review_benchmark"];assert b["encyclopedia_grade_listed_id_count"]>=186 and set(IDS).issubset(set(map(str,b["covered_event_ids"])))
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch18-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37721122416 and x["artifact_id"]==11525997098 and x["artifact_digest"]=='sha256:58b3314d30f0230cf9fa5c4d9d6673a784b1ecb2e2e43729f2fc7c7bb4c624d6' and x["raw_artifact_sha256"]=='sha256-e4f5948dbc8dfe8211f2cd4dc691fb0eb41c8da75971863501c32840f2fea725' and x["uws_benchmark_verification"]["workflow_run_id"]==37721608338
