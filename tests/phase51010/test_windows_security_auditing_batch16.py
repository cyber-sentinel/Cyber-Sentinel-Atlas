import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['4798', '4799', '4800', '4801', '4802', '4803', '4816', '4817', '4818', '4819'];EXPECTED={'4798': {'0': 9}, '4799': {'0': 9}, '4800': {'0': 5}, '4801': {'0': 5}, '4802': {'0': 5}, '4803': {'0': 5}, '4816': {'0': 3, '1': 3}, '4817': {'0': 9}, '4818': {'0': 12}, '4819': {'0': 10}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch16"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=160;b=m["windows_security_log_review_benchmark"];assert b["encyclopedia_grade_listed_id_count"]>=166 and set(IDS).issubset(set(map(str,b["covered_event_ids"])))
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch16-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37721122416 and x["artifact_id"]==11526231210 and x["artifact_digest"]=='sha256:866699f6881be481c0e90866b410efc46b151c4f160d1d36c94fff451bfd24a7' and x["raw_artifact_sha256"]=='sha256-666b395b266fa41752a1ec9025c7ce20ac904508b798f0ebd1432c8382c362d8' and x["uws_benchmark_verification"]["workflow_run_id"]==37721608338
