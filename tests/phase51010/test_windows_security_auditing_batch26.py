import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['4980', '4981', '4982', '4983', '4984', '4985', '5024', '5025', '5027', '5028'];LISTED=['4980', '4981', '4982', '4983', '4984', '4985', '5024', '5025', '5027', '5028'];EXPECTED={'4980': {'0': 26}, '4981': {'0': 26}, '4982': {'0': 30}, '4983': {'0': 18}, '4984': {'0': 13}, '4985': {'0': 9}, '5024': {'0': 0}, '5025': {'0': 0}, '5027': {'0': 1}, '5028': {'0': 1}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch26"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=260;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=266 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch26-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37826533823 and x["artifact_id"]==11571467104 and x["artifact_digest"]=='sha256:107ced9a09dd3f09001095c0da4a76513df6a272e21353947f7db6d6df1e9f0a' and x["raw_artifact_sha256"]=='sha256-93fc3540e469e7bb41c849f664b0f33138cf552c8bc621622f2989f5daad0bab' and x["uws_benchmark_verification"]["workflow_run_id"]==37826876988
