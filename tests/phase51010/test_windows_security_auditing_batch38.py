import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['5474', '5477', '5478', '5479', '5480', '5483', '5484', '5485', '5632', '5633'];LISTED=['5474', '5477', '5478', '5479', '5480', '5483', '5484', '5485', '5632', '5633'];EXPECTED={'5474': {'0': 2}, '5477': {'0': 2}, '5478': {'0': 0}, '5479': {'0': 0}, '5480': {'0': 0}, '5483': {'0': 1}, '5484': {'0': 1}, '5485': {'0': 0}, '5632': {'0': 11, '1': 14}, '5633': {'0': 8}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch38"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=380;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=385 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch38-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37940285199 and x["artifact_id"]==11621312200 and x["artifact_digest"]=='sha256:ffcdd09a9f5438343771bf7c5f49f2c7cc4fbcb428a136e98b17d78e15b7f79f' and x["raw_artifact_sha256"]=='sha256-f1c6048052bd9d84dc6ec0298b09cdc1734f73ace5d954be959cc8dd99732c39' and x["uws_benchmark_verification"]["workflow_run_id"]==37940429829
