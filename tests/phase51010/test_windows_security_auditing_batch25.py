import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['4960', '4961', '4962', '4963', '4964', '4965', '4976', '4977', '4978', '4979'];LISTED=['4960', '4961', '4962', '4963', '4964', '4965', '4976', '4977', '4978', '4979'];EXPECTED={'4960': {'0': 2}, '4961': {'0': 2}, '4962': {'0': 2}, '4963': {'0': 2}, '4964': {'0': 11}, '4965': {'0': 2}, '4976': {'0': 3}, '4977': {'0': 3}, '4978': {'0': 3}, '4979': {'0': 21}}
def events():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_shapes():
 d=events()
 for e in IDS: assert {str(v["version"]):v["field_count"] for v in d[e]["overview"]["event_versions"]}==EXPECTED[e] and d[e]["source_id"]=="atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-batch25"
def test_progress():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=250;b=m["windows_security_log_review_benchmark"];covered=set(map(str,b["covered_event_ids"]));assert b["encyclopedia_grade_listed_id_count"]>=256 and set(LISTED).issubset(covered) and not (set(IDS)-set(LISTED)) & covered
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch25-26100.telemetry.json").read_text())["scope_metadata"];assert x["workflow_run_id"]==37826533823 and x["artifact_id"]==11571014017 and x["artifact_digest"]=='sha256:296b5d6549b8427dcfcbb5747ad1bb616de550ee7e87a7d2c3aa0885c2dcb119' and x["raw_artifact_sha256"]=='sha256-bead26b51855541d71ca85abc04b925eeba2e629d867e60a28f9c9974e629970' and x["uws_benchmark_verification"]["workflow_run_id"]==37826876988
