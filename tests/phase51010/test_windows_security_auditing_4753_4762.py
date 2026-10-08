import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];E={'4753': {'0': 8}, '4754': {'0': 10}, '4755': {'0': 10}, '4756': {'0': 10, '1': 11}, '4757': {'0': 10}, '4758': {'0': 8}, '4759': {'0': 10}, '4760': {'0': 10}, '4761': {'0': 10, '1': 11}, '4762': {'0': 10}}
def bp():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_versions():
 d=bp();assert all({str(x["version"]):x["field_count"] for x in d[e]["overview"]["event_versions"]}==E[e] for e in E);assert {x["native_name"]:x for x in d["4756"]["fields"]}["MembershipExpirationTime"]["versions"]==["1"] and {x["native_name"]:x for x in d["4761"]["fields"]}["MembershipExpirationTime"]["versions"]==["1"]
def test_semantics():
 d=bp();assert all(d[e]["overview"]["subcategory"]=="Audit Security Group Management" for e in ("4754","4755","4756","4757","4758"));assert all(d[e]["overview"]["subcategory"]=="Audit Distribution Group Management" for e in ("4753","4759","4760","4761","4762"))
def test_coverage():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());assert int(m["windows_security_log_review_benchmark"]["completion_ratio"].split("/")[0])>=126;f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=120
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-4753-4762-26100.telemetry.json").read_text())["scope_metadata"];assert (x["workflow_run_id"],x["artifact_id"],x["provider_event_version_definition_count"])==(37680802160,11508793624,12) and x["artifact_digest"]=='sha256:5033778ccdf7a966a8fc16121f2bcdcd7d9652baf85bff51341b86c2940f7882' and x["raw_artifact_sha256"]=='sha256-67a6e722b1b4da6f31a51c5c673b60079eec8d24b0d3734f9a290d1c2ce4e952'
