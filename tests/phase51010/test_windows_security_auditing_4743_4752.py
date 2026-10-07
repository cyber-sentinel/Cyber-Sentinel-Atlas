import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];E={'4743': {'0': 8}, '4744': {'0': 10}, '4745': {'0': 10}, '4746': {'0': 10, '1': 11}, '4747': {'0': 10}, '4748': {'0': 8}, '4749': {'0': 10}, '4750': {'0': 10}, '4751': {'0': 10, '1': 11}, '4752': {'0': 10}}
def bp():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_versions():
 d=bp();assert all({str(x["version"]):x["field_count"] for x in d[e]["overview"]["event_versions"]}==E[e] for e in E);assert {x["native_name"]:x for x in d["4746"]["fields"]}["MembershipExpirationTime"]["versions"]==["1"] and {x["native_name"]:x for x in d["4751"]["fields"]}["MembershipExpirationTime"]["versions"]==["1"]
def test_semantics():
 d=bp();assert d["4743"]["overview"]["subcategory"]=="Audit Computer Account Management";assert all(d[e]["overview"]["subcategory"]=="Audit Distribution Group Management" for e in E if e!="4743")
def test_coverage():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());assert int(m["windows_security_log_review_benchmark"]["completion_ratio"].split("/")[0])>=116;f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=110
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-4743-4752-26100.telemetry.json").read_text())["scope_metadata"];assert (x["workflow_run_id"],x["artifact_id"],x["provider_event_version_definition_count"])==(37664692346,11502400552,12) and x["artifact_digest"]=='sha256:729297c7038391b9d7f0e2e81869a5615a2f1e8f12bd7e0fc8da98edacee9b28' and x["raw_artifact_sha256"]=='sha256-79439457a025d2acfa7ef9672b6fc1c59e3a1ce596d610d10ec896df65d1c9d0'
