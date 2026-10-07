import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];E={'4731': {'0': 10}, '4732': {'0': 10, '1': 11}, '4733': {'0': 10}, '4734': {'0': 8}, '4735': {'0': 10}, '4737': {'0': 10}, '4738': {'0': 27}, '4739': {'0': 21}, '4741': {'0': 28}, '4742': {'0': 29}}
def bp():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_versions():
 d=bp();assert all({str(x["version"]):x["field_count"] for x in d[e]["overview"]["event_versions"]}==E[e] for e in E);assert {x["native_name"]:x for x in d["4732"]["fields"]}["MembershipExpirationTime"]["versions"]==["1"]
def test_semantics():
 d=bp();assert d["4739"]["overview"]["subcategory"]=="Audit Authentication Policy Change" and d["4742"]["overview"]["subcategory"]=="Audit Computer Account Management"
def test_coverage():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());assert int(m["windows_security_log_review_benchmark"]["completion_ratio"].split("/")[0])>=106;f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=100
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-4731-4742-26100.telemetry.json").read_text())["scope_metadata"];assert (x["workflow_run_id"],x["artifact_id"],x["provider_event_version_definition_count"])==(37639160374,11490748773,11) and x["artifact_digest"]=='sha256:0f5a8e3dc94cdf27948ae1ce0a302211acdec40e106b17503e04f672bc16216f' and x["raw_artifact_sha256"]=='sha256-48f4aa4cbca60e5285fcc73b30e877786ee96a3a3ddaab0eba85a3dd3e765c3a'
