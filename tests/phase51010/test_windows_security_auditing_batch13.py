import json
from pathlib import Path
R=Path(__file__).resolve().parents[2];IDS=['4763', '4764', '4765', '4766', '4767', '4770', '4772', '4773', '4774', '4775'];E={'4763':{'0': 8}, '4764':{'0': 9}, '4765':{'0': 11}, '4766':{'0': 8}, '4767':{'0': 7}, '4770':{'0': 8, '1': 10}, '4772':{'0': 7}, '4773':{'0': 7}, '4774':{'0': 3}, '4775':{'0': 2}}
def bp():return {str(x["native_event_id"]):x for x in json.loads((R/"content/encyclopedia/approved-exemplars.json").read_text())["events"] if x.get("namespace")=="microsoft.windows.security"}
def test_versions():
 d=bp();assert all({str(x["version"]):x["field_count"] for x in d[e]["overview"]["event_versions"]}==E[e] for e in IDS);f={x["native_name"]:x for x in d["4770"]["fields"]};assert f["RequestTicketHash"]["versions"]==["1"] and f["ResponseTicketHash"]["versions"]==["1"]
def test_semantics():
 d=bp();assert d["4764"]["overview"]["subcategory"]=="Audit Security Group Management";assert d["4765"]["overview"]["subcategory"]=="Audit User Account Management";assert d["4770"]["overview"]["subcategory"]=="Audit Kerberos Service Ticket Operations";assert d["4772"]["overview"]["event_type"]=="Defined / not generated" and d["4773"]["overview"]["event_type"]=="Defined / not generated";assert d["4774"]["overview"]["event_type"]=="Success/Failure"
def test_coverage():
 m=json.loads((R/"content/encyclopedia/coverage-manifest.json").read_text());assert m["windows_security_log_review_benchmark"]["completion_ratio"]=="136/422";f=next(x for x in m["families"] if x["id"]=="windows-security-auditing");assert f["encyclopedia_grade_count"]>=130 and f["remaining_count"]<=293
def test_binding():
 x=json.loads((R/"ingestion/inventories/windows-security-auditing-batch13-26100.telemetry.json").read_text())["scope_metadata"];assert (x["workflow_run_id"],x["artifact_id"],x["provider_event_version_definition_count"])==(37683880855,11509498136,11) and x["artifact_digest"]=='sha256:b5e5abe42a8229c381d31ad1673dfc639e47936294c6b847f7baf1d08897eeee' and x["raw_artifact_sha256"]=='sha256-dbda8672f69d06561e3a714f70f25a558f82ccaafd2e08d30da3aeb46969f8a9'
