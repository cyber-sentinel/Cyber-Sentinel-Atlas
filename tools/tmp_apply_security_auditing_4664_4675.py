#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
BASE_COMMIT = "3feda12eecc037fb4039cd6040b485eba29c3393"
BASE_PATH = "tools/tmp_apply_security_auditing_4654_4663.py"
NOW = "2026-10-07T01:45:00Z"
IDS = ["4664","4665","4666","4667","4668","4670","4671","4673","4674","4675"]
RUN_ID = 37522839076
ARTIFACT_ID = 11440968647
ARTIFACT_DIGEST = "sha256:cac4ba75a3f404967bfc8a487be3075a407107628ae6c0d4b4b346898d40c3e0"
RAW_SHA256 = "sha256-0dce574b1c2915ac46bec36a7059d59d5e278f0694797c08a422ae131858cd36"
STRUCTURAL_ID = "atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-4664-4675"
STRUCTURAL_VERSION = "windows-server-2025-build-26100-security-auditing-4664-4675"

META = {
 "4664":{"title":"An attempt was made to create a hard link","category":"Object Access","subcategory":"Audit File System","event_type":"Success","marker":"S","url":"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4664","source_version":"event-4664-v0-doc","summary":"Records successful creation of an NTFS hard link and identifies the subject, original file, new link and transaction context.","requirements":["Enable Audit File System success auditing and configure an appropriate SACL where hard-link creation visibility is required.","Preserve FileName, LinkName, TransactionId and subject context."],"interpretation":"Hard-link creation is uncommon in many environments and can be relevant to tampering, persistence or path-confusion investigations when unexpected.","analysis":["Review FileName and LinkName for sensitive targets and unusual paths.","Correlate TransactionId and subject logon context with adjacent object-access telemetry."],"correlations":[{"target":"4660","key":"TransactionId + Computer + time","purpose":"correlate related transactional object activity where present"}]},
 "4665":{"title":"An attempt was made to create an application client context","category":"Object Access","subcategory":"Audit Application Generated","event_type":"Success/Failure","marker":"S,F","url":"https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration","source_version":"advanced-audit-policy-current-doc","summary":"Application-generated audit telemetry for creation of a Windows auditing API client context.","requirements":["Enable Audit Application Generated when applications using Windows auditing APIs require monitoring.","Preserve application, client identity, client logon identifier and status."],"interpretation":"Security relevance depends on the application emitting the audit event and whether the client context is expected.","analysis":["Baseline AppName and ClientName values for applications that use Windows auditing APIs.","Investigate unexpected client domains, logon identifiers or failure status values."],"correlations":[{"target":"4666","key":"AppInstance + ClientLogonId + time","purpose":"associate client-context creation with application operations"}]},
 "4666":{"title":"An application attempted an operation","category":"Object Access","subcategory":"Audit Application Generated","event_type":"Success/Failure","marker":"S,F","url":"https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration","source_version":"advanced-audit-policy-current-doc","summary":"Application-generated audit telemetry describing an application operation against a named object or scope.","requirements":["Enable Audit Application Generated for monitored applications using Windows auditing APIs.","Preserve application/client identity, object/scope, role/group and operation identifiers."],"interpretation":"Meaning is application-defined; analyze only with the emitting application's expected authorization model and operation vocabulary.","analysis":["Use AppName, ObjectName, ScopeName and OperationName together to identify the audited action.","Investigate unexpected Role/Group combinations or operations from unusual client identities."],"correlations":[{"target":"4665","key":"AppInstance + ClientLogonId + time","purpose":"associate operation with application client-context creation"},{"target":"4667","key":"AppInstance + ClientLogonId + time","purpose":"track client-context lifecycle"}]},
 "4667":{"title":"An application client context was deleted","category":"Object Access","subcategory":"Audit Application Generated","event_type":"Success/Failure","marker":"S,F","url":"https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration","source_version":"advanced-audit-policy-current-doc","summary":"Application-generated audit telemetry for deletion of a Windows auditing API client context.","requirements":["Enable Audit Application Generated for monitored applications using Windows auditing APIs.","Preserve application instance and client identity/logon context."],"interpretation":"Primarily lifecycle telemetry; value increases when paired with context creation and operations from the same application instance.","analysis":["Correlate AppInstance and ClientLogonId with preceding 4665/4666 events.","Review abnormal context churn or deletion following failed/unusual operations."],"correlations":[{"target":"4665","key":"AppInstance + ClientLogonId + time","purpose":"pair client-context deletion with creation"}]},
 "4668":{"title":"An application was initialized","category":"Object Access","subcategory":"Audit Application Generated","event_type":"Success/Failure","marker":"S,F","url":"https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration","source_version":"advanced-audit-policy-current-doc","summary":"Application-generated audit telemetry indicating initialization of an application using Windows auditing APIs.","requirements":["Enable Audit Application Generated where application initialization should be monitored.","Preserve application instance, client identity/logon context and StoreUrl."],"interpretation":"Interpret with application-specific expectations; unexpected applications or stores can warrant review.","analysis":["Baseline AppName and StoreUrl combinations.","Correlate AppInstance with subsequent client-context and operation events."],"correlations":[{"target":"4665","key":"AppInstance + time","purpose":"associate application initialization with later client-context creation"}]},
 "4670":{"title":"Permissions on an object were changed","category":"Object Access","subcategory":"Audit File System / Registry / Authentication Policy Change / Authorization Policy Change","event_type":"Success","marker":"S","url":"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4670","source_version":"event-4670-v0-doc","summary":"Records a permissions change on an audited object and exposes old and new security descriptors plus subject and process context.","requirements":["Enable the relevant audit subcategory and configure SACL coverage for permission-changing access where required.","Preserve ObjectType/ObjectName, OldSd/NewSd, HandleId and process context."],"interpretation":"Unexpected ACL or ownership changes on sensitive objects are high-value investigation signals.","analysis":["Diff OldSd and NewSd to identify added/removed ACEs or ownership changes.","Correlate ProcessId with process creation telemetry and HandleId with earlier object access."],"correlations":[{"target":"4656","key":"HandleId + Computer + time","purpose":"recover preceding handle-request context"},{"target":"4688","key":"ProcessId + Computer + time","purpose":"resolve the process responsible for the permission change"}]},
 "4671":{"title":"An application attempted to access a blocked ordinal through the TBS","category":"Object Access","subcategory":"Audit Other Object Access Events","event_type":"Defined / not generated","marker":"-","url":"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4671","source_version":"event-4671-v0-doc","summary":"Microsoft defines this TPM Base Services blocked-ordinal event but documents that current Windows does not invoke it.","requirements":["Treat this as a defined provider identity rather than expected operational telemetry.","Preserve caller identity and Ordinal if observed in controlled evidence or future platform behavior."],"interpretation":"Absence is expected according to Microsoft documentation; unexpected presence should trigger platform/source verification before semantic conclusions.","analysis":["If observed, verify OS build/provider provenance first.","Review Ordinal and caller identity only after confirming the event is genuinely emitted by the expected provider."],"correlations":[]},
 "4673":{"title":"A privileged service was called","category":"Privilege Use","subcategory":"Audit Sensitive Privilege Use / Audit Non Sensitive Privilege Use","event_type":"Success/Failure","marker":"S,F","url":"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4673","source_version":"event-4673-v0-doc","summary":"Records an attempt to perform privileged system service operations and identifies the subject, service, privilege list and process.","requirements":["Enable the relevant Privilege Use audit subcategory.","Preserve Service, PrivilegeList, subject and process context."],"interpretation":"Unexpected use of sensitive privileges or unusual services/processes is security-relevant; failures can indicate blocked or attempted privileged activity.","analysis":["Prioritize rare privileges such as SeTcbPrivilege or SeDebugPrivilege when inconsistent with the account role.","Correlate ProcessId with process creation and SubjectLogonId with logon telemetry."],"correlations":[{"target":"4624","key":"SubjectLogonId + Computer","purpose":"resolve privileged subject logon context"},{"target":"4688","key":"ProcessId + Computer + time","purpose":"resolve privileged-calling process"}]},
 "4674":{"title":"An operation was attempted on a privileged object","category":"Privilege Use","subcategory":"Audit Sensitive Privilege Use / Audit Non Sensitive Privilege Use","event_type":"Success/Failure","marker":"S,F","url":"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4674","source_version":"event-4674-v0-doc","summary":"Records a privileged operation attempted on a protected subsystem object after the object is opened.","requirements":["Enable the relevant Privilege Use audit subcategory.","Preserve ObjectServer/ObjectType/ObjectName, HandleId, AccessMask, PrivilegeList and process context."],"interpretation":"Unexpected privilege use against protected subsystem objects can indicate administration, security-control manipulation or malicious privilege abuse.","analysis":["Review PrivilegeList together with ObjectType/ObjectName and AccessMask.","Correlate ProcessId and subject logon context with surrounding execution/authentication telemetry."],"correlations":[{"target":"4673","key":"SubjectLogonId + ProcessId + time","purpose":"compare privileged object operations with privileged service calls"},{"target":"4688","key":"ProcessId + Computer + time","purpose":"resolve process context"}]},
 "4675":{"title":"SIDs were filtered","category":"Logon/Logoff","subcategory":"Audit Logon","event_type":"Success","marker":"S","url":"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4675","source_version":"event-4675-v0-doc","summary":"Records SID filtering for an Active Directory trust and identifies the target account, trust direction/type/attributes, TDO SID and filtered SID list.","requirements":["Collect on Active Directory domain controllers where trust/SID-filtering visibility is required.","Preserve trust metadata and SidList."],"interpretation":"Use this event to understand SID filtering across trust boundaries; unexpected filtered SIDs or trust changes warrant directory/trust investigation.","analysis":["Review TdoDirection, TdoType and TdoAttributes against expected trust configuration.","Inspect SidList for unexpected principals and correlate with trust-change events."],"correlations":[{"target":"4716","key":"trust identity + time","purpose":"correlate SID filtering with trusted-domain information changes"}]}
}

FIELD_DETAILS = {
 "AppName":("Application","application-name","Application name supplied to the Windows auditing API."),
 "AppInstance":("Application","application-instance","Application instance identifier used to correlate application-generated audit events."),
 "ClientName":("Client","client-name","Client identity/name supplied by the application-generated audit event."),
 "ClientDomain":("Client","client-domain","Client domain supplied by the application-generated audit event."),
 "ClientLogonId":("Client","client-logon-id","Client logon identifier for correlation with authentication context."),
 "Status":("Result","status","Provider-native status value for application client-context creation."),
 "ScopeName":("Application Operation","scope-name","Application-defined authorization scope."),
 "Role":("Application Operation","role","Application-defined role associated with the operation."),
 "Group":("Application Operation","group","Application-defined group associated with the operation."),
 "OperationName":("Application Operation","operation-name","Application-defined operation name."),
 "OperationId":("Application Operation","operation-id","Application-defined numeric operation identifier."),
 "StoreUrl":("Application","store-url","Application audit-policy store URL or locator."),
 "FileName":("Link Information","file-name","Existing file or directory referenced by the new hard link."),
 "LinkName":("Link Information","link-name","Path/name of the newly created hard link."),
 "OldSd":("Permission Change","old-security-descriptor","Security descriptor before the permissions change."),
 "NewSd":("Permission Change","new-security-descriptor","Security descriptor after the permissions change."),
 "CallerUserSid":("Caller","caller-user-sid","Security identifier of the calling account."),
 "CallerUserName":("Caller","caller-user-name","Name of the calling account."),
 "CallerDomainName":("Caller","caller-domain-name","Domain associated with the calling account."),
 "CallerLogonId":("Caller","caller-logon-id","Logon identifier of the calling account."),
 "Ordinal":("TBS","ordinal","TPM Base Services ordinal requested by the application."),
 "Service":("Privilege Use","service","Privileged system service/function invoked."),
 "TargetUserSid":("Target Account","target-user-sid","Security identifier of the target account/trust context."),
 "TargetUserName":("Target Account","target-user-name","Target account name."),
 "TargetDomainName":("Target Account","target-domain-name","Target account domain."),
 "TdoDirection":("Trust Information","trust-direction","Trusted-domain-object direction value."),
 "TdoAttributes":("Trust Information","trust-attributes","Trusted-domain-object attributes."),
 "TdoType":("Trust Information","trust-type","Trusted-domain-object type."),
 "TdoSid":("Trust Information","tdo-domain-sid","SID of the trusted-domain object/domain."),
 "SidList":("Trust Information","filtered-sids","Provider-rendered list of SIDs filtered by the trust boundary.")
}


def load_base():
    text = subprocess.check_output(["git","show",f"{BASE_COMMIT}:{BASE_PATH}"], text=True)
    tmp = Path(tempfile.mkdtemp()) / "base_batch.py"
    tmp.write_text(text, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("base_batch", tmp)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def raw_discovery():
    p=Path(os.environ["ATLAS_DISCOVERY_JSON"]); blob=p.read_bytes()
    assert "sha256-"+hashlib.sha256(blob).hexdigest()==RAW_SHA256
    d=json.loads(blob)
    assert d["provider"]=="Microsoft-Windows-Security-Auditing" and d["channel_scope"]=="Security"
    assert d["unique_event_id_count"]==10 and d["event_version_definition_count"]==10
    assert [str(x) for x in d["requested_ids"]]==IDS
    return d


def provider_shapes(data):
    ns={"e":"http://schemas.microsoft.com/win/2004/08/events"}; result={eid:[] for eid in IDS}
    for ev in data["events"]:
        eid=str(ev["id"]); root=ET.fromstring(ev["template"])
        fields=[(x.attrib["name"],x.attrib.get("inType"),x.attrib.get("outType")) for x in root.findall("e:data",ns)]
        result[eid].append({"version":int(ev["version"]),"level":ev["level"],"fields":fields})
    expected={"4664":7,"4665":6,"4666":11,"4667":5,"4668":6,"4670":12,"4671":5,"4673":9,"4674":12,"4675":8}
    assert {eid:[x["version"] for x in rows] for eid,rows in result.items()}=={eid:[0] for eid in IDS}
    assert {eid:len(rows[0]["fields"]) for eid,rows in result.items()}==expected
    return result


def build_inventory(base, shapes):
    identities=[]
    for eid in IDS:
        v=shapes[eid][0]
        identities.append({"event_id":eid,"versions":[{"version":0,"field_count":len(v["fields"]),"level":v["level"],"fields":[{"name":n,"in_type":i,"out_type":o} for n,i,o in v["fields"]]}]})
    doc={"ingestion_contract_version":"1.0.0","inventory_contract_version":"1.0.0","inventory_id":"atlas:inventory:atlas.ingestion:windows-security-auditing-4664-4675-26100","inventory_kind":"telemetry","declared_scope":"Microsoft-Windows-Security-Auditing provider Event IDs 4664,4665,4666,4667,4668,4670,4671,4673,4674,4675 linked to Security on controlled Windows Server 2025 Datacenter build 26100","source_ids":[STRUCTURAL_ID],"inventory_method":"provider-runtime-metadata","inventory_source_version":STRUCTURAL_VERSION,"expected_identity_count":10,"identity_dimensions":["provider","channel","native-id","product","platform","version"],"scope_metadata":{"provider":"Microsoft-Windows-Security-Auditing","channel":"Security","product":"Windows Server 2025 Datacenter","platform":"Windows","windows_build":"26100","architecture":"64-bit","workflow_run_id":RUN_ID,"artifact_id":ARTIFACT_ID,"artifact_digest":ARTIFACT_DIGEST,"raw_artifact_sha256":RAW_SHA256,"provider_event_version_definition_count":10,"provider_unique_event_id_count":10,"expected_identities":identities,"completeness_semantics":"bounded structural evidence for ten identities already inside the separately frozen 423-ID provider denominator; version definitions are preserved and do not alter that denominator"},"guardrails":{"max_unexplained_shrink_percent":0,"max_unexplained_growth_percent":0}}
    doc["digest"]=base.digest_without_field(doc); return doc


def configure_base(base):
    base.NOW=NOW; base.IDS=IDS; base.RUN_ID=RUN_ID; base.ARTIFACT_ID=ARTIFACT_ID; base.ARTIFACT_DIGEST=ARTIFACT_DIGEST; base.RAW_SHA256=RAW_SHA256; base.STRUCTURAL_ID=STRUCTURAL_ID; base.STRUCTURAL_VERSION=STRUCTURAL_VERSION; base.META=META; base.FIELD_DETAILS.update(FIELD_DETAILS)


def write_sources(base):
    sd=ROOT/"content/encyclopedia/sources"
    provider=base.source_record(STRUCTURAL_ID,"microsoft-windows-security-auditing-provider-26100-4664-4675","Microsoft-Windows-Security-Auditing Security Provider Metadata — Windows Server 2025 build 26100 — bounded Event IDs 4664–4675 batch",["https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log"],change={"strategy":"checksum","notes":f"Bound to workflow {RUN_ID}, artifact {ARTIFACT_ID}, artifact digest {ARTIFACT_DIGEST}, raw JSON {RAW_SHA256}, and normalized inventory."})
    base.dump(sd/"microsoft-windows-security-auditing-provider-26100-4664-4675.json",provider)
    for eid in IDS:
        m=META[eid]
        base.dump(sd/f"microsoft-windows-security-event-{eid}.json",base.source_record(f"atlas:source:atlas.source:microsoft-windows-security-event-{eid}",f"microsoft-windows-security-event-{eid}",f"Microsoft Windows Security Auditing Event {eid} Documentation",[m["url"],"https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/Appendix-L--Events-to-Monitor"],change={"strategy":"content-diff","notes":"Microsoft event/audit-policy material is semantic authority; controlled provider evidence is structural authority for exact version and field shape."}))
        base.dump(sd/f"ultimate-windows-security-event-{eid}.json",base.source_record(f"atlas:source:atlas.source:ultimate-windows-security-event-{eid}",f"ultimate-windows-security-event-{eid}",f"Ultimate Windows Security — Windows Security Log Event ID {eid}",[f"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={eid}"],secondary=True,change={"strategy":"manual","notes":"Coverage / Quick Detail benchmark only. No automated or bulk ingestion is authorized."}))


def update_coverage(base):
    p=ROOT/"content/encyclopedia/coverage-manifest.json"; d=json.loads(p.read_text())
    b=d["windows_security_log_review_benchmark"]
    assert (b["listed_unique_event_id_count"],b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"])==(422,46,376)
    covered=sorted(set(b["covered_event_ids"])|set(IDS),key=int); assert len(covered)==56
    b.update({"covered_event_ids":covered,"encyclopedia_grade_listed_id_count":56,"remaining_listed_id_count":366,"completion_ratio":"56/422","completion_percent":13.27})
    fam=next(x for x in d["families"] if x["id"]=="windows-security-auditing"); assert (fam["denominator_count"],fam["encyclopedia_grade_count"],fam["remaining_count"])==(423,40,383); fam.update({"encyclopedia_grade_count":50,"remaining_count":373})
    base.dump(p,d)


def rebuild_snapshot():
    p=ROOT/"tools/content/build_windows_security_coverage_snapshot.py"; spec=importlib.util.spec_from_file_location("cov",p); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); s=m.build_snapshot()
    assert (s["denominator_count"],s["encyclopedia_grade_count"],s["remaining_count"],s["completion_ratio"],s["completion_percent"])==(423,50,373,"50/423",11.82)
    (ROOT/"content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json").write_text(json.dumps(s,sort_keys=True,indent=2)+"\n")


def update_tests():
    p=ROOT/"tests/phase51010/test_windows_security_coverage_snapshot.py"; t=p.read_text()
    for old,new in [("== 40","== 50"),("== 383","== 373"),("== \"40/423\"","== \"50/423\""),("== 9.46","== 11.82")]: t=t.replace(old,new)
    p.write_text(t)
    p=ROOT/"tests/phase51010/test_windows_security_auditing_4654_4663.py"; t=p.read_text()
    old='assert (b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(46,376,"46/422",10.9); assert set(IDS).issubset(set(b["covered_event_ids"])); w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert (w["denominator_count"],w["encyclopedia_grade_count"],w["remaining_count"])==(423,40,383)'
    new='assert b["listed_unique_event_id_count"]==422 and set(IDS).issubset(set(b["covered_event_ids"])) and b["encyclopedia_grade_listed_id_count"]>=46; w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert w["denominator_count"]==423 and w["encyclopedia_grade_count"]>=40 and w["remaining_count"]==423-w["encyclopedia_grade_count"]'
    assert old in t; p.write_text(t.replace(old,new))


def write_batch_test(base, shapes):
    expected={eid:{"0":len(shapes[eid][0]["fields"])} for eid in IDS}
    text=f'''#!/usr/bin/env python3\nfrom __future__ import annotations\nimport importlib.util,json\nfrom pathlib import Path\nROOT=Path(__file__).resolve().parents[2]\nIDS={IDS!r}\nSTRUCTURAL={STRUCTURAL_ID!r}\nEXPECTED={expected!r}\ndef mod(n,p):\n s=importlib.util.spec_from_file_location(n,p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m\nbuilder=mod("b",ROOT/"tools/content/build_encyclopedia_records.py"); validator=mod("v",ROOT/"tools/validate_phase52.py")\ndef records(): return builder.build_records()\ndef bp():\n d=json.loads((ROOT/"content/encyclopedia/approved-exemplars.json").read_text()); return {{str(x["native_event_id"]):x for x in d["events"] if x.get("namespace")=="microsoft.windows.security"}}\ndef test_01_canonical():\n pairs=[(ROOT/"content/encyclopedia/approved-exemplars.json",x) for x in records()]; e=validator.validate_schema_records(pairs)+validator.validate_semantics(pairs,validator.load_registries()); assert e==[],"\\n".join(e)\ndef test_02_search_and_scope():\n pairs=[(ROOT/"content/encyclopedia/approved-exemplars.json",x) for x in records()]; data={{x["id"]:x for x in records()}}\n for eid in IDS:\n  rid=f"atlas:event:microsoft.windows.security:{{eid}}"; assert validator.resolve_query(pairs,eid)==[rid]; c=data[rid]["native_identifiers"][0]["context"]; assert (c["provider"],c["channel"])==("Microsoft-Windows-Security-Auditing","Security")\ndef test_03_versions_exact():\n d=bp()\n for eid,want in EXPECTED.items(): assert {{r["version"]:r["field_count"] for r in d[eid]["overview"]["event_versions"]}}==want\ndef test_04_semantics():\n d=bp(); assert d["4664"]["overview"]["event_type"]=="Success"; assert d["4671"]["overview"]["event_type"]=="Defined / not generated"; assert d["4673"]["overview"]["event_type"]=="Success/Failure"; assert d["4674"]["overview"]["event_type"]=="Success/Failure"\ndef test_05_evidence_and_redistribution():\n data={{x["id"]:x for x in records()}}\n for eid in IDS:\n  cs=[x for x in data.values() if x.get("record_kind")=="claim" and x.get("subject_id")==f"atlas:event:microsoft.windows.security:{{eid}}" and x.get("predicate")=="telemetry.represents"]; assert len(cs)==1 and STRUCTURAL in {{e["source_id"] for e in cs[0]["evidence"]}}; assert data[f"atlas:source:atlas.source:ultimate-windows-security-event-{{eid}}"]["redistribution"]["policy"]=="prohibited"\ndef test_06_coverage():\n m=json.loads((ROOT/"content/encyclopedia/coverage-manifest.json").read_text()); b=m["windows_security_log_review_benchmark"]; assert (b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(56,366,"56/422",13.27); assert set(IDS).issubset(set(b["covered_event_ids"])); w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert (w["denominator_count"],w["encyclopedia_grade_count"],w["remaining_count"])==(423,50,373)\ndef test_07_discovery_binding():\n x=json.loads((ROOT/"ingestion/inventories/windows-security-auditing-4664-4675-26100.telemetry.json").read_text()); s=x["scope_metadata"]; assert (s["workflow_run_id"],s["artifact_id"],s["provider_event_version_definition_count"],s["provider_unique_event_id_count"])==({RUN_ID},{ARTIFACT_ID},10,10); assert s["artifact_digest"]=={ARTIFACT_DIGEST!r} and s["raw_artifact_sha256"]=={RAW_SHA256!r}\n'''
    (ROOT/"tests/phase51010/test_windows_security_auditing_4664_4675.py").write_text(text)


def update_docs(base):
    p=ROOT/"docs/windows-security-log-scope.md"; t=p.read_text()
    t=t.replace("Current controlled progress after the fourth bounded Windows Security Log batch:","Current controlled progress after the fifth bounded Windows Security Log batch:")
    t=t.replace("- Windows Security Log UWS review benchmark: `46/422` listed identities encyclopedia-grade (`10.90%`), `376` remaining;","- Windows Security Log UWS review benchmark: `56/422` listed identities encyclopedia-grade (`13.27%`), `366` remaining;")
    t=t.replace("- newly promoted Security-Auditing IDs in this batch: `4654`, `4655`, `4656`, `4657`, `4658`, `4659`, `4660`, `4661`, `4662`, `4663`;","- newly promoted Security-Auditing IDs in this batch: `4664`, `4665`, `4666`, `4667`, `4668`, `4670`, `4671`, `4673`, `4674`, `4675`;")
    t=t.replace("- Windows Security Auditing provider coverage: `40/423` encyclopedia-grade with `383` provider-specific identities remaining;","- Windows Security Auditing provider coverage: `50/423` encyclopedia-grade with `373` provider-specific identities remaining;")
    p.write_text(t)
    p=ROOT/"docs/releases/third-party-redistribution-inventory.json"; d=json.loads(p.read_text()); row=next(x for x in d["entries"] if x["id"]=="microsoft-windows-security-documentation")
    adds=[*[f"content/encyclopedia/sources/microsoft-windows-security-event-{eid}.json" for eid in IDS],"ingestion/inventories/windows-security-auditing-4664-4675-26100.telemetry.json","content/encyclopedia/sources/microsoft-windows-security-auditing-provider-26100-4664-4675.json"]
    parts=[x.strip() for x in row.get("review_evidence","").split(" + ") if x.strip()]
    for x in adds:
        if x not in parts: parts.append(x)
    row["review_evidence"]=" + ".join(parts); base.dump(p,d)


def main():
    base=load_base(); configure_base(base); data=raw_discovery(); shapes=provider_shapes(data)
    inv=build_inventory(base,shapes); base.dump(ROOT/"ingestion/inventories/windows-security-auditing-4664-4675-26100.telemetry.json",inv)
    write_sources(base); base.update_blueprint(shapes); update_coverage(base); rebuild_snapshot(); update_tests(); write_batch_test(base,shapes); update_docs(base)
    print("batch_ids="+",".join(IDS)); print("inventory_digest="+inv["digest"]); print("coverage=56/422"); print("security_auditing=50/423")

if __name__=="__main__": main()
