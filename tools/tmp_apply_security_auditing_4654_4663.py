#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-10-06T17:13:27Z"
IDS = ["4654","4655","4656","4657","4658","4659","4660","4661","4662","4663"]
RUN_ID = 37501843050
ARTIFACT_ID = 11430091652
ARTIFACT_DIGEST = "sha256:d22a526b900daaa1ffe82773075b5945c30b1411d5a4c18df9b3ef5d19abf898"
RAW_SHA256 = "sha256-135c03313f17821eb27e163a18c352cdd4f036ecb2b41ef361e977073311c050"
STRUCTURAL_ID = "atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-4654-4663"
STRUCTURAL_VERSION = "windows-server-2025-build-26100-security-auditing-4654-4663"

META = {
    "4654": {
        "title": "An IPsec Quick Mode negotiation failed",
        "category": "Logon/Logoff",
        "subcategory": "Audit IPsec Quick Mode",
        "event_type": "Failure",
        "marker": "F",
        "url": "https://learn.microsoft.com/en-us/windows/win32/fwp/auditing-and-logging",
        "source_version": "audit-ipsec-quick-mode-current-doc",
        "summary": "Records failure of an IPsec Quick Mode negotiation. Controlled provider evidence preserves both Version 0 and Version 1 payloads, with Version 1 adding TunnelId and TrafficSelectorId.",
        "requirements": ["Enable Audit IPsec Quick Mode failure auditing where IPsec negotiation visibility is required.", "Preserve endpoint, protocol, failure-state, filter and security-association identifiers; preserve version identity."],
        "interpretation": "A negotiation failure can be caused by policy mismatch, reachability, peer configuration or hostile/abnormal traffic. Repetition and unexpected peers increase security relevance.",
        "analysis": ["Use FailurePoint, FailureReason, Mode and State to localize the failed negotiation phase.", "Cluster failures by endpoint tuple, protocol, QMFilterID, MMSAID and time.", "For Version 1, retain TunnelId and TrafficSelectorId rather than flattening to Version 0."],
        "correlations": [{"target":"5451","key":"endpoint tuple + time","purpose":"compare failed Quick Mode negotiations with successful Quick Mode security-association establishment where available"}],
    },
    "4655": {
        "title": "An IPsec Main Mode security association ended",
        "category": "Logon/Logoff",
        "subcategory": "Audit IPsec Main Mode",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-ipsec-main-mode",
        "source_version": "audit-ipsec-main-mode-current-doc",
        "summary": "Records termination of an IPsec Main Mode security association and exposes the local/remote addresses, keying module and Main Mode SA identifier needed for lifecycle correlation.",
        "requirements": ["Enable Audit IPsec Main Mode success auditing where Main Mode lifecycle visibility is required.", "Preserve LocalAddress, RemoteAddress, KeyModName and MMSAID."],
        "interpretation": "Association termination is normally lifecycle telemetry. Unexpected peers, timing or repeated churn should be investigated in surrounding IPsec context.",
        "analysis": ["Correlate MMSAID with establishment events 4650 or 4651.", "Review rapid establishment/termination cycles and unexpected remote addresses.", "Use KeyModName and endpoint identity to separate normal lifecycle from policy/interoperability issues."],
        "correlations": [{"target":"4650","key":"MMSAID + Computer","purpose":"correlate non-certificate Main Mode SA establishment with termination"},{"target":"4651","key":"MMSAID + Computer","purpose":"correlate certificate-backed Main Mode SA establishment with termination"}],
    },
    "4656": {
        "title": "A handle to an object was requested",
        "alias_title": "A handle to an object was requested (general object access)",
        "category": "Object Access",
        "subcategory": "Audit File System / Kernel Object / Registry / Removable Storage",
        "event_type": "Success/Failure",
        "marker": "S,F",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4656",
        "source_version": "event-4656-v1-doc",
        "summary": "Records a request for specific access to an audited object. Failure is generated when access is declined; the event shows requested access and the result but not whether a later operation was performed.",
        "requirements": ["Configure the relevant Object Access audit subcategory and an object SACL matching the access to be audited.", "Preserve object identity, handle, requested rights, subject and process context."],
        "interpretation": "High volume is possible. Security value depends on object sensitivity, requested rights, success/failure result and process context.",
        "analysis": ["Prioritize sensitive ObjectName values and write/delete/permission-change rights.", "Use HandleId and TransactionId to correlate later object operations.", "Correlate ProcessId with process creation telemetry using event time because PIDs are reusable.", "Do not flatten Version 0 and Version 1: Version 1 adds AccessReason and ResourceAttributes."],
        "correlations": [{"target":"4663","key":"HandleId + Computer + time","purpose":"determine whether requested access was subsequently exercised"},{"target":"4660","key":"TransactionId or HandleId + Computer + time","purpose":"correlate deletion activity"},{"target":"4688","key":"ProcessId + Computer + time","purpose":"resolve process creation context"}],
    },
    "4657": {
        "title": "A registry value was modified",
        "category": "Object Access",
        "subcategory": "Audit Registry",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657",
        "source_version": "event-4657-v0-doc",
        "summary": "Records modification of a registry value when the registry key SACL audits Set Value access, including old/new value type and data plus process context.",
        "requirements": ["Enable Audit Registry success auditing and configure an appropriate registry SACL for Set Value access.", "Preserve registry object/value names, old/new values, subject and process context."],
        "interpretation": "Registry changes are common; prioritize sensitive persistence, security-policy, service, authentication and startup locations and deviations from expected writers.",
        "analysis": ["Compare OldValue and NewValue and assess whether the change affects security or persistence.", "Baseline expected ProcessName values for sensitive keys.", "Correlate ProcessId with 4688 and related process telemetry."],
        "correlations": [{"target":"4688","key":"ProcessId + Computer + time","purpose":"resolve process creation context for the registry writer"}],
    },
    "4658": {
        "title": "The handle to an object was closed",
        "category": "Object Access",
        "subcategory": "Audit Handle Manipulation / Object Access",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4658",
        "source_version": "event-4658-v0-doc",
        "summary": "Records closure of an audited object handle. It is primarily useful for handle-lifecycle correlation and can help determine how long a handle remained open.",
        "requirements": ["Enable Audit Handle Manipulation success auditing where handle close visibility is required.", "Preserve HandleId, subject and process context."],
        "interpretation": "This event often has little standalone security relevance; its value is strongest when correlated to the same handle in related object-access events.",
        "analysis": ["Track HandleId across the object-access lifecycle.", "Correlate ProcessId/ProcessName with the process that held the handle.", "Use timing between handle request and close only when collection completeness is sufficient."],
        "correlations": [{"target":"4656","key":"HandleId + Computer","purpose":"correlate general object handle request with closure"},{"target":"4661","key":"HandleId + Computer","purpose":"correlate SAM/AD object handle request with closure"}],
    },
    "4659": {
        "title": "A handle to an object was requested with intent to delete",
        "category": "Object Access",
        "subcategory": "Audit Kernel Object / Object Access",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration",
        "source_version": "advanced-audit-policy-current-doc",
        "summary": "Records a handle request made with intent to delete an audited object, preserving subject, object, handle, transaction, requested rights and process identifiers.",
        "requirements": ["Enable the applicable Object Access auditing and SACL policy for the target object class.", "Preserve ObjectType/ObjectName, HandleId, TransactionId, AccessList/AccessMask and process context."],
        "interpretation": "Intent to delete is not identical to confirmed deletion. Correlate with subsequent deletion evidence before asserting that the object was removed.",
        "analysis": ["Prioritize sensitive objects and unexpected deleting processes.", "Correlate HandleId/TransactionId with Event 4660 and other object events.", "Use AccessList/AccessMask to confirm requested delete-related rights."],
        "correlations": [{"target":"4660","key":"HandleId or TransactionId + Computer + time","purpose":"confirm a subsequent object deletion"},{"target":"4688","key":"ProcessId + Computer + time","purpose":"resolve requesting process context"}],
    },
    "4660": {
        "title": "An object was deleted",
        "category": "Object Access",
        "subcategory": "Audit File System / Kernel Object / Registry",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4660",
        "source_version": "event-4660-v0-doc",
        "summary": "Records confirmed deletion of an audited object. The event carries HandleId rather than the deleted object name, so object identity is normally recovered through correlated access telemetry.",
        "requirements": ["Enable the relevant Object Access audit subcategory and configure Delete auditing in the object SACL.", "Preserve HandleId, TransactionId, subject and process context."],
        "interpretation": "Unlike an access attempt, this event represents an actual delete operation, but it does not itself carry ObjectName.",
        "analysis": ["Correlate HandleId to Event 4663 or 4656 to recover the object name and access context.", "Investigate unexpected deleting processes or sensitive objects.", "Correlate ProcessId with process creation telemetry using tight time bounds."],
        "correlations": [{"target":"4663","key":"HandleId + Computer + time","purpose":"recover ObjectName and DELETE access context"},{"target":"4656","key":"TransactionId or HandleId + Computer + time","purpose":"recover earlier handle-request context"}],
    },
    "4661": {
        "title": "A handle to an object was requested",
        "alias_title": "A handle to an object was requested (SAM or directory service)",
        "category": "Object Access",
        "subcategory": "Audit Directory Service Access / Audit SAM",
        "event_type": "Success/Failure",
        "marker": "S,F",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4661",
        "source_version": "event-4661-current-doc",
        "summary": "Records a handle request for an Active Directory or Security Account Manager object. If access is declined, a Failure event is generated.",
        "requirements": ["Enable the applicable Directory Service Access or SAM/Object Access auditing and required SACLs.", "Preserve object identity, Properties, access rights, subject and process context."],
        "interpretation": "This event can be high volume and overlaps semantically with later operation telemetry. Prioritize sensitive SAM/AD objects and privileged access rights.",
        "analysis": ["Use ObjectType/ObjectName and Properties to identify the targeted directory/SAM object.", "Correlate HandleId with Event 4662 operations and 4658 closure.", "Do not flatten versions: Version 1 adds AccessReason."],
        "correlations": [{"target":"4662","key":"HandleId + ObjectName + Computer + time","purpose":"correlate the requested handle with an operation performed on the object"},{"target":"4658","key":"HandleId + Computer","purpose":"track handle closure"}],
    },
    "4662": {
        "title": "An operation was performed on an object",
        "category": "DS Access",
        "subcategory": "Audit Directory Service Access",
        "event_type": "Success/Failure",
        "marker": "S,F",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662",
        "source_version": "event-4662-v0-doc",
        "summary": "Records an operation performed on an Active Directory object when the object SACL matches the operation. A Failure event is generated when the operation fails.",
        "requirements": ["Enable Audit Directory Service Access and configure appropriate SACLs on the Active Directory objects to be monitored.", "Preserve ObjectType/ObjectName, OperationType, AccessList/AccessMask, Properties and additional information."],
        "interpretation": "Security relevance is driven by the target object/property and access type. Privileged write, control, delete or permissions-changing operations deserve higher scrutiny.",
        "analysis": ["Resolve property GUIDs in Properties when necessary to understand the affected AD attributes.", "Prioritize Write Property, Control Access, DELETE, WRITE_DAC and WRITE_OWNER on sensitive objects.", "Correlate HandleId with 4661 where available."],
        "correlations": [{"target":"4661","key":"HandleId + ObjectName + Computer + time","purpose":"correlate object operation with the preceding handle request"}],
    },
    "4663": {
        "title": "An attempt was made to access an object",
        "category": "Object Access",
        "subcategory": "Audit File System / Kernel Object / Registry / Removable Storage",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663",
        "source_version": "event-4663-v1-doc",
        "summary": "Records an audited access operation that was actually attempted against an object, including object identity, handle, requested access rights and process context.",
        "requirements": ["Enable the applicable Object Access audit subcategory and configure an object SACL matching the access to be audited.", "Preserve ObjectName, HandleId, AccessList/AccessMask and process context."],
        "interpretation": "This event confirms use of the requested access rather than merely a handle request. Analyze in the context of object sensitivity and the access rights exercised.",
        "analysis": ["Prioritize write/delete/permission-changing access to sensitive files, registry keys and other objects.", "Use HandleId to correlate with Event 4656 and 4660.", "Do not flatten versions: Version 1 adds ResourceAttributes."],
        "correlations": [{"target":"4656","key":"HandleId + Computer + time","purpose":"correlate performed access with the preceding handle request"},{"target":"4660","key":"HandleId + Computer + time","purpose":"confirm deletion when DELETE access is followed by an actual delete"}],
    },
}

FIELD_DETAILS = {
    "SubjectUserSid": ("Subject", "subject-user-sid", "Security identifier of the subject account."),
    "SubjectUserName": ("Subject", "subject-user-name", "Account name of the subject."),
    "SubjectDomainName": ("Subject", "subject-domain-name", "Domain or computer name associated with the subject."),
    "SubjectLogonId": ("Subject", "subject-logon-id", "Logon-session identifier of the subject for authentication correlation."),
    "ObjectServer": ("Object", "object-server", "Security subsystem or service responsible for the audited object."),
    "ObjectType": ("Object", "object-type", "Provider-reported type or class of the audited object."),
    "ObjectName": ("Object", "object-name", "Provider-reported name or identifying path of the audited object."),
    "ObjectValueName": ("Object", "object-value-name", "Registry value name affected by the operation."),
    "HandleId": ("Object", "handle-id", "Object handle identifier used to correlate related access events."),
    "TransactionId": ("Object", "transaction-id", "Transaction GUID used to correlate related transactional object operations."),
    "AccessList": ("Access Request Information", "access-list", "Provider-rendered list of access rights requested or exercised."),
    "AccessReason": ("Access Request Information", "access-reason", "Provider-rendered explanation of why requested access was granted or denied."),
    "AccessMask": ("Access Request Information", "access-mask", "Bit mask representing requested or exercised access rights."),
    "PrivilegeList": ("Access Request Information", "privilege-list", "Privileges associated with the audited access request."),
    "Properties": ("Access Request Information", "properties", "Object properties or property identifiers associated with the audited operation."),
    "RestrictedSidCount": ("Access Request Information", "restricted-sid-count", "Count of restricted SIDs associated with the access token."),
    "ResourceAttributes": ("Access Request Information", "resource-attributes", "Resource attributes associated with the audited object in provider versions that expose them."),
    "OperationType": ("Operation", "operation-type", "Provider-reported type of object or registry operation."),
    "AdditionalInfo": ("Additional Information", "additional-info", "Provider-native additional context for the audited operation."),
    "AdditionalInfo2": ("Additional Information", "additional-info-2", "Second provider-native additional context value for the audited operation."),
    "ProcessId": ("Process Information", "process-id", "Process identifier associated with the audited activity."),
    "ProcessName": ("Process Information", "process-name", "Process image name or path associated with the audited activity."),
    "OldValueType": ("Change Information", "old-value-type", "Registry value type before the modification."),
    "OldValue": ("Change Information", "old-value", "Registry value data before the modification."),
    "NewValueType": ("Change Information", "new-value-type", "Registry value type after the modification."),
    "NewValue": ("Change Information", "new-value", "Registry value data after the modification."),
    "LocalAddress": ("Local Endpoint", "local-address", "Local address associated with the IPsec negotiation."),
    "LocalAddressMask": ("Local Endpoint", "local-address-mask", "Local address mask associated with the IPsec traffic selector."),
    "LocalPort": ("Local Endpoint", "local-port", "Local port associated with the IPsec traffic selector."),
    "LocalTunnelEndpoint": ("Local Endpoint", "local-tunnel-endpoint", "Local tunnel endpoint associated with the IPsec negotiation."),
    "RemoteAddress": ("Remote Endpoint", "remote-address", "Remote address associated with the IPsec negotiation."),
    "RemoteAddressMask": ("Remote Endpoint", "remote-address-mask", "Remote address mask associated with the IPsec traffic selector."),
    "RemotePort": ("Remote Endpoint", "remote-port", "Remote port associated with the IPsec traffic selector."),
    "RemoteTunnelEndpoint": ("Remote Endpoint", "remote-tunnel-endpoint", "Remote tunnel endpoint associated with the IPsec negotiation."),
    "RemotePrivateAddress": ("Remote Endpoint", "remote-private-address", "Remote private address exposed by the provider for the IPsec negotiation."),
    "Protocol": ("Network", "protocol", "Numeric protocol identifier associated with the traffic selector."),
    "KeyModName": ("IPsec", "key-module-name", "Keying module name associated with the IPsec negotiation."),
    "FailurePoint": ("Failure Information", "failure-point", "Provider-reported point at which negotiation failed."),
    "FailureReason": ("Failure Information", "failure-reason", "Provider-reported reason for negotiation failure."),
    "Mode": ("Failure Information", "mode", "Provider-reported negotiation mode."),
    "State": ("Failure Information", "state", "Provider-reported negotiation state."),
    "Role": ("IPsec", "role", "Negotiation role, such as initiator or responder, as reported by the provider."),
    "MessageID": ("IPsec", "message-id", "Provider-reported IKE/IPsec message identifier."),
    "QMFilterID": ("Security Association", "quick-mode-filter-id", "Quick Mode filter identifier used for correlation."),
    "MMSAID": ("Security Association", "main-mode-sa-id", "Main Mode security-association identifier used for correlation."),
    "TunnelId": ("Security Association", "tunnel-id", "Version 1 tunnel identifier exposed by the provider."),
    "TrafficSelectorId": ("Security Association", "traffic-selector-id", "Version 1 traffic-selector identifier exposed by the provider."),
}


def dump(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_without_field(record):
    payload = copy.deepcopy(record)
    payload.pop("digest", None)
    return "sha256-" + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def source_record(source_id, canonical_key, title, urls, *, secondary=False, change=None):
    return {
        "schema_version":"1.0.0","record_kind":"source","id":source_id,"record_revision":1,
        "created_at":NOW,"updated_at":NOW,"curation_status":"validated","namespace":"atlas.source",
        "canonical_key":canonical_key,"title":title,
        "publisher":"Monterey Technology Group, Inc." if secondary else "Microsoft",
        "source_class":"tier-c-secondary-research" if secondary else "tier-a-authoritative",
        "canonical_urls":urls,"official_status":"secondary-reference" if secondary else "official",
        "license":{"status":"restricted" if secondary else "unknown"},
        "redistribution":{"policy":"prohibited" if secondary else "restricted","notes":"External Quick Detail / coverage benchmark only; no substantial page prose is packaged." if secondary else "ATLAS stores independently authored normalized facts and source locators; substantial Microsoft documentation prose is not redistributed."},
        "freshness_policy":{"expected_update_cadence":"web-reference" if secondary else "documentation-maintained","stale_after_days":90 if secondary else 180},
        "change_detection_policy":change or {"strategy":"content-diff","notes":"Material changes require controlled re-review."},
    }


def raw_discovery():
    path = Path(os.environ["ATLAS_DISCOVERY_JSON"])
    blob = path.read_bytes()
    assert "sha256-" + hashlib.sha256(blob).hexdigest() == RAW_SHA256
    data = json.loads(blob)
    assert data["provider"] == "Microsoft-Windows-Security-Auditing"
    assert data["channel_scope"] == "Security"
    assert data["unique_event_id_count"] == 10
    assert data["event_version_definition_count"] == 14
    assert [str(x) for x in data["requested_ids"]] == IDS
    return data


def provider_shapes(data):
    ns = {"e":"http://schemas.microsoft.com/win/2004/08/events"}
    result = {eid: [] for eid in IDS}
    for ev in data["events"]:
        eid = str(ev["id"])
        root = ET.fromstring(ev["template"])
        fields = [(d.attrib["name"], d.attrib.get("inType"), d.attrib.get("outType")) for d in root.findall("e:data", ns)]
        result[eid].append({"version":int(ev["version"]),"level":ev["level"],"fields":fields})
    for eid in IDS:
        result[eid].sort(key=lambda x: x["version"])
    assert {eid:[x["version"] for x in rows] for eid,rows in result.items()} == {
        "4654":[0,1],"4655":[0],"4656":[0,1],"4657":[0],"4658":[0],"4659":[0],"4660":[0],"4661":[0,1],"4662":[0],"4663":[0,1]
    }
    expected_counts = {"4654":[19,21],"4655":[4],"4656":[15,17],"4657":[14],"4658":[8],"4659":[13],"4660":[9],"4661":[16,17],"4662":[14],"4663":[12,13]}
    assert {eid:[len(x["fields"]) for x in rows] for eid,rows in result.items()} == expected_counts
    return result


def typ(value):
    if value == "win:Pointer": return "Pointer/HexInt64"
    return (value or "unknown").removeprefix("win:")


def kebab(name):
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", name).replace("_", "-")
    return value.lower()


def merged_fields(eid, shapes):
    ordered=[]
    seen=set()
    by_version={str(v["version"]):{n:(i,o) for n,i,o in v["fields"]} for v in shapes[eid]}
    for v in shapes[eid]:
        for n,_,_ in v["fields"]:
            if n not in seen:
                seen.add(n); ordered.append(n)
    out=[]
    for name in ordered:
        versions=[v for v in by_version if name in by_version[v]]
        types=[]
        for v in versions:
            i,_=by_version[v][name]
            if typ(i) not in types: types.append(typ(i))
        section,key,meaning=FIELD_DETAILS.get(name,("Provider Data",kebab(name),f"Provider-native {name} value for Event {eid}; interpret with the event and version context."))
        f={"key":key,"section":section,"native_name":name,"type":types[0] if len(types)==1 else "Version-dependent: " + " / ".join(types),"meaning":meaning,"versions":versions}
        if name == "SubjectLogonId": f["correlation"]="Correlate with authentication/logon telemetry on the same computer; Logon IDs are boot-session scoped."
        if name == "ProcessId": f["correlation"]="Correlate with process creation telemetry using PID plus event time because PIDs are reusable."
        if len(types)>1: f["notes"]="Provider field type differs by event version; preserve the exact version-specific structural evidence."
        out.append(f)
    return out


def event_versions(eid, shapes):
    notes={
        ("4654",0):"Version 0 provider shape contains 19 fields.",
        ("4654",1):"Version 1 adds TunnelId and TrafficSelectorId to the Version 0 shape.",
        ("4656",0):"Version 0 provider shape contains 15 fields.",
        ("4656",1):"Version 1 adds AccessReason and ResourceAttributes.",
        ("4661",0):"Version 0 provider shape contains 16 fields.",
        ("4661",1):"Version 1 adds AccessReason.",
        ("4663",0):"Version 0 provider shape contains 12 fields.",
        ("4663",1):"Version 1 adds ResourceAttributes.",
    }
    return [{"version":str(v["version"]),"generation":"Documented and/or provider-validated shape","field_count":len(v["fields"]),"notes":notes.get((eid,v["version"]),"Controlled Windows Server 2025 provider structural shape.")} for v in shapes[eid]]


def structural_inventory(shapes):
    identities=[]
    for eid in IDS:
        versions=[]
        for v in shapes[eid]:
            versions.append({"version":v["version"],"field_count":len(v["fields"]),"level":v["level"],"fields":[{"name":n,"in_type":i,"out_type":o} for n,i,o in v["fields"]]})
        identities.append({"event_id":eid,"versions":versions})
    doc={
        "ingestion_contract_version":"1.0.0","inventory_contract_version":"1.0.0",
        "inventory_id":"atlas:inventory:atlas.ingestion:windows-security-auditing-4654-4663-26100","inventory_kind":"telemetry",
        "declared_scope":"Microsoft-Windows-Security-Auditing provider Event IDs 4654 through 4663 linked to Security on controlled Windows Server 2025 Datacenter build 26100",
        "source_ids":[STRUCTURAL_ID],"inventory_method":"provider-runtime-metadata","inventory_source_version":STRUCTURAL_VERSION,
        "expected_identity_count":10,"identity_dimensions":["provider","channel","native-id","product","platform","version"],
        "scope_metadata":{"provider":"Microsoft-Windows-Security-Auditing","channel":"Security","product":"Windows Server 2025 Datacenter","platform":"Windows","windows_build":"26100","architecture":"64-bit","workflow_run_id":RUN_ID,"artifact_id":ARTIFACT_ID,"artifact_digest":ARTIFACT_DIGEST,"raw_artifact_sha256":RAW_SHA256,"provider_event_version_definition_count":14,"provider_unique_event_id_count":10,"expected_identities":identities,"completeness_semantics":"bounded structural evidence for ten identities already inside the separately frozen 423-ID provider denominator; version definitions are preserved and do not alter that denominator"},
        "guardrails":{"max_unexplained_shrink_percent":0,"max_unexplained_growth_percent":0},
    }
    doc["digest"] = digest_without_field(doc)
    return doc


def write_sources():
    sd=ROOT/"content/encyclopedia/sources"
    provider=source_record(STRUCTURAL_ID,"microsoft-windows-security-auditing-provider-26100-4654-4663","Microsoft-Windows-Security-Auditing Security Provider Metadata — Windows Server 2025 build 26100 — Event IDs 4654–4663 bounded batch",["https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log"],change={"strategy":"checksum","notes":f"Bound to workflow {RUN_ID}, artifact {ARTIFACT_ID}, artifact digest {ARTIFACT_DIGEST}, raw JSON {RAW_SHA256}, and normalized inventory."})
    dump(sd/"microsoft-windows-security-auditing-provider-26100-4654-4663.json",provider)
    for eid in IDS:
        meta=META[eid]
        dump(sd/f"microsoft-windows-security-event-{eid}.json",source_record(f"atlas:source:atlas.source:microsoft-windows-security-event-{eid}",f"microsoft-windows-security-event-{eid}",f"Microsoft Windows Security Auditing Event {eid} Documentation",[meta["url"],"https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/Appendix-L--Events-to-Monitor"],change={"strategy":"content-diff","notes":"Microsoft event/audit-policy material is semantic authority; controlled provider evidence is structural authority for exact versions and field shape."}))
        dump(sd/f"ultimate-windows-security-event-{eid}.json",source_record(f"atlas:source:atlas.source:ultimate-windows-security-event-{eid}",f"ultimate-windows-security-event-{eid}",f"Ultimate Windows Security — Windows Security Log Event ID {eid}",[f"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={eid}"],secondary=True,change={"strategy":"manual","notes":"No automated or bulk ingestion is authorized."}))


def event_record(eid, shapes):
    meta=META[eid]
    alias=meta.get("alias_title",meta["title"])
    return {
        "id":f"atlas:event:microsoft.windows.security:{eid}","namespace":"microsoft.windows.security","canonical_key":eid,
        "title":f"Windows Security Event {eid} — {meta['title']}","provider":"Microsoft-Windows-Security-Auditing","channel":"Security","product":"Windows Security Auditing","platform":"Windows","native_event_id":eid,
        "aliases":[eid,f"Event ID {eid}",f"Windows {eid}",alias],"lifecycle":"current",
        "source_id":f"atlas:source:atlas.source:microsoft-windows-security-event-{eid}","source_version":meta["source_version"],"source_url":meta["url"],"source_locator":f"{eid}({meta['marker']}): {meta['title']}",
        "structural_source":{"source_id":STRUCTURAL_ID,"source_version":STRUCTURAL_VERSION,"locator":f"Microsoft-Windows-Security-Auditing / Security / Event ID {eid} / versions "+",".join(str(v["version"]) for v in shapes[eid])},
        "external_reference":{"source_id":f"atlas:source:atlas.source:ultimate-windows-security-event-{eid}","url":f"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={eid}","role":"PRIMARY_EXTERNAL_QUICK_DETAIL_REFERENCE","redistribution":"source-link-and-coverage-benchmark-only"},
        "overview":{"summary":meta["summary"],"category":meta["category"],"subcategory":meta["subcategory"],"event_type":meta["event_type"],"provider_level":"Informational","event_versions":event_versions(eid,shapes)},
        "collection":{"requirements":meta["requirements"],"interpretation_note":meta["interpretation"]},"correlations":meta["correlations"],"analysis":meta["analysis"],"fields":merged_fields(eid,shapes),
    }


def update_blueprint(shapes):
    path=ROOT/"content/encyclopedia/approved-exemplars.json"
    doc=json.loads(path.read_text(encoding="utf-8"))
    existing={str(x.get("native_event_id")) for x in doc["events"] if x.get("namespace")=="microsoft.windows.security"}
    assert not existing.intersection(IDS)
    for rec in [event_record(eid,shapes) for eid in IDS]:
        n=int(rec["native_event_id"])
        idxs=[i for i,x in enumerate(doc["events"]) if x.get("namespace")=="microsoft.windows.security"]
        at=idxs[-1]+1
        for i in idxs:
            if int(doc["events"][i]["native_event_id"])>n:
                at=i; break
        doc["events"].insert(at,rec)
    dump(path,doc)


def update_coverage():
    path=ROOT/"content/encyclopedia/coverage-manifest.json"
    doc=json.loads(path.read_text(encoding="utf-8"))
    bench=doc["windows_security_log_review_benchmark"]
    assert (bench["listed_unique_event_id_count"],bench["encyclopedia_grade_listed_id_count"],bench["remaining_listed_id_count"])==(422,36,386)
    covered=sorted(set(bench["covered_event_ids"])|set(IDS),key=int)
    assert len(covered)==46
    bench.update({"covered_event_ids":covered,"encyclopedia_grade_listed_id_count":46,"remaining_listed_id_count":376,"completion_ratio":"46/422","completion_percent":10.9})
    fam=next(x for x in doc["families"] if x["id"]=="windows-security-auditing")
    assert (fam["denominator_count"],fam["encyclopedia_grade_count"],fam["remaining_count"])==(423,30,393)
    fam.update({"encyclopedia_grade_count":40,"remaining_count":383})
    dump(path,doc)


def rebuild_snapshot():
    path=ROOT/"tools/content/build_windows_security_coverage_snapshot.py"
    spec=importlib.util.spec_from_file_location("cov",path); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    snap=module.build_snapshot()
    assert (snap["denominator_count"],snap["encyclopedia_grade_count"],snap["remaining_count"],snap["completion_ratio"],snap["completion_percent"])==(423,40,383,"40/423",9.46)
    (ROOT/"content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json").write_text(json.dumps(snap,sort_keys=True,indent=2)+"\n",encoding="utf-8")


def update_existing_tests():
    path=ROOT/"tests/phase51010/test_windows_security_coverage_snapshot.py"
    text=path.read_text(encoding="utf-8")
    for old,new in [("== 30","== 40"),("== 393","== 383"),("== \"30/423\"","== \"40/423\""),("== 7.09","== 9.46")]:
        text=text.replace(old,new)
    path.write_text(text,encoding="utf-8")
    path=ROOT/"tests/phase51010/test_windows_security_auditing_4626_4653.py"
    text=path.read_text(encoding="utf-8")
    pattern=r'def test_05_coverage\(\):\n.*?(?=\ndef test_06_discovery_binding\(\):)'
    replacement='def test_05_coverage():\n m=json.loads((ROOT/"content/encyclopedia/coverage-manifest.json").read_text()); b=m["windows_security_log_review_benchmark"]; assert b["listed_unique_event_id_count"]==422 and set(IDS).issubset(set(b["covered_event_ids"])) and b["encyclopedia_grade_listed_id_count"]>=36; w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert w["denominator_count"]==423 and w["encyclopedia_grade_count"]>=30 and w["remaining_count"]==423-w["encyclopedia_grade_count"]\n'
    text,n=re.subn(pattern,replacement,text,flags=re.S); assert n==1
    path.write_text(text,encoding="utf-8")


def write_batch_test():
    path=ROOT/"tests/phase51010/test_windows_security_auditing_4654_4663.py"
    expected={"4654":{"0":19,"1":21},"4655":{"0":4},"4656":{"0":15,"1":17},"4657":{"0":14},"4658":{"0":8},"4659":{"0":13},"4660":{"0":9},"4661":{"0":16,"1":17},"4662":{"0":14},"4663":{"0":12,"1":13}}
    test=f'''#!/usr/bin/env python3\nfrom __future__ import annotations\nimport importlib.util,json\nfrom pathlib import Path\nROOT=Path(__file__).resolve().parents[2]\nIDS={IDS!r}\nSTRUCTURAL={STRUCTURAL_ID!r}\nEXPECTED={expected!r}\ndef mod(n,p):\n s=importlib.util.spec_from_file_location(n,p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m\nbuilder=mod("b",ROOT/"tools/content/build_encyclopedia_records.py"); validator=mod("v",ROOT/"tools/validate_phase52.py")\ndef records(): return builder.build_records()\ndef bp():\n d=json.loads((ROOT/"content/encyclopedia/approved-exemplars.json").read_text()); return {{str(x["native_event_id"]):x for x in d["events"] if x.get("namespace")=="microsoft.windows.security"}}\ndef test_01_canonical():\n pairs=[(ROOT/"content/encyclopedia/approved-exemplars.json",x) for x in records()]; e=validator.validate_schema_records(pairs)+validator.validate_semantics(pairs,validator.load_registries()); assert e==[],"\\n".join(e)\ndef test_02_search_and_scope():\n pairs=[(ROOT/"content/encyclopedia/approved-exemplars.json",x) for x in records()]; data={{x["id"]:x for x in records()}}\n for eid in IDS:\n  rid=f"atlas:event:microsoft.windows.security:{{eid}}"; assert validator.resolve_query(pairs,eid)==[rid]; c=data[rid]["native_identifiers"][0]["context"]; assert (c["provider"],c["channel"])==("Microsoft-Windows-Security-Auditing","Security")\ndef test_03_versions_are_exact_and_not_flattened():\n d=bp()\n for eid,want in EXPECTED.items(): assert {{r["version"]:r["field_count"] for r in d[eid]["overview"]["event_versions"]}}==want\n assert {{f["native_name"]:f for f in d["4654"]["fields"]}}["TunnelId"]["versions"]==["1"]\n assert {{f["native_name"]:f for f in d["4656"]["fields"]}}["AccessReason"]["versions"]==["1"]\n assert {{f["native_name"]:f for f in d["4661"]["fields"]}}["AccessReason"]["versions"]==["1"]\n assert {{f["native_name"]:f for f in d["4663"]["fields"]}}["ResourceAttributes"]["versions"]==["1"]\ndef test_04_semantic_distinctions_and_aliases():\n d=bp(); assert d["4654"]["overview"]["event_type"]=="Failure"; assert d["4656"]["overview"]["event_type"]=="Success/Failure"; assert d["4661"]["overview"]["event_type"]=="Success/Failure"; assert d["4662"]["overview"]["event_type"]=="Success/Failure"; assert "general object access" in " ".join(d["4656"]["aliases"]); assert "SAM or directory service" in " ".join(d["4661"]["aliases"])\ndef test_05_evidence_and_redistribution():\n data={{x["id"]:x for x in records()}}\n for eid in IDS:\n  cs=[x for x in data.values() if x.get("record_kind")=="claim" and x.get("subject_id")==f"atlas:event:microsoft.windows.security:{{eid}}" and x.get("predicate")=="telemetry.represents"]; assert len(cs)==1 and STRUCTURAL in {{e["source_id"] for e in cs[0]["evidence"]}}; assert data[f"atlas:source:atlas.source:ultimate-windows-security-event-{{eid}}"]["redistribution"]["policy"]=="prohibited"\ndef test_06_coverage():\n m=json.loads((ROOT/"content/encyclopedia/coverage-manifest.json").read_text()); b=m["windows_security_log_review_benchmark"]; assert (b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(46,376,"46/422",10.9); assert set(IDS).issubset(set(b["covered_event_ids"])); w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert (w["denominator_count"],w["encyclopedia_grade_count"],w["remaining_count"])==(423,40,383)\ndef test_07_discovery_binding():\n x=json.loads((ROOT/"ingestion/inventories/windows-security-auditing-4654-4663-26100.telemetry.json").read_text()); s=x["scope_metadata"]; assert (s["workflow_run_id"],s["artifact_id"],s["provider_event_version_definition_count"],s["provider_unique_event_id_count"])==({RUN_ID},{ARTIFACT_ID},14,10); assert s["artifact_digest"]=={ARTIFACT_DIGEST!r} and s["raw_artifact_sha256"]=={RAW_SHA256!r}\n'''
    path.write_text(test,encoding="utf-8")


def update_docs_and_redistribution():
    path=ROOT/"docs/windows-security-log-scope.md"
    text=path.read_text(encoding="utf-8")
    old='''Current controlled progress after the third bounded Windows Security Log batch:\n\n- Windows Security Log UWS review benchmark: `36/422` listed identities encyclopedia-grade (`8.53%`), `386` remaining;\n- newly promoted Security-Auditing IDs in this batch: `4626`, `4627`, `4634`, `4646`, `4647`, `4649`, `4650`, `4651`, `4652`, `4653`;\n- Windows Security Auditing provider coverage: `30/423` encyclopedia-grade with `393` provider-specific identities remaining;'''
    new='''Current controlled progress after the fourth bounded Windows Security Log batch:\n\n- Windows Security Log UWS review benchmark: `46/422` listed identities encyclopedia-grade (`10.90%`), `376` remaining;\n- newly promoted Security-Auditing IDs in this batch: `4654`, `4655`, `4656`, `4657`, `4658`, `4659`, `4660`, `4661`, `4662`, `4663`;\n- Windows Security Auditing provider coverage: `40/423` encyclopedia-grade with `383` provider-specific identities remaining;'''
    assert old in text
    path.write_text(text.replace(old,new),encoding="utf-8")
    path=ROOT/"docs/releases/third-party-redistribution-inventory.json"
    doc=json.loads(path.read_text(encoding="utf-8")); row=next(x for x in doc["entries"] if x["id"]=="microsoft-windows-security-documentation")
    additions=[*[f"content/encyclopedia/sources/microsoft-windows-security-event-{eid}.json" for eid in IDS],"ingestion/inventories/windows-security-auditing-4654-4663-26100.telemetry.json","content/encyclopedia/sources/microsoft-windows-security-auditing-provider-26100-4654-4663.json"]
    parts=[x.strip() for x in row.get("review_evidence","").split(" + ") if x.strip()]
    for item in additions:
        if item not in parts: parts.append(item)
    row["review_evidence"]=" + ".join(parts)
    row["upstream_revision"]="Microsoft Learn Security-Auditing event/audit-policy sources plus controlled provider structural evidence; source prose excluded from Public Preview pack"
    dump(path,doc)


def main():
    data=raw_discovery(); shapes=provider_shapes(data)
    inv=structural_inventory(shapes)
    dump(ROOT/"ingestion/inventories/windows-security-auditing-4654-4663-26100.telemetry.json",inv)
    write_sources(); update_blueprint(shapes); update_coverage(); rebuild_snapshot(); update_existing_tests(); write_batch_test(); update_docs_and_redistribution()
    print("batch_ids="+",".join(IDS)); print("inventory_digest="+inv["digest"]); print("coverage=46/422"); print("security_auditing=40/423")

if __name__ == "__main__":
    main()
