#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_COMMIT = "a5757f49df3b83b5a915ebf578d0678b6ffbcbf4"
HISTORICAL_PATH = "tools/tmp_apply_security_auditing_4689_4698.py"
NOW = "2026-10-07T10:55:00Z"
IDS = ["4699","4700","4701","4702","4703","4704","4705","4706","4707","4709"]
RUN_ID = 37610244718
ARTIFACT_ID = 11478270373
ARTIFACT_DIGEST = "sha256:9fedb9a65977712bec90d23589773d9f97ff5b2167054819c3de7d12602cc7de"
RAW_SHA256 = "sha256-b486c1cb4b2380e14e9eba77fc79efa09734faff9ff90a221a6ad3f0acc42633"
STRUCTURAL_ID = "atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-4699-4709"
STRUCTURAL_VERSION = "windows-server-2025-build-26100-security-auditing-4699-4709"

META = {
    "4699": {
        "title": "A scheduled task was deleted",
        "category": "Object Access",
        "subcategory": "Audit Other Object Access Events",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4699",
        "source_version": "event-4699-v0-doc-plus-provider-v1",
        "summary": "Records deletion of a scheduled task. Controlled provider evidence preserves Version 0 and Version 1; Version 1 adds client process identity/lineage plus RPC locality and FQDN context.",
        "requirements": ["Enable Audit Other Object Access Events success auditing where scheduled-task lifecycle visibility is required.", "Preserve TaskName, TaskContent and the exact event version; retain Version 1 client/RPC/FQDN context."],
        "interpretation": "Scheduled-task deletion can be routine administration or cleanup, but unexpected deletion of critical or suspicious tasks can indicate anti-forensics, defense evasion or persistence cleanup.",
        "analysis": ["Review TaskName and TaskContent against approved automation and known persistence mechanisms.", "For Version 1, correlate ClientProcessId/ParentProcessId with process creation telemetry and use RPC/FQDN context to distinguish local from remote administration."],
        "correlations": [{"target":"4698","key":"TaskName + Computer","purpose":"pair task deletion with prior task creation"},{"target":"4702","key":"TaskName + Computer + time","purpose":"review task updates before deletion"}],
    },
    "4700": {
        "title": "A scheduled task was enabled",
        "category": "Object Access",
        "subcategory": "Audit Other Object Access Events",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4700",
        "source_version": "event-4700-v0-doc-plus-provider-v1",
        "summary": "Records enablement of a scheduled task. Controlled provider evidence preserves Version 0 and Version 1; Version 1 adds client process identity/lineage plus RPC locality and FQDN context.",
        "requirements": ["Enable Audit Other Object Access Events success auditing where scheduled-task state changes require visibility.", "Preserve TaskName, TaskContent and the exact event version; retain Version 1 client/RPC/FQDN context."],
        "interpretation": "Enabling a previously disabled scheduled task may reactivate legitimate automation or persistence. Prioritize critical tasks, unexpected principals, remote changes and unusual task actions.",
        "analysis": ["Inspect task XML and baseline whether the task should normally be enabled.", "For Version 1, correlate ClientProcessId/ParentProcessId with 4688 and evaluate RPC/FQDN context."],
        "correlations": [{"target":"4701","key":"TaskName + Computer","purpose":"track enable/disable transitions"},{"target":"4698","key":"TaskName + Computer","purpose":"resolve original task creation"}],
    },
    "4701": {
        "title": "A scheduled task was disabled",
        "category": "Object Access",
        "subcategory": "Audit Other Object Access Events",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4701",
        "source_version": "event-4701-v0-doc-plus-provider-v1",
        "summary": "Records disabling of a scheduled task. Controlled provider evidence preserves Version 0 and Version 1; Version 1 adds client process identity/lineage plus RPC locality and FQDN context.",
        "requirements": ["Enable Audit Other Object Access Events success auditing where scheduled-task state changes require visibility.", "Preserve TaskName, TaskContent and the exact event version; retain Version 1 client/RPC/FQDN context."],
        "interpretation": "Disabling a critical scheduled task can disrupt controls or operations; unexpected changes should be compared with approved administration and the task's security role.",
        "analysis": ["Review TaskName and task XML for security-sensitive or persistence-related actions.", "For Version 1, resolve the modifying client process and whether the change was local or remote."],
        "correlations": [{"target":"4700","key":"TaskName + Computer","purpose":"track disable/enable transitions"},{"target":"4698","key":"TaskName + Computer","purpose":"resolve original task creation"}],
    },
    "4702": {
        "title": "A scheduled task was updated",
        "category": "Object Access",
        "subcategory": "Audit Other Object Access Events",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4702",
        "source_version": "event-4702-v0-doc-plus-provider-v1",
        "summary": "Records modification of a scheduled task and captures the new XML definition. Controlled provider evidence preserves Version 0 and Version 1; Version 1 adds client process identity/lineage plus RPC locality and FQDN context.",
        "requirements": ["Enable Audit Other Object Access Events success auditing where scheduled-task modification visibility is required.", "Preserve TaskName, TaskContentNew and the exact event version; retain Version 1 client/RPC/FQDN context."],
        "interpretation": "Scheduled-task updates are high-value persistence and execution telemetry because an existing trusted task can be repurposed by changing actions, principals, triggers or credentials.",
        "analysis": ["Parse TaskContentNew XML for executable/script actions, principals, logon type, hidden settings and suspicious triggers.", "For Version 1, correlate the client and parent PIDs with 4688 and evaluate remote RPC/FQDN context."],
        "correlations": [{"target":"4698","key":"TaskName + Computer","purpose":"compare current update with task creation"},{"target":"4699","key":"TaskName + Computer + time","purpose":"track later task deletion"}],
    },
    "4703": {
        "title": "A user right was adjusted",
        "category": "Policy Change",
        "subcategory": "Audit Authorization Policy Change",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4703",
        "source_version": "event-4703-v0-doc",
        "summary": "Records token privilege adjustment for a target account, including the requesting subject, target logon context, process and enabled/disabled privilege lists.",
        "requirements": ["Enable Audit Authorization Policy Change success auditing only where token-privilege adjustment visibility is intentionally required because event volume can be high.", "Preserve target logon context, ProcessId/ProcessName and both enabled and disabled privilege lists."],
        "interpretation": "This event can be noisy because applications and services legitimately adjust token privileges. Security value is highest for unusual principals, processes or sensitive privileges outside expected baselines.",
        "analysis": ["Baseline frequent service/application privilege adjustments before alerting.", "Correlate ProcessId with 4688 and target/subject LogonId values with authentication telemetry before attributing the action."],
        "correlations": [{"target":"4688","key":"ProcessId + ProcessName + Computer + time","purpose":"resolve the process adjusting token privileges"},{"target":"4624","key":"TargetLogonId or SubjectLogonId + Computer","purpose":"resolve logon context"}],
    },
    "4704": {
        "title": "A user right was assigned",
        "category": "Policy Change",
        "subcategory": "Audit Authorization Policy Change",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4704",
        "source_version": "event-4704-v0-doc",
        "summary": "Records assignment of one or more local user rights to a security principal.",
        "requirements": ["Enable Audit Authorization Policy Change success auditing on systems where local user-right changes require monitoring.", "Preserve TargetSid, PrivilegeList and subject logon context."],
        "interpretation": "Assignment of powerful rights can materially change privilege and persistence opportunities. Compare the target principal and granted rights with approved security policy.",
        "analysis": ["Prioritize restricted rights and assignments to unexpected, external, dormant or non-administrative principals.", "Correlate SubjectLogonId with authentication and administrative change records."],
        "correlations": [{"target":"4705","key":"TargetSid + PrivilegeList + Computer","purpose":"track later removal of the assigned user right"},{"target":"4624","key":"SubjectLogonId + Computer","purpose":"resolve the administrator logon context"}],
    },
    "4705": {
        "title": "A user right was removed",
        "category": "Policy Change",
        "subcategory": "Audit Authorization Policy Change",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4705",
        "source_version": "event-4705-v0-doc",
        "summary": "Records removal of one or more local user rights from a security principal.",
        "requirements": ["Enable Audit Authorization Policy Change success auditing on systems where local user-right changes require monitoring.", "Preserve TargetSid, PrivilegeList and subject logon context."],
        "interpretation": "Removal may be legitimate hardening or deprovisioning, but unexpected changes to critical accounts or rights can disrupt operations or conceal earlier unauthorized grants.",
        "analysis": ["Validate removed rights against approved change records and expected target-account policy.", "Correlate SubjectLogonId with authentication and compare with preceding 4704 events for the same target/right."],
        "correlations": [{"target":"4704","key":"TargetSid + PrivilegeList + Computer","purpose":"identify prior assignment of the removed right"},{"target":"4624","key":"SubjectLogonId + Computer","purpose":"resolve the administrator logon context"}],
    },
    "4706": {
        "title": "A new trust was created to a domain",
        "category": "Policy Change",
        "subcategory": "Audit Authentication Policy Change",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4706",
        "source_version": "event-4706-v0-doc",
        "summary": "Records creation of an Active Directory domain trust on a domain controller, including trusted-domain identity and provider-native trust type/direction/attributes and SID-filtering state.",
        "requirements": ["Collect this event from domain controllers and monitor all domain-trust creation.", "Preserve DomainName, DomainSid, TdoType, TdoDirection, TdoAttributes, SidFilteringEnabled and subject context."],
        "interpretation": "Domain-trust creation is a high-impact authentication-policy change. Any unplanned trust should be investigated for authorization, trust direction/type and SID-filtering implications.",
        "analysis": ["Validate the trusted domain, direction and attributes against approved forest/domain architecture.", "Review SID-filtering state and the subject account that created the trust."],
        "correlations": [{"target":"4707","key":"DomainSid + DomainName","purpose":"track later removal of the trust"},{"target":"4624","key":"SubjectLogonId + Computer","purpose":"resolve the administrative logon"}],
    },
    "4707": {
        "title": "A trust to a domain was removed",
        "category": "Policy Change",
        "subcategory": "Audit Authentication Policy Change",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4707",
        "source_version": "event-4707-v0-doc",
        "summary": "Records removal of an Active Directory domain trust on a domain controller.",
        "requirements": ["Collect this event from domain controllers and monitor all domain-trust removal.", "Preserve DomainName, DomainSid and subject logon context."],
        "interpretation": "Domain-trust removal is a material authentication-policy change. Unplanned removal can disrupt cross-domain access and may indicate unauthorized administrative activity.",
        "analysis": ["Validate the removed trust against approved architecture and change records.", "Identify the subject account and correlate with trust creation/modification history."],
        "correlations": [{"target":"4706","key":"DomainSid + DomainName","purpose":"identify creation history for the removed trust"},{"target":"4624","key":"SubjectLogonId + Computer","purpose":"resolve the administrative logon"}],
    },
    "4709": {
        "title": "IPsec Services was started",
        "category": "Policy Change",
        "subcategory": "Audit Filtering Platform Policy Change",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-filtering-platform-policy-change",
        "source_version": "audit-filtering-platform-policy-change-event-4709-provider-v0",
        "summary": "Microsoft identifies Event 4709 as the success audit for IPsec Services start status. Controlled provider evidence preserves three provider-rendered parameter fields without assigning undocumented meanings to those slots.",
        "requirements": ["Enable Audit Filtering Platform Policy Change success auditing where IPsec service status changes require visibility.", "Preserve param1, param2 and param3 exactly as provider-rendered strings together with host and event context."],
        "interpretation": "Treat this as IPsec service-state telemetry. Unexpected starts or restarts should be correlated with service configuration, policy deployment and administrative activity; the three provider parameters remain opaque unless separately documented.",
        "analysis": ["Baseline expected IPsec service startup behavior and investigate unexpected state transitions.", "Do not infer semantic meaning for param1/param2/param3 beyond their provider-rendered values without authoritative documentation."],
        "correlations": [{"target":"4710","key":"Computer + time","purpose":"track later IPsec Services disablement"}],
    },
}

EXTRA_FIELD_DETAILS = {
    "TaskContentNew": ("Task", "task-content-new", "Updated XML task definition captured when the scheduled task was changed."),
    "TargetUserSid": ("Target Account", "target-user-sid", "SID of the target account whose token privileges were adjusted."),
    "TargetUserName": ("Target Account", "target-user-name", "Name of the target account whose token privileges were adjusted."),
    "TargetDomainName": ("Target Account", "target-domain-name", "Domain or computer context for the target account."),
    "EnabledPrivilegeList": ("Privileges", "enabled-privilege-list", "Privileges enabled on the target token by the adjustment."),
    "DisabledPrivilegeList": ("Privileges", "disabled-privilege-list", "Privileges disabled on the target token by the adjustment."),
    "TargetSid": ("Target Account", "target-sid", "SID of the security principal whose local user-right assignment changed."),
    "PrivilegeList": ("User Rights", "privilege-list", "Provider-rendered list of user rights assigned to or removed from the target principal."),
    "DomainName": ("Trusted Domain", "domain-name", "Name of the trusted domain associated with the trust change."),
    "DomainSid": ("Trusted Domain", "domain-sid", "SID of the trusted domain associated with the trust change."),
    "TdoType": ("Trusted Domain", "tdo-type", "Provider-native trusted-domain object type value."),
    "TdoDirection": ("Trusted Domain", "tdo-direction", "Provider-native trust direction value."),
    "TdoAttributes": ("Trusted Domain", "tdo-attributes", "Provider-native trusted-domain attribute bitmask."),
    "SidFilteringEnabled": ("Trusted Domain", "sid-filtering-enabled", "Provider-rendered SID-filtering state for the trust."),
    "param1": ("IPsec Service", "parameter-1", "Provider-rendered Event 4709 parameter string; semantic meaning is intentionally left unspecified without authoritative documentation."),
    "param2": ("IPsec Service", "parameter-2", "Provider-rendered Event 4709 parameter string; semantic meaning is intentionally left unspecified without authoritative documentation."),
    "param3": ("IPsec Service", "parameter-3", "Provider-rendered Event 4709 parameter string; semantic meaning is intentionally left unspecified without authoritative documentation."),
}


def load_impl():
    text = subprocess.check_output(["git", "show", f"{HISTORICAL_COMMIT}:{HISTORICAL_PATH}"], text=True)
    tmp = Path(tempfile.mkdtemp()) / "batch06_impl.py"
    tmp.write_text(text, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("batch06_impl", tmp)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load historical Batch 06 helper")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.ROOT = ROOT
    mod.NOW = NOW
    mod.IDS = IDS
    mod.RUN_ID = RUN_ID
    mod.ARTIFACT_ID = ARTIFACT_ID
    mod.ARTIFACT_DIGEST = ARTIFACT_DIGEST
    mod.RAW_SHA256 = RAW_SHA256
    mod.STRUCTURAL_ID = STRUCTURAL_ID
    mod.STRUCTURAL_VERSION = STRUCTURAL_VERSION
    mod.META = META
    mod.FIELD_DETAILS.update(EXTRA_FIELD_DETAILS)
    return mod


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
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events"}
    result = {eid: [] for eid in IDS}
    for event in data["events"]:
        eid = str(event["id"])
        root = ET.fromstring(event["template"])
        fields = [(x.attrib["name"], x.attrib.get("inType"), x.attrib.get("outType")) for x in root.findall("e:data", ns)]
        result[eid].append({"version": int(event["version"]), "level": event["level"], "fields": fields})
    expected_versions = {
        "4699":[0,1], "4700":[0,1], "4701":[0,1], "4702":[0,1],
        "4703":[0], "4704":[0], "4705":[0], "4706":[0], "4707":[0], "4709":[0],
    }
    expected_counts = {
        "4699":{0:6,1:11}, "4700":{0:6,1:11}, "4701":{0:6,1:11}, "4702":{0:6,1:11},
        "4703":{0:12}, "4704":{0:6}, "4705":{0:6}, "4706":{0:10}, "4707":{0:6}, "4709":{0:3},
    }
    assert {eid:[r["version"] for r in rows] for eid,rows in result.items()} == expected_versions
    assert {eid:{r["version"]:len(r["fields"]) for r in rows} for eid,rows in result.items()} == expected_counts
    extras = ["ClientProcessStartKey","ClientProcessId","ParentProcessId","RpcCallClientLocality","FQDN"]
    for eid in ("4699","4700","4701","4702"):
        byv = {r["version"]:[f[0] for f in r["fields"]] for r in result[eid]}
        assert byv[1][-5:] == extras
    assert [f[0] for f in result["4702"][0]["fields"]][-2:] == ["TaskName","TaskContentNew"]
    assert [f[0] for f in result["4709"][0]["fields"]] == ["param1","param2","param3"]
    return result


def build_inventory(base, shapes):
    identities = []
    for eid in IDS:
        versions = []
        for shape in shapes[eid]:
            versions.append({
                "version": shape["version"],
                "field_count": len(shape["fields"]),
                "level": shape["level"],
                "fields": [{"name": n, "in_type": i, "out_type": o} for n,i,o in shape["fields"]],
            })
        identities.append({"event_id": eid, "versions": versions})
    doc = {
        "ingestion_contract_version": "1.0.0",
        "inventory_contract_version": "1.0.0",
        "inventory_id": "atlas:inventory:atlas.ingestion:windows-security-auditing-4699-4709-26100",
        "inventory_kind": "telemetry",
        "declared_scope": "Microsoft-Windows-Security-Auditing provider Event IDs 4699, 4700-4707 and 4709 linked to Security on controlled Windows Server 2025 Datacenter build 26100",
        "source_ids": [STRUCTURAL_ID],
        "inventory_method": "provider-runtime-metadata",
        "inventory_source_version": STRUCTURAL_VERSION,
        "expected_identity_count": 10,
        "identity_dimensions": ["provider","channel","native-id","product","platform","version"],
        "scope_metadata": {
            "provider":"Microsoft-Windows-Security-Auditing",
            "channel":"Security",
            "product":"Windows Server 2025 Datacenter",
            "platform":"Windows",
            "windows_build":"26100",
            "architecture":"64-bit",
            "workflow_run_id": RUN_ID,
            "artifact_id": ARTIFACT_ID,
            "artifact_digest": ARTIFACT_DIGEST,
            "raw_artifact_sha256": RAW_SHA256,
            "provider_event_version_definition_count": 14,
            "provider_unique_event_id_count": 10,
            "expected_identities": identities,
            "completeness_semantics": "bounded structural evidence for ten identities already inside the separately frozen 423-ID provider denominator; fourteen version definitions are preserved and do not alter that denominator",
        },
        "guardrails":{"max_unexplained_shrink_percent":0,"max_unexplained_growth_percent":0},
    }
    doc["digest"] = base.digest_without_field(doc)
    return doc


def write_sources(base):
    source_dir = ROOT / "content/encyclopedia/sources"
    provider = base.source_record(
        STRUCTURAL_ID,
        "microsoft-windows-security-auditing-provider-26100-4699-4709",
        "Microsoft-Windows-Security-Auditing Security Provider Metadata — Windows Server 2025 build 26100 — bounded Event IDs 4699–4709 batch",
        ["https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log"],
        change={"strategy":"checksum","notes":f"Bound to workflow {RUN_ID}, artifact {ARTIFACT_ID}, artifact digest {ARTIFACT_DIGEST}, raw JSON {RAW_SHA256}, and normalized inventory."},
    )
    base.dump(source_dir / "microsoft-windows-security-auditing-provider-26100-4699-4709.json", provider)
    appendix = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/Appendix-L--Events-to-Monitor"
    for eid in IDS:
        meta = META[eid]
        base.dump(
            source_dir / f"microsoft-windows-security-event-{eid}.json",
            base.source_record(
                f"atlas:source:atlas.source:microsoft-windows-security-event-{eid}",
                f"microsoft-windows-security-event-{eid}",
                f"Microsoft Windows Security Auditing Event {eid} Documentation",
                [meta["url"], appendix],
                change={"strategy":"content-diff","notes":"Microsoft event/audit-policy material is semantic authority; controlled provider evidence is structural authority for exact version and field shape."},
            ),
        )
        base.dump(
            source_dir / f"ultimate-windows-security-event-{eid}.json",
            base.source_record(
                f"atlas:source:atlas.source:ultimate-windows-security-event-{eid}",
                f"ultimate-windows-security-event-{eid}",
                f"Ultimate Windows Security — Windows Security Log Event ID {eid}",
                [f"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={eid}"],
                secondary=True,
                change={"strategy":"manual","notes":"Coverage / Quick Detail benchmark only. No automated or bulk ingestion is authorized."},
            ),
        )


def update_coverage(base):
    path = ROOT / "content/encyclopedia/coverage-manifest.json"
    data = json.loads(path.read_text())
    b = data["windows_security_log_review_benchmark"]
    assert (b["listed_unique_event_id_count"], b["encyclopedia_grade_listed_id_count"], b["remaining_listed_id_count"], b["completion_ratio"]) == (422,66,356,"66/422")
    covered = sorted(set(b["covered_event_ids"]) | set(IDS), key=int)
    assert len(covered) == 76
    b.update({"covered_event_ids":covered,"encyclopedia_grade_listed_id_count":76,"remaining_listed_id_count":346,"completion_ratio":"76/422","completion_percent":18.01})
    fam = next(x for x in data["families"] if x["id"] == "windows-security-auditing")
    assert (fam["denominator_count"],fam["encyclopedia_grade_count"],fam["remaining_count"]) == (423,60,363)
    fam.update({"encyclopedia_grade_count":70,"remaining_count":353})
    base.dump(path, data)


def rebuild_snapshot():
    path = ROOT / "tools/content/build_windows_security_coverage_snapshot.py"
    spec = importlib.util.spec_from_file_location("coverage_builder", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load coverage snapshot builder")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    snap = m.build_snapshot()
    assert (snap["denominator_count"],snap["encyclopedia_grade_count"],snap["remaining_count"],snap["completion_ratio"],snap["completion_percent"]) == (423,70,353,"70/423",16.55)
    (ROOT / "content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json").write_text(json.dumps(snap, sort_keys=True, indent=2) + "\n")


def update_tests():
    path = ROOT / "tests/phase51010/test_windows_security_coverage_snapshot.py"
    text = path.read_text()
    assert text.count('snapshot["encyclopedia_grade_count"] == 60') == 2
    assert text.count('snapshot["remaining_count"] == 363') == 1
    assert text.count('snapshot["completion_ratio"] == "60/423"') == 1
    assert text.count('snapshot["completion_percent"] == 14.18') == 1
    text = text.replace('snapshot["encyclopedia_grade_count"] == 60', 'snapshot["encyclopedia_grade_count"] == 70')
    text = text.replace('snapshot["remaining_count"] == 363', 'snapshot["remaining_count"] == 353')
    text = text.replace('snapshot["completion_ratio"] == "60/423"', 'snapshot["completion_ratio"] == "70/423"')
    text = text.replace('snapshot["completion_percent"] == 14.18', 'snapshot["completion_percent"] == 16.55')
    path.write_text(text)

    path = ROOT / "tests/phase51010/test_windows_security_auditing_4689_4698.py"
    text = path.read_text()
    old = 'assert (b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(66,356,"66/422",15.64); assert set(IDS).issubset(set(b["covered_event_ids"])); w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert (w["denominator_count"],w["encyclopedia_grade_count"],w["remaining_count"])==(423,60,363)'
    new = 'assert b["listed_unique_event_id_count"]==422 and set(IDS).issubset(set(b["covered_event_ids"])) and b["encyclopedia_grade_listed_id_count"]>=66; w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert w["denominator_count"]==423 and w["encyclopedia_grade_count"]>=60 and w["remaining_count"]==423-w["encyclopedia_grade_count"]'
    assert text.count(old) == 1
    path.write_text(text.replace(old,new))


def write_batch_test(base, shapes):
    expected = {eid:{str(r["version"]):len(r["fields"]) for r in shapes[eid]} for eid in IDS}
    text = f'''#!/usr/bin/env python3
from __future__ import annotations
import importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
IDS={IDS!r}
STRUCTURAL={STRUCTURAL_ID!r}
EXPECTED={expected!r}
def mod(n,p):
 s=importlib.util.spec_from_file_location(n,p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
builder=mod("b",ROOT/"tools/content/build_encyclopedia_records.py"); validator=mod("v",ROOT/"tools/validate_phase52.py")
def records(): return builder.build_records()
def bp():
 d=json.loads((ROOT/"content/encyclopedia/approved-exemplars.json").read_text()); return {{str(x["native_event_id"]):x for x in d["events"] if x.get("namespace")=="microsoft.windows.security"}}
def test_01_canonical():
 pairs=[(ROOT/"content/encyclopedia/approved-exemplars.json",x) for x in records()]; e=validator.validate_schema_records(pairs)+validator.validate_semantics(pairs,validator.load_registries()); assert e==[],"\\n".join(e)
def test_02_search_and_scope():
 pairs=[(ROOT/"content/encyclopedia/approved-exemplars.json",x) for x in records()]; data={{x["id"]:x for x in records()}}
 for eid in IDS:
  rid=f"atlas:event:microsoft.windows.security:{{eid}}"; assert validator.resolve_query(pairs,eid)==[rid]; c=data[rid]["native_identifiers"][0]["context"]; assert (c["provider"],c["channel"])==("Microsoft-Windows-Security-Auditing","Security")
def test_03_versions_exact():
 d=bp()
 for eid,want in EXPECTED.items(): assert {{str(r["version"]):r["field_count"] for r in d[eid]["overview"]["event_versions"]}}==want
 for eid in ("4699","4700","4701","4702"): assert EXPECTED[eid]=={{"0":6,"1":11}}
 assert EXPECTED["4703"]=={{"0":12}} and EXPECTED["4706"]=={{"0":10}} and EXPECTED["4709"]=={{"0":3}}
def test_04_semantics():
 d=bp()
 for eid in IDS: assert d[eid]["overview"]["event_type"]=="Success"
 assert d["4703"]["overview"]["subcategory"]=="Audit Authorization Policy Change"
 assert d["4706"]["overview"]["subcategory"]=="Audit Authentication Policy Change"
 assert d["4709"]["overview"]["subcategory"]=="Audit Filtering Platform Policy Change"
def test_05_evidence_and_redistribution():
 data={{x["id"]:x for x in records()}}
 for eid in IDS:
  cs=[x for x in data.values() if x.get("record_kind")=="claim" and x.get("subject_id")==f"atlas:event:microsoft.windows.security:{{eid}}" and x.get("predicate")=="telemetry.represents"]; assert len(cs)==1 and STRUCTURAL in {{e["source_id"] for e in cs[0]["evidence"]}}; assert data[f"atlas:source:atlas.source:ultimate-windows-security-event-{{eid}}"]["redistribution"]["policy"]=="prohibited"
def test_06_coverage():
 m=json.loads((ROOT/"content/encyclopedia/coverage-manifest.json").read_text()); b=m["windows_security_log_review_benchmark"]; assert (b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(76,346,"76/422",18.01); assert set(IDS).issubset(set(b["covered_event_ids"])); w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert (w["denominator_count"],w["encyclopedia_grade_count"],w["remaining_count"])==(423,70,353)
def test_07_discovery_binding():
 x=json.loads((ROOT/"ingestion/inventories/windows-security-auditing-4699-4709-26100.telemetry.json").read_text()); s=x["scope_metadata"]; assert (s["workflow_run_id"],s["artifact_id"],s["provider_event_version_definition_count"],s["provider_unique_event_id_count"])==({RUN_ID},{ARTIFACT_ID},14,10); assert s["artifact_digest"]=={ARTIFACT_DIGEST!r} and s["raw_artifact_sha256"]=={RAW_SHA256!r}
'''
    (ROOT / "tests/phase51010/test_windows_security_auditing_4699_4709.py").write_text(text)


def update_docs(base):
    path = ROOT / "docs/windows-security-log-scope.md"
    text = path.read_text()
    old_lines = {
        "Current controlled progress after the sixth bounded Windows Security Log batch:":"Current controlled progress after the seventh bounded Windows Security Log batch:",
        "- Windows Security Log UWS review benchmark: `66/422` listed identities encyclopedia-grade (`15.64%`), `356` remaining;":"- Windows Security Log UWS review benchmark: `76/422` listed identities encyclopedia-grade (`18.01%`), `346` remaining;",
        "- newly promoted Security-Auditing IDs in this batch: `4689`, `4690`, `4691`, `4692`, `4693`, `4694`, `4695`, `4696`, `4697`, `4698`;":"- newly promoted Security-Auditing IDs in this batch: `4699`, `4700`, `4701`, `4702`, `4703`, `4704`, `4705`, `4706`, `4707`, `4709`;",
        "- Windows Security Auditing provider coverage: `60/423` encyclopedia-grade with `363` provider-specific identities remaining;":"- Windows Security Auditing provider coverage: `70/423` encyclopedia-grade with `353` provider-specific identities remaining;",
    }
    for old,new in old_lines.items():
        assert text.count(old)==1, old
        text=text.replace(old,new)
    path.write_text(text)

    path = ROOT / "docs/releases/third-party-redistribution-inventory.json"
    data=json.loads(path.read_text())
    row=next(x for x in data["entries"] if x["id"]=="microsoft-windows-security-documentation")
    additions=[*[f"content/encyclopedia/sources/microsoft-windows-security-event-{eid}.json" for eid in IDS], "ingestion/inventories/windows-security-auditing-4699-4709-26100.telemetry.json", "content/encyclopedia/sources/microsoft-windows-security-auditing-provider-26100-4699-4709.json"]
    parts=[x.strip() for x in row.get("review_evidence","").split(" + ") if x.strip()]
    for item in additions:
        if item not in parts: parts.append(item)
    row["review_evidence"]=" + ".join(parts)
    base.dump(path,data)


def main():
    impl=load_impl()
    impl.raw_discovery=raw_discovery
    impl.provider_shapes=provider_shapes
    impl.build_inventory=build_inventory
    impl.write_sources=write_sources
    impl.update_coverage=update_coverage
    impl.rebuild_snapshot=rebuild_snapshot
    impl.update_tests=update_tests
    impl.write_batch_test=write_batch_test
    impl.update_docs=update_docs
    impl.main()


if __name__ == "__main__":
    main()
