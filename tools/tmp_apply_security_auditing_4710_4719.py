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
PREVIOUS_COMMIT = "a192a01"
PREVIOUS_PATH = "tools/tmp_apply_security_auditing_4699_4709.py"
NOW = "2026-10-07T13:15:00Z"
IDS = ["4710", "4711", "4712", "4713", "4714", "4715", "4716", "4717", "4718", "4719"]
RUN_ID = 37624523330
ARTIFACT_ID = 11483148487
ARTIFACT_DIGEST = "sha256:291987d9ae9b9dc664c5f5eec89f7319329d9b37b9a00e2e5abfa23dd96b47c8"
RAW_SHA256 = "sha256-555591bdecf81f19d6c015f4b16768f2de795077e73d930b591fe94b51508af8"
STRUCTURAL_ID = "atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-4710-4719"
STRUCTURAL_VERSION = "windows-server-2025-build-26100-security-auditing-4710-4719"

FILTERING_POLICY_URL = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-filtering-platform-policy-change"
EVENT_URL = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-{}"

META = {
    "4710": {
        "title": "IPsec Services was disabled",
        "category": "Policy Change",
        "subcategory": "Audit Filtering Platform Policy Change",
        "event_type": "Success",
        "marker": "S",
        "url": FILTERING_POLICY_URL,
        "source_version": "audit-filtering-platform-policy-change-event-4710-provider-v0",
        "summary": "Records that IPsec Services was disabled. Controlled provider evidence preserves two provider-rendered parameter fields without assigning undocumented meanings to either slot.",
        "requirements": ["Enable Audit Filtering Platform Policy Change success auditing where IPsec service-state visibility is required.", "Preserve param1 and param2 exactly as provider-rendered strings together with host and event context."],
        "interpretation": "Unexpected disablement can remove IPsec policy enforcement or indicate service disruption. The two provider parameters remain opaque unless separately documented by authoritative evidence.",
        "analysis": ["Correlate the transition with service-control, policy-deployment and administrator activity.", "Do not infer meanings for param1 or param2 beyond their provider-rendered values."],
        "correlations": [{"target": "4709", "key": "Computer + time", "purpose": "track the preceding or later IPsec Services start transition"}],
    },
    "4711": {
        "title": "PAStore Engine policy status was reported",
        "category": "Policy Change",
        "subcategory": "Audit Filtering Platform Policy Change",
        "event_type": "Success",
        "marker": "S",
        "url": FILTERING_POLICY_URL,
        "source_version": "audit-filtering-platform-policy-change-event-4711-provider-v0",
        "summary": "Microsoft defines Event 4711 as a success audit that may carry one of several PAStore Engine IPsec policy-status messages. Controlled provider evidence exposes one opaque provider-rendered parameter field.",
        "requirements": ["Enable Audit Filtering Platform Policy Change success auditing where IPsec policy-store status requires visibility.", "Preserve param1 exactly; interpret the rendered message in context without inventing a fixed field contract."],
        "interpretation": "Use the complete provider-rendered message to determine the specific PAStore condition. A single fixed semantic meaning must not be assigned to this multi-message event identity.",
        "analysis": ["Retain the original rendered message and correlate it with nearby IPsec policy and service events.", "Escalate unexpected policy-store conditions only after confirming the exact rendered message and host baseline."],
        "correlations": [{"target": "4712", "key": "Computer + time", "purpose": "associate PAStore status with potentially serious IPsec failures"}],
    },
    "4712": {
        "title": "IPsec Services encountered a potentially serious failure",
        "category": "Policy Change",
        "subcategory": "Audit Filtering Platform Policy Change",
        "event_type": "Failure",
        "marker": "F",
        "url": FILTERING_POLICY_URL,
        "source_version": "audit-filtering-platform-policy-change-event-4712-provider-v0",
        "summary": "Records a potentially serious IPsec Services failure. Controlled provider evidence preserves one provider-rendered parameter field whose detailed semantics are not inferred.",
        "requirements": ["Enable Audit Filtering Platform Policy Change failure auditing where IPsec failure visibility is required.", "Preserve param1 exactly with system, service and surrounding event context."],
        "interpretation": "Treat this event as high-value availability and policy-enforcement failure telemetry. Determine operational and security impact from the rendered message and correlated service state.",
        "analysis": ["Investigate the exact provider-rendered error with service health and relevant system logs.", "Correlate preceding 4709-4711 events and policy deployment changes on the same computer."],
        "correlations": [{"target": "4710", "key": "Computer + time", "purpose": "check whether the serious failure coincided with IPsec disablement"}],
    },
    "4713": {
        "title": "Kerberos policy was changed",
        "category": "Policy Change",
        "subcategory": "Audit Authentication Policy Change",
        "event_type": "Success",
        "marker": "S",
        "url": EVENT_URL.format("4713"),
        "source_version": "event-4713-v0-doc",
        "summary": "Records a Kerberos policy change on a domain controller and includes the provider-rendered policy-change payload plus subject identity.",
        "requirements": ["Collect from domain controllers and monitor all unexpected Kerberos policy changes.", "Preserve subject logon context and KerberosPolicyChange exactly as rendered."],
        "interpretation": "Kerberos policy changes can alter domain authentication behavior, ticket lifetimes and enforcement. Unplanned changes require authorization and Group Policy review.",
        "analysis": ["Compare the rendered policy change with approved domain policy and change records.", "Resolve SubjectLogonId against authentication telemetry and identify the policy delivery path."],
        "correlations": [{"target": "4624", "key": "SubjectLogonId + Computer", "purpose": "resolve the administrative logon context"}],
    },
    "4714": {
        "title": "Encrypted data recovery policy was changed",
        "category": "Policy Change",
        "subcategory": "Audit Other Policy Change Events",
        "event_type": "Success",
        "marker": "S",
        "url": EVENT_URL.format("4714"),
        "source_version": "event-4714-v0-doc-plus-provider-shape",
        "summary": "Records a change to the Encrypting File System Data Recovery Agent certificate or policy. Controlled provider evidence preserves the subject and EfsPolicyChange payload even though older documentation examples may show processing-error output.",
        "requirements": ["Enable Audit Other Policy Change Events success auditing where EFS recovery-policy changes require visibility.", "Preserve EfsPolicyChange and the complete subject context."],
        "interpretation": "An unauthorized Data Recovery Agent or policy change can affect recovery authority and access to encrypted data. Validate every unexpected change against Group Policy administration.",
        "analysis": ["Compare the change with approved EFS Data Recovery Agent policy and certificate lifecycle records.", "Correlate the subject with Group Policy processing and registry-policy changes on the computer."],
        "correlations": [{"target": "4624", "key": "SubjectLogonId + Computer", "purpose": "resolve the initiating logon context"}],
    },
    "4715": {
        "title": "The audit policy (SACL) on an object was changed",
        "category": "Policy Change",
        "subcategory": "Audit Policy Change",
        "event_type": "Success",
        "marker": "S",
        "url": EVENT_URL.format("4715"),
        "source_version": "event-4715-v0-doc",
        "summary": "Records a change to the local audit-policy security descriptor, including the prior and new security descriptors.",
        "requirements": ["Monitor this always-generated audit-policy change on high-value systems.", "Preserve OldSd and NewSd so the security-descriptor delta remains reviewable."],
        "interpretation": "An unplanned SACL policy-descriptor change can reduce or redirect audit coverage. Compare old and new descriptors and determine whether the change was authorized.",
        "analysis": ["Diff OldSd and NewSd using an SDDL-aware parser rather than raw string heuristics alone.", "Resolve the subject and correlate the change with policy-management activity."],
        "correlations": [{"target": "4719", "key": "SubjectLogonId + Computer + time", "purpose": "associate security-descriptor and audit-subcategory changes"}],
    },
    "4716": {
        "title": "Trusted domain information was modified",
        "category": "Policy Change",
        "subcategory": "Audit Authentication Policy Change",
        "event_type": "Success",
        "marker": "S",
        "url": EVENT_URL.format("4716"),
        "source_version": "event-4716-v0-doc",
        "summary": "Records modification of Active Directory trusted-domain information, including domain identity and provider-native trust type, direction, attributes and SID-filtering state.",
        "requirements": ["Collect from domain controllers and monitor every trusted-domain modification.", "Preserve DomainName, DomainSid, TdoType, TdoDirection, TdoAttributes, SidFilteringEnabled and subject context."],
        "interpretation": "Trust changes can alter cross-domain authentication paths and SID-filtering protections. Any unplanned modification is high impact.",
        "analysis": ["Validate trust direction, type, attributes and SID-filtering state against approved forest architecture.", "Review the subject account and compare with trust creation/removal history."],
        "correlations": [{"target": "4706", "key": "DomainSid + DomainName", "purpose": "resolve trust creation history"}, {"target": "4707", "key": "DomainSid + DomainName", "purpose": "track trust removal"}],
    },
    "4717": {
        "title": "System security access was granted to an account",
        "category": "Policy Change",
        "subcategory": "Audit Authentication Policy Change",
        "event_type": "Success",
        "marker": "S",
        "url": EVENT_URL.format("4717"),
        "source_version": "event-4717-v0-doc",
        "summary": "Records assignment of a local logon right to a security principal, one event per affected principal.",
        "requirements": ["Enable Audit Authentication Policy Change success auditing where local logon-right changes require monitoring.", "Preserve TargetSid, AccessGranted and subject context."],
        "interpretation": "Granting interactive, remote, service, batch or network logon rights changes an account's access path. Unexpected grants can enable persistence or lateral movement.",
        "analysis": ["Prioritize high-value systems, restricted rights and unexpected target principals.", "Microsoft notes this is commonly performed by SYSTEM; investigate a different subject unless clearly authorized."],
        "correlations": [{"target": "4718", "key": "TargetSid + access right + Computer", "purpose": "track later removal of the granted logon right"}],
    },
    "4718": {
        "title": "System security access was removed from an account",
        "category": "Policy Change",
        "subcategory": "Audit Authentication Policy Change",
        "event_type": "Success",
        "marker": "S",
        "url": EVENT_URL.format("4718"),
        "source_version": "event-4718-v0-doc",
        "summary": "Records removal of a local logon right from a security principal, one event per affected principal.",
        "requirements": ["Enable Audit Authentication Policy Change success auditing where local logon-right changes require monitoring.", "Preserve TargetSid, AccessRemoved and subject context."],
        "interpretation": "Removal may be legitimate hardening, but an unexpected change can disrupt service operation or conceal prior unauthorized grants.",
        "analysis": ["Validate the removed right and target account against approved policy and service dependencies.", "Microsoft notes this is commonly performed by SYSTEM; investigate an unusual subject and correlate with prior 4717 events."],
        "correlations": [{"target": "4717", "key": "TargetSid + access right + Computer", "purpose": "identify the earlier grant of the removed logon right"}],
    },
    "4719": {
        "title": "System audit policy was changed",
        "category": "Policy Change",
        "subcategory": "Audit Policy Change",
        "event_type": "Success",
        "marker": "S",
        "url": EVENT_URL.format("4719"),
        "source_version": "event-4719-v0-doc-plus-provider-v1",
        "summary": "Records a local audit-policy subcategory change. Controlled provider evidence preserves Version 0 and Version 1; Version 1 adds ClientProcessId and ClientProcessStartKey.",
        "requirements": ["Monitor every event because it is logged regardless of the Audit Policy Change subcategory setting.", "Preserve category/subcategory identifiers, AuditPolicyChanges and exact event version; retain Version 1 client-process fields."],
        "interpretation": "Audit-policy changes can add or remove success/failure collection and directly affect detection visibility. Every unplanned change on a high-value system requires investigation.",
        "analysis": ["Translate CategoryId, SubcategoryId and SubcategoryGuid using authoritative audit-policy mappings and inspect AuditPolicyChanges.", "For Version 1, correlate ClientProcessId and ClientProcessStartKey with process telemetry."],
        "correlations": [{"target": "4715", "key": "SubjectLogonId + Computer + time", "purpose": "associate audit-policy and policy-security-descriptor changes"}, {"target": "4688", "key": "ClientProcessId + Computer + time", "purpose": "resolve the Version 1 client process"}],
    },
}

EXTRA_FIELD_DETAILS = {
    "param1": ("Provider Message", "parameter-1", "Opaque provider-rendered parameter; event-specific meaning is not inferred without authoritative documentation."),
    "param2": ("Provider Message", "parameter-2", "Opaque provider-rendered parameter; event-specific meaning is not inferred without authoritative documentation."),
    "KerberosPolicyChange": ("Kerberos Policy", "kerberos-policy-change", "Provider-rendered Kerberos policy-change detail."),
    "EfsPolicyChange": ("EFS Recovery Policy", "efs-policy-change", "Provider-rendered Encrypting File System recovery-policy change detail."),
    "OldSd": ("Audit Policy Security Descriptor", "old-security-descriptor", "Security descriptor before the audit-policy SACL change."),
    "NewSd": ("Audit Policy Security Descriptor", "new-security-descriptor", "Security descriptor after the audit-policy SACL change."),
    "AccessGranted": ("Logon Right", "access-granted", "Local logon right granted to the target principal."),
    "AccessRemoved": ("Logon Right", "access-removed", "Local logon right removed from the target principal."),
    "CategoryId": ("Audit Policy Change", "category-id", "Provider-rendered audit category identifier."),
    "SubcategoryId": ("Audit Policy Change", "subcategory-id", "Provider-rendered audit subcategory identifier."),
    "SubcategoryGuid": ("Audit Policy Change", "subcategory-guid", "GUID of the audit-policy subcategory that changed."),
    "AuditPolicyChanges": ("Audit Policy Change", "audit-policy-changes", "Provider-rendered success/failure audit-policy changes."),
}


def load_previous():
    text = subprocess.check_output(["git", "show", f"{PREVIOUS_COMMIT}:{PREVIOUS_PATH}"], text=True, encoding="utf-8")
    tmp = Path(tempfile.mkdtemp()) / "batch07_impl.py"
    tmp.write_text(text, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("batch07_impl", tmp)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load historical Batch 07 helper")
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
    mod.EXTRA_FIELD_DETAILS = EXTRA_FIELD_DETAILS
    return mod


def raw_discovery():
    path = Path(os.environ["ATLAS_DISCOVERY_JSON"])
    blob = path.read_bytes()
    assert "sha256-" + hashlib.sha256(blob).hexdigest() == RAW_SHA256
    data = json.loads(blob)
    assert data["provider"] == "Microsoft-Windows-Security-Auditing"
    assert data["channel_scope"] == "Security"
    assert data["unique_event_id_count"] == 10
    assert data["event_version_definition_count"] == 11
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
    expected_versions = {eid: [0] for eid in IDS}
    expected_versions["4719"] = [0, 1]
    expected_counts = {
        "4710": {0: 2}, "4711": {0: 1}, "4712": {0: 1}, "4713": {0: 5}, "4714": {0: 5},
        "4715": {0: 6}, "4716": {0: 10}, "4717": {0: 6}, "4718": {0: 6}, "4719": {0: 8, 1: 10},
    }
    assert {eid: [r["version"] for r in rows] for eid, rows in result.items()} == expected_versions
    assert {eid: {r["version"]: len(r["fields"]) for r in rows} for eid, rows in result.items()} == expected_counts
    assert [f[0] for f in result["4710"][0]["fields"]] == ["param1", "param2"]
    assert [f[0] for f in result["4711"][0]["fields"]] == ["param1"]
    assert [f[0] for f in result["4712"][0]["fields"]] == ["param1"]
    byv = {r["version"]: [f[0] for f in r["fields"]] for r in result["4719"]}
    assert byv[1] == byv[0] + ["ClientProcessId", "ClientProcessStartKey"]
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
                "fields": [{"name": n, "in_type": i, "out_type": o} for n, i, o in shape["fields"]],
            })
        identities.append({"event_id": eid, "versions": versions})
    doc = {
        "ingestion_contract_version": "1.0.0",
        "inventory_contract_version": "1.0.0",
        "inventory_id": "atlas:inventory:atlas.ingestion:windows-security-auditing-4710-4719-26100",
        "inventory_kind": "telemetry",
        "declared_scope": "Microsoft-Windows-Security-Auditing provider Event IDs 4710 through 4719 linked to Security on controlled Windows Server 2025 Datacenter build 26100",
        "source_ids": [STRUCTURAL_ID],
        "inventory_method": "provider-runtime-metadata",
        "inventory_source_version": STRUCTURAL_VERSION,
        "expected_identity_count": 10,
        "identity_dimensions": ["provider", "channel", "native-id", "product", "platform", "version"],
        "scope_metadata": {
            "provider": "Microsoft-Windows-Security-Auditing", "channel": "Security",
            "product": "Windows Server 2025 Datacenter", "platform": "Windows", "windows_build": "26100", "architecture": "64-bit",
            "workflow_run_id": RUN_ID, "artifact_id": ARTIFACT_ID, "artifact_digest": ARTIFACT_DIGEST, "raw_artifact_sha256": RAW_SHA256,
            "provider_event_version_definition_count": 11, "provider_unique_event_id_count": 10, "expected_identities": identities,
            "completeness_semantics": "bounded structural evidence for ten identities already inside the separately frozen 423-ID provider denominator; eleven version definitions are preserved and do not alter that denominator",
        },
        "guardrails": {"max_unexplained_shrink_percent": 0, "max_unexplained_growth_percent": 0},
    }
    doc["digest"] = base.digest_without_field(doc)
    return doc


def write_sources(base):
    source_dir = ROOT / "content/encyclopedia/sources"
    provider = base.source_record(
        STRUCTURAL_ID,
        "microsoft-windows-security-auditing-provider-26100-4710-4719",
        "Microsoft-Windows-Security-Auditing Security Provider Metadata — Windows Server 2025 build 26100 — bounded Event IDs 4710–4719 batch",
        ["https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log"],
        change={"strategy": "checksum", "notes": f"Bound to workflow {RUN_ID}, artifact {ARTIFACT_ID}, artifact digest {ARTIFACT_DIGEST}, raw JSON {RAW_SHA256}, and normalized inventory."},
    )
    base.dump(source_dir / "microsoft-windows-security-auditing-provider-26100-4710-4719.json", provider)
    appendix = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/Appendix-L--Events-to-Monitor"
    for eid in IDS:
        meta = META[eid]
        base.dump(source_dir / f"microsoft-windows-security-event-{eid}.json", base.source_record(
            f"atlas:source:atlas.source:microsoft-windows-security-event-{eid}", f"microsoft-windows-security-event-{eid}",
            f"Microsoft Windows Security Auditing Event {eid} Documentation", [meta["url"], appendix],
            change={"strategy": "content-diff", "notes": "Microsoft event/audit-policy material is semantic authority; controlled provider evidence is structural authority for exact version and field shape."},
        ))
        base.dump(source_dir / f"ultimate-windows-security-event-{eid}.json", base.source_record(
            f"atlas:source:atlas.source:ultimate-windows-security-event-{eid}", f"ultimate-windows-security-event-{eid}",
            f"Ultimate Windows Security — Windows Security Log Event ID {eid}",
            [f"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={eid}"], secondary=True,
            change={"strategy": "manual", "notes": "Coverage / Quick Detail benchmark only. No automated or bulk ingestion is authorized."},
        ))


def update_coverage(base):
    path = ROOT / "content/encyclopedia/coverage-manifest.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    b = data["windows_security_log_review_benchmark"]
    assert (b["listed_unique_event_id_count"], b["encyclopedia_grade_listed_id_count"], b["remaining_listed_id_count"], b["completion_ratio"]) == (422, 76, 346, "76/422")
    covered = sorted(set(b["covered_event_ids"]) | set(IDS), key=int)
    assert len(covered) == 86
    b.update({"covered_event_ids": covered, "encyclopedia_grade_listed_id_count": 86, "remaining_listed_id_count": 336, "completion_ratio": "86/422", "completion_percent": 20.38})
    fam = next(x for x in data["families"] if x["id"] == "windows-security-auditing")
    assert (fam["denominator_count"], fam["encyclopedia_grade_count"], fam["remaining_count"]) == (423, 70, 353)
    fam.update({"encyclopedia_grade_count": 80, "remaining_count": 343})
    base.dump(path, data)


def rebuild_snapshot():
    path = ROOT / "tools/content/build_windows_security_coverage_snapshot.py"
    spec = importlib.util.spec_from_file_location("coverage_builder", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load coverage snapshot builder")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    snap = mod.build_snapshot()
    assert (snap["denominator_count"], snap["encyclopedia_grade_count"], snap["remaining_count"], snap["completion_ratio"], snap["completion_percent"]) == (423, 80, 343, "80/423", 18.91)
    (ROOT / "content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json").write_text(json.dumps(snap, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def update_tests():
    path = ROOT / "tests/phase51010/test_windows_security_coverage_snapshot.py"
    text = path.read_text(encoding="utf-8")
    assert text.count('snapshot["encyclopedia_grade_count"] == 70') == 2
    assert text.count('snapshot["remaining_count"] == 353') == 1
    assert text.count('snapshot["completion_ratio"] == "70/423"') == 1
    assert text.count('snapshot["completion_percent"] == 16.55') == 1
    text = text.replace('snapshot["encyclopedia_grade_count"] == 70', 'snapshot["encyclopedia_grade_count"] == 80')
    text = text.replace('snapshot["remaining_count"] == 353', 'snapshot["remaining_count"] == 343')
    text = text.replace('snapshot["completion_ratio"] == "70/423"', 'snapshot["completion_ratio"] == "80/423"')
    text = text.replace('snapshot["completion_percent"] == 16.55', 'snapshot["completion_percent"] == 18.91')
    path.write_text(text, encoding="utf-8")

    path = ROOT / "tests/phase51010/test_windows_security_auditing_4699_4709.py"
    text = path.read_text(encoding="utf-8")
    old = 'assert (b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(76,346,"76/422",18.01); assert set(IDS).issubset(set(b["covered_event_ids"])); w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert (w["denominator_count"],w["encyclopedia_grade_count"],w["remaining_count"])==(423,70,353)'
    new = 'assert b["listed_unique_event_id_count"]==422 and set(IDS).issubset(set(b["covered_event_ids"])) and b["encyclopedia_grade_listed_id_count"]>=76; w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert w["denominator_count"]==423 and w["encyclopedia_grade_count"]>=70 and w["remaining_count"]==423-w["encyclopedia_grade_count"]'
    assert text.count(old) == 1
    path.write_text(text.replace(old, new), encoding="utf-8")


def write_batch_test(shapes):
    expected = {eid: {str(row["version"]): len(row["fields"]) for row in shapes[eid]} for eid in IDS}
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
 assert EXPECTED["4710"]=={{"0":2}} and EXPECTED["4711"]=={{"0":1}} and EXPECTED["4712"]=={{"0":1}}
 assert EXPECTED["4719"]=={{"0":8,"1":10}}
def test_04_semantics_and_opaque_parameters():
 d=bp(); assert d["4712"]["overview"]["event_type"]=="Failure"
 assert d["4714"]["overview"]["subcategory"]=="Audit Other Policy Change Events"
 assert d["4716"]["overview"]["subcategory"]=="Audit Authentication Policy Change"
 assert d["4719"]["overview"]["subcategory"]=="Audit Policy Change"
 for eid in ("4710","4711","4712"):
  details=" ".join(x["meaning"] for x in d[eid]["fields"] if x["native_name"].startswith("param")); assert "opaque" in details.lower()
def test_05_evidence_and_redistribution():
 data={{x["id"]:x for x in records()}}
 for eid in IDS:
  cs=[x for x in data.values() if x.get("record_kind")=="claim" and x.get("subject_id")==f"atlas:event:microsoft.windows.security:{{eid}}" and x.get("predicate")=="telemetry.represents"]; assert len(cs)==1 and STRUCTURAL in {{e["source_id"] for e in cs[0]["evidence"]}}; assert data[f"atlas:source:atlas.source:ultimate-windows-security-event-{{eid}}"]["redistribution"]["policy"]=="prohibited"
def test_06_coverage():
 m=json.loads((ROOT/"content/encyclopedia/coverage-manifest.json").read_text()); b=m["windows_security_log_review_benchmark"]; assert (b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(86,336,"86/422",20.38); assert set(IDS).issubset(set(b["covered_event_ids"])); w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert (w["denominator_count"],w["encyclopedia_grade_count"],w["remaining_count"])==(423,80,343)
def test_07_discovery_binding():
 x=json.loads((ROOT/"ingestion/inventories/windows-security-auditing-4710-4719-26100.telemetry.json").read_text()); s=x["scope_metadata"]; assert (s["workflow_run_id"],s["artifact_id"],s["provider_event_version_definition_count"],s["provider_unique_event_id_count"])==({RUN_ID},{ARTIFACT_ID},11,10); assert s["artifact_digest"]=={ARTIFACT_DIGEST!r} and s["raw_artifact_sha256"]=={RAW_SHA256!r}
'''
    (ROOT / "tests/phase51010/test_windows_security_auditing_4710_4719.py").write_text(text, encoding="utf-8")


def update_docs(base):
    path = ROOT / "docs/windows-security-log-scope.md"
    text = path.read_text(encoding="utf-8")
    replacements = {
        "Current controlled progress after the seventh bounded Windows Security Log batch:": "Current controlled progress after the eighth bounded Windows Security Log batch:",
        "- Windows Security Log UWS review benchmark: `76/422` listed identities encyclopedia-grade (`18.01%`), `346` remaining;": "- Windows Security Log UWS review benchmark: `86/422` listed identities encyclopedia-grade (`20.38%`), `336` remaining;",
        "- newly promoted Security-Auditing IDs in this batch: `4699`, `4700`, `4701`, `4702`, `4703`, `4704`, `4705`, `4706`, `4707`, `4709`;": "- newly promoted Security-Auditing IDs in this batch: `4710`, `4711`, `4712`, `4713`, `4714`, `4715`, `4716`, `4717`, `4718`, `4719`;",
        "- Windows Security Auditing provider coverage: `70/423` encyclopedia-grade with `353` provider-specific identities remaining;": "- Windows Security Auditing provider coverage: `80/423` encyclopedia-grade with `343` provider-specific identities remaining;",
    }
    for old, new in replacements.items():
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")

    path = ROOT / "docs/releases/third-party-redistribution-inventory.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    row = next(x for x in data["entries"] if x["id"] == "microsoft-windows-security-documentation")
    additions = [*[f"content/encyclopedia/sources/microsoft-windows-security-event-{eid}.json" for eid in IDS], "ingestion/inventories/windows-security-auditing-4710-4719-26100.telemetry.json", "content/encyclopedia/sources/microsoft-windows-security-auditing-provider-26100-4710-4719.json"]
    parts = [x.strip() for x in row.get("review_evidence", "").split(" + ") if x.strip()]
    for item in additions:
        if item not in parts:
            parts.append(item)
    row["review_evidence"] = " + ".join(parts)
    base.dump(path, data)


def main():
    previous = load_previous()
    batch06 = previous.load_impl()
    base = batch06.load_base()
    batch06.configure_base(base)
    discovery = raw_discovery()
    shapes = provider_shapes(discovery)
    inventory = build_inventory(base, shapes)
    base.dump(ROOT / "ingestion/inventories/windows-security-auditing-4710-4719-26100.telemetry.json", inventory)
    write_sources(base)
    base.update_blueprint(shapes)
    update_coverage(base)
    rebuild_snapshot()
    update_tests()
    write_batch_test(shapes)
    update_docs(base)
    print("batch_ids=" + ",".join(IDS))
    print("inventory_digest=" + inventory["digest"])
    print("coverage=86/422")
    print("security_auditing=80/423")


if __name__ == "__main__":
    main()
