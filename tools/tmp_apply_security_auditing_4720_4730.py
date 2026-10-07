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
PREVIOUS_COMMIT = "9ecd3c058592dfd5b6dc652018ac0873cce43aee"
PREVIOUS_PATH = "tools/tmp_apply_security_auditing_4710_4719.py"
NOW = "2026-10-07T13:30:00Z"
IDS = ["4720", "4722", "4723", "4724", "4725", "4726", "4727", "4728", "4729", "4730"]
RUN_ID = 37628383060
ARTIFACT_ID = 11484872075
ARTIFACT_DIGEST = "sha256:3392082db05683036a210341decced6439940f89be9891ee65082ad51011a48e"
RAW_SHA256 = "sha256-52a8b607bc78e3fdc2f93f49d7f2b665211e130a744ddbfa798d6811b7f0a5ad"
STRUCTURAL_ID = "atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-4720-4730"
STRUCTURAL_VERSION = "windows-server-2025-build-26100-security-auditing-4720-4730"
EVENT_URL = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-{}"


def meta(title, subcategory, event_type, marker, summary, requirements, interpretation, analysis, correlations, source_version):
    return {
        "title": title, "category": "Account Management", "subcategory": subcategory,
        "event_type": event_type, "marker": marker, "summary": summary,
        "requirements": requirements, "interpretation": interpretation,
        "analysis": analysis, "correlations": correlations, "source_version": source_version,
    }


META = {
    "4720": meta(
        "A user account was created", "Audit User Account Management", "Success", "S",
        "Records creation of a local or domain user account and preserves the initial account attributes and user-account-control state exposed by the provider.",
        ["Enable Audit User Account Management success auditing on systems where account lifecycle visibility is required.", "Preserve target identity, account attributes, UAC values, delegation targets, SID history and subject context."],
        "Unexpected account creation is a high-value persistence and privilege-establishment signal, especially on domain controllers and critical local systems.",
        ["Validate the target account, creator and attributes against an approved identity lifecycle request.", "Review UAC, delegation, SID history, logon hours and workstation restrictions for anomalous settings."],
        [{"target": "4722", "key": "TargetSid + Computer", "purpose": "track later account enablement"}, {"target": "4726", "key": "TargetSid + Computer", "purpose": "track later account deletion"}],
        "event-4720-v0-doc",
    ),
    "4722": meta(
        "A user account was enabled", "Audit User Account Management", "Success", "S",
        "Records enablement of a user or computer object and identifies the target and initiating subject.",
        ["Enable Audit User Account Management success auditing.", "Preserve TargetSid and complete subject logon context."],
        "Enabling dormant, disabled or sensitive accounts can restore access and should match approved administration.",
        ["Prioritize high-value, service, dormant and local accounts.", "Correlate SubjectLogonId and confirm whether the enabled object is a user or computer account."],
        [{"target": "4725", "key": "TargetSid + Computer", "purpose": "track disable/enable transitions"}, {"target": "4624", "key": "SubjectLogonId + Computer", "purpose": "resolve the administrator session"}],
        "event-4722-v0-doc",
    ),
    "4723": meta(
        "An attempt was made to change an account's password", "Audit User Account Management", "Success/Failure", "S, F",
        "Records an account password-change attempt, normally initiated by the same account, and includes target, subject and privilege context.",
        ["Enable Audit User Account Management success and failure auditing where password-change attempts require visibility.", "Preserve target/subject identity, SubjectLogonId and PrivilegeList."],
        "Failures can indicate password-policy rejection or invalid current credentials; repeated attempts against valuable accounts warrant investigation.",
        ["Confirm whether subject and target are expected to match and review password-policy outcomes.", "Correlate domain failures with 4771 or 4776 where available."],
        [{"target": "4771", "key": "TargetUserName + time", "purpose": "resolve Kerberos pre-authentication failure"}, {"target": "4776", "key": "TargetUserName + time", "purpose": "resolve credential validation failure"}],
        "event-4723-v0-doc",
    ),
    "4724": meta(
        "An attempt was made to reset an account's password", "Audit User Account Management", "Success/Failure", "S, F",
        "Records an attempt by one account to reset another user or computer account password.",
        ["Enable Audit User Account Management success and failure auditing.", "Preserve target identity and complete subject logon context."],
        "Password resets can be routine help-desk or administrative actions, but unauthorized resets enable account takeover and persistence.",
        ["Validate the reset against an approved request and administrator role.", "Prioritize privileged, service and break-glass targets and investigate policy failures."],
        [{"target": "4624", "key": "SubjectLogonId + Computer", "purpose": "resolve the resetting administrator session"}],
        "event-4724-v0-doc",
    ),
    "4725": meta(
        "A user account was disabled", "Audit User Account Management", "Success", "S",
        "Records disablement of a user or computer object and identifies the target and initiating subject.",
        ["Enable Audit User Account Management success auditing.", "Preserve TargetSid and complete subject logon context."],
        "Disablement may be legitimate containment or lifecycle management, but unexpected changes can disrupt critical services or privileged access.",
        ["Validate the action against incident response, offboarding or change records.", "Prioritize service, privileged and high-value accounts that should not be disabled unexpectedly."],
        [{"target": "4722", "key": "TargetSid + Computer", "purpose": "track later re-enablement"}],
        "event-4725-v0-doc",
    ),
    "4726": meta(
        "A user account was deleted", "Audit User Account Management", "Success", "S",
        "Records deletion of a user object and preserves target, subject and privilege context.",
        ["Enable Audit User Account Management success auditing.", "Preserve target identity, PrivilegeList and subject logon context."],
        "Unexpected account deletion can remove access, disrupt services or destroy identity evidence after unauthorized activity.",
        ["Confirm approved deprovisioning and preserve directory/history evidence before cleanup.", "Correlate the subject with authentication and earlier account lifecycle events."],
        [{"target": "4720", "key": "TargetSid + TargetUserName", "purpose": "resolve original account creation"}],
        "event-4726-v0-doc",
    ),
    "4727": meta(
        "A security-enabled global group was created", "Audit Security Group Management", "Success", "S",
        "Records creation of an Active Directory security-enabled global group, including group identity, SAM name and SID history.",
        ["Enable Audit Security Group Management success auditing on domain controllers.", "Preserve TargetSid, SamAccountName, SidHistory, PrivilegeList and subject context."],
        "New global security groups can establish new authorization structures; unexpected groups or SID history require investigation.",
        ["Validate the group name, scope and owner against approved access design.", "Inspect SID history and subsequent membership changes."],
        [{"target": "4728", "key": "TargetSid + Computer", "purpose": "track member additions"}, {"target": "4730", "key": "TargetSid + Computer", "purpose": "track group deletion"}],
        "event-4727-v0-doc",
    ),
    "4728": meta(
        "A member was added to a security-enabled global group", "Audit Security Group Management", "Success", "S",
        "Records addition of a member to an Active Directory security-enabled global group. Version 1 adds MembershipExpirationTime for time-bounded membership.",
        ["Enable Audit Security Group Management success auditing on domain controllers.", "Preserve member, group, subject and exact event version; retain MembershipExpirationTime when Version 1 is emitted."],
        "Membership additions can grant broad domain authorization. Temporary membership must retain its expiration evidence rather than being flattened into Version 0.",
        ["Prioritize privileged or high-value global groups and unexpected member SIDs.", "For Version 1, validate MembershipExpirationTime against the approved just-in-time access window."],
        [{"target": "4729", "key": "MemberSid + TargetSid + Computer", "purpose": "track later membership removal"}],
        "event-4728-v0-doc-plus-provider-v1",
    ),
    "4729": meta(
        "A member was removed from a security-enabled global group", "Audit Security Group Management", "Success", "S",
        "Records removal of a member from an Active Directory security-enabled global group.",
        ["Enable Audit Security Group Management success auditing on domain controllers.", "Preserve member, group, subject and privilege context."],
        "Removal may be expected deprovisioning or containment, but unexpected changes to privileged groups can disrupt administration or conceal prior access.",
        ["Validate the removal against access reviews, incidents and lifecycle records.", "Correlate with the earlier 4728 addition for the same member/group pair."],
        [{"target": "4728", "key": "MemberSid + TargetSid + Computer", "purpose": "resolve membership grant history"}],
        "event-4729-v0-doc",
    ),
    "4730": meta(
        "A security-enabled global group was deleted", "Audit Security Group Management", "Success", "S",
        "Records deletion of an Active Directory security-enabled global group.",
        ["Enable Audit Security Group Management success auditing on domain controllers.", "Preserve group target identity, PrivilegeList and subject context."],
        "Unexpected deletion can remove authorization, disrupt dependent resources and erase group structure used during an intrusion.",
        ["Confirm approved group retirement and identify affected resources and memberships.", "Correlate with group creation and membership history before deletion."],
        [{"target": "4727", "key": "TargetSid + TargetUserName", "purpose": "resolve original group creation"}],
        "event-4730-v0-doc",
    ),
}

for event_id, item in META.items():
    item["url"] = EVENT_URL.format(event_id)

EXTRA_FIELD_DETAILS = {
    "TargetUserName": ("Target Account", "target-user-name", "Name of the target user, computer or group object."),
    "TargetDomainName": ("Target Account", "target-domain-name", "Domain or computer context for the target object."),
    "TargetSid": ("Target Account", "target-sid", "SID of the target user, computer or group object."),
    "PrivilegeList": ("Additional Information", "privilege-list", "Provider-rendered privileges used during the operation; may be empty or a dash."),
    "SamAccountName": ("Account Attributes", "sam-account-name", "Pre-Windows 2000 logon name or SAM-compatible name."),
    "DisplayName": ("Account Attributes", "display-name", "Display name assigned to the created account."),
    "UserPrincipalName": ("Account Attributes", "user-principal-name", "User principal name assigned to the account."),
    "HomeDirectory": ("Account Attributes", "home-directory", "Configured home directory."),
    "HomePath": ("Account Attributes", "home-path", "Configured home drive/path attribute."),
    "ScriptPath": ("Account Attributes", "script-path", "Configured logon script path."),
    "ProfilePath": ("Account Attributes", "profile-path", "Configured user profile path."),
    "UserWorkstations": ("Account Attributes", "user-workstations", "Provider-rendered workstation restrictions."),
    "PasswordLastSet": ("Account Attributes", "password-last-set", "Provider-rendered password-last-set state."),
    "AccountExpires": ("Account Attributes", "account-expires", "Provider-rendered account expiration state."),
    "PrimaryGroupId": ("Account Attributes", "primary-group-id", "Relative identifier of the account primary group."),
    "AllowedToDelegateTo": ("Account Attributes", "allowed-to-delegate-to", "Services to which the account is allowed to delegate credentials."),
    "OldUacValue": ("User Account Control", "old-uac-value", "Previous provider-native userAccountControl value."),
    "NewUacValue": ("User Account Control", "new-uac-value", "New provider-native userAccountControl value."),
    "UserAccountControl": ("User Account Control", "user-account-control", "Provider-rendered user-account-control flags."),
    "UserParameters": ("Account Attributes", "user-parameters", "Provider-rendered user parameters attribute."),
    "SidHistory": ("Account Attributes", "sid-history", "Provider-rendered SID history associated with the object."),
    "LogonHours": ("Account Attributes", "logon-hours", "Provider-rendered allowed logon hours."),
    "MemberName": ("Member", "member-name", "Distinguished name or provider-rendered name of the affected group member."),
    "MemberSid": ("Member", "member-sid", "SID of the affected group member."),
    "MembershipExpirationTime": ("Member", "membership-expiration-time", "Expiration time for the Version 1 time-bounded group membership."),
}


def load_previous():
    text = subprocess.check_output(["git", "show", f"{PREVIOUS_COMMIT}:{PREVIOUS_PATH}"], text=True, encoding="utf-8")
    tmp = Path(tempfile.mkdtemp()) / "batch08_impl.py"
    tmp.write_text(text, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("batch08_impl", tmp)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load historical Batch 08 helper")
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    for name, value in {
        "ROOT": ROOT, "NOW": NOW, "IDS": IDS, "RUN_ID": RUN_ID, "ARTIFACT_ID": ARTIFACT_ID,
        "ARTIFACT_DIGEST": ARTIFACT_DIGEST, "RAW_SHA256": RAW_SHA256, "STRUCTURAL_ID": STRUCTURAL_ID,
        "STRUCTURAL_VERSION": STRUCTURAL_VERSION, "META": META, "EXTRA_FIELD_DETAILS": EXTRA_FIELD_DETAILS,
    }.items():
        setattr(mod, name, value)
    return mod


def raw_discovery():
    path = Path(os.environ["ATLAS_DISCOVERY_JSON"]); blob = path.read_bytes()
    assert "sha256-" + hashlib.sha256(blob).hexdigest() == RAW_SHA256
    data = json.loads(blob)
    assert data["provider"] == "Microsoft-Windows-Security-Auditing" and data["channel_scope"] == "Security"
    assert data["unique_event_id_count"] == 10 and data["event_version_definition_count"] == 11
    assert [str(x) for x in data["requested_ids"]] == IDS
    return data


def provider_shapes(data):
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events"}; result = {eid: [] for eid in IDS}
    for event in data["events"]:
        root = ET.fromstring(event["template"])
        fields = [(x.attrib["name"], x.attrib.get("inType"), x.attrib.get("outType")) for x in root.findall("e:data", ns)]
        result[str(event["id"])].append({"version": int(event["version"]), "level": event["level"], "fields": fields})
    versions = {eid: [0] for eid in IDS}; versions["4728"] = [0, 1]
    counts = {"4720": {0: 26}, "4722": {0: 7}, "4723": {0: 8}, "4724": {0: 7}, "4725": {0: 7}, "4726": {0: 8}, "4727": {0: 10}, "4728": {0: 10, 1: 11}, "4729": {0: 10}, "4730": {0: 8}}
    assert {eid: [r["version"] for r in rows] for eid, rows in result.items()} == versions
    assert {eid: {r["version"]: len(r["fields"]) for r in rows} for eid, rows in result.items()} == counts
    byv = {r["version"]: [f[0] for f in r["fields"]] for r in result["4728"]}
    assert byv[1] == byv[0] + ["MembershipExpirationTime"]
    return result


def build_inventory(base, shapes):
    identities = [{"event_id": eid, "versions": [{"version": r["version"], "field_count": len(r["fields"]), "level": r["level"], "fields": [{"name": n, "in_type": i, "out_type": o} for n, i, o in r["fields"]]} for r in shapes[eid]]} for eid in IDS]
    doc = {
        "ingestion_contract_version": "1.0.0", "inventory_contract_version": "1.0.0",
        "inventory_id": "atlas:inventory:atlas.ingestion:windows-security-auditing-4720-4730-26100", "inventory_kind": "telemetry",
        "declared_scope": "Microsoft-Windows-Security-Auditing provider Event IDs 4720, 4722-4730 linked to Security on controlled Windows Server 2025 Datacenter build 26100",
        "source_ids": [STRUCTURAL_ID], "inventory_method": "provider-runtime-metadata", "inventory_source_version": STRUCTURAL_VERSION,
        "expected_identity_count": 10, "identity_dimensions": ["provider", "channel", "native-id", "product", "platform", "version"],
        "scope_metadata": {
            "provider": "Microsoft-Windows-Security-Auditing", "channel": "Security", "product": "Windows Server 2025 Datacenter", "platform": "Windows", "windows_build": "26100", "architecture": "64-bit",
            "workflow_run_id": RUN_ID, "artifact_id": ARTIFACT_ID, "artifact_digest": ARTIFACT_DIGEST, "raw_artifact_sha256": RAW_SHA256,
            "provider_event_version_definition_count": 11, "provider_unique_event_id_count": 10, "expected_identities": identities,
            "completeness_semantics": "bounded structural evidence for ten identities already inside the separately frozen 423-ID provider denominator; eleven version definitions are preserved and do not alter that denominator",
        },
        "guardrails": {"max_unexplained_shrink_percent": 0, "max_unexplained_growth_percent": 0},
    }
    doc["digest"] = base.digest_without_field(doc); return doc


def write_sources(base):
    source_dir = ROOT / "content/encyclopedia/sources"
    base.dump(source_dir / "microsoft-windows-security-auditing-provider-26100-4720-4730.json", base.source_record(
        STRUCTURAL_ID, "microsoft-windows-security-auditing-provider-26100-4720-4730",
        "Microsoft-Windows-Security-Auditing Security Provider Metadata — Windows Server 2025 build 26100 — bounded Event IDs 4720–4730 batch",
        ["https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log"],
        change={"strategy": "checksum", "notes": f"Bound to workflow {RUN_ID}, artifact {ARTIFACT_ID}, artifact digest {ARTIFACT_DIGEST}, raw JSON {RAW_SHA256}, and normalized inventory."},
    ))
    appendix = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/Appendix-L--Events-to-Monitor"
    for eid in IDS:
        base.dump(source_dir / f"microsoft-windows-security-event-{eid}.json", base.source_record(
            f"atlas:source:atlas.source:microsoft-windows-security-event-{eid}", f"microsoft-windows-security-event-{eid}", f"Microsoft Windows Security Auditing Event {eid} Documentation", [META[eid]["url"], appendix],
            change={"strategy": "content-diff", "notes": "Microsoft event/audit-policy material is semantic authority; controlled provider evidence is structural authority for exact version and field shape."},
        ))
        base.dump(source_dir / f"ultimate-windows-security-event-{eid}.json", base.source_record(
            f"atlas:source:atlas.source:ultimate-windows-security-event-{eid}", f"ultimate-windows-security-event-{eid}", f"Ultimate Windows Security — Windows Security Log Event ID {eid}",
            [f"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={eid}"], secondary=True,
            change={"strategy": "manual", "notes": "Coverage / Quick Detail benchmark only. No automated or bulk ingestion is authorized."},
        ))


def update_coverage(base):
    path = ROOT / "content/encyclopedia/coverage-manifest.json"; data = json.loads(path.read_text(encoding="utf-8")); b = data["windows_security_log_review_benchmark"]
    assert (b["listed_unique_event_id_count"], b["encyclopedia_grade_listed_id_count"], b["remaining_listed_id_count"], b["completion_ratio"]) == (422, 86, 336, "86/422")
    covered = sorted(set(b["covered_event_ids"]) | set(IDS), key=int); assert len(covered) == 96
    b.update({"covered_event_ids": covered, "encyclopedia_grade_listed_id_count": 96, "remaining_listed_id_count": 326, "completion_ratio": "96/422", "completion_percent": 22.75})
    fam = next(x for x in data["families"] if x["id"] == "windows-security-auditing"); assert (fam["denominator_count"], fam["encyclopedia_grade_count"], fam["remaining_count"]) == (423, 80, 343)
    fam.update({"encyclopedia_grade_count": 90, "remaining_count": 333}); base.dump(path, data)


def rebuild_snapshot():
    spec = importlib.util.spec_from_file_location("coverage_builder", ROOT / "tools/content/build_windows_security_coverage_snapshot.py"); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    snap = mod.build_snapshot(); assert (snap["denominator_count"], snap["encyclopedia_grade_count"], snap["remaining_count"], snap["completion_ratio"], snap["completion_percent"]) == (423, 90, 333, "90/423", 21.28)
    (ROOT / "content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json").write_text(json.dumps(snap, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def update_tests():
    path = ROOT / "tests/phase51010/test_windows_security_coverage_snapshot.py"; text = path.read_text(encoding="utf-8")
    for old, new in [('== 80', '== 90'), ('== 343', '== 333'), ('== "80/423"', '== "90/423"'), ('== 18.91', '== 21.28')]:
        assert old in text; text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")
    path = ROOT / "tests/phase51010/test_windows_security_auditing_4710_4719.py"; text = path.read_text(encoding="utf-8")
    old = 'assert (b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(86,336,"86/422",20.38); assert set(IDS).issubset(set(b["covered_event_ids"])); w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert (w["denominator_count"],w["encyclopedia_grade_count"],w["remaining_count"])==(423,80,343)'
    new = 'assert b["listed_unique_event_id_count"]==422 and set(IDS).issubset(set(b["covered_event_ids"])) and b["encyclopedia_grade_listed_id_count"]>=86; w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert w["denominator_count"]==423 and w["encyclopedia_grade_count"]>=80 and w["remaining_count"]==423-w["encyclopedia_grade_count"]'
    assert text.count(old) == 1; path.write_text(text.replace(old, new), encoding="utf-8")


def write_batch_test(shapes):
    expected = {eid: {str(r["version"]): len(r["fields"]) for r in shapes[eid]} for eid in IDS}
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
 assert EXPECTED["4720"]=={{"0":26}} and EXPECTED["4728"]=={{"0":10,"1":11}}
 assert {{f["native_name"]:f for f in d["4728"]["fields"]}}["MembershipExpirationTime"]["versions"]==["1"]
def test_04_semantics():
 d=bp(); assert d["4723"]["overview"]["event_type"]=="Success/Failure" and d["4724"]["overview"]["event_type"]=="Success/Failure"
 for eid in ("4720","4722","4723","4724","4725","4726"): assert d[eid]["overview"]["subcategory"]=="Audit User Account Management"
 for eid in ("4727","4728","4729","4730"): assert d[eid]["overview"]["subcategory"]=="Audit Security Group Management"
def test_05_evidence_and_redistribution():
 data={{x["id"]:x for x in records()}}
 for eid in IDS:
  cs=[x for x in data.values() if x.get("record_kind")=="claim" and x.get("subject_id")==f"atlas:event:microsoft.windows.security:{{eid}}" and x.get("predicate")=="telemetry.represents"]; assert len(cs)==1 and STRUCTURAL in {{e["source_id"] for e in cs[0]["evidence"]}}; assert data[f"atlas:source:atlas.source:ultimate-windows-security-event-{{eid}}"]["redistribution"]["policy"]=="prohibited"
def test_06_coverage():
 m=json.loads((ROOT/"content/encyclopedia/coverage-manifest.json").read_text()); b=m["windows_security_log_review_benchmark"]; assert (b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(96,326,"96/422",22.75); assert set(IDS).issubset(set(b["covered_event_ids"])); w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert (w["denominator_count"],w["encyclopedia_grade_count"],w["remaining_count"])==(423,90,333)
def test_07_discovery_binding():
 x=json.loads((ROOT/"ingestion/inventories/windows-security-auditing-4720-4730-26100.telemetry.json").read_text()); s=x["scope_metadata"]; assert (s["workflow_run_id"],s["artifact_id"],s["provider_event_version_definition_count"],s["provider_unique_event_id_count"])==({RUN_ID},{ARTIFACT_ID},11,10); assert s["artifact_digest"]=={ARTIFACT_DIGEST!r} and s["raw_artifact_sha256"]=={RAW_SHA256!r}
'''
    (ROOT / "tests/phase51010/test_windows_security_auditing_4720_4730.py").write_text(text, encoding="utf-8")


def update_docs(base):
    path = ROOT / "docs/windows-security-log-scope.md"; text = path.read_text(encoding="utf-8")
    replacements = {
        "Current controlled progress after the eighth bounded Windows Security Log batch:": "Current controlled progress after the ninth bounded Windows Security Log batch:",
        "- Windows Security Log UWS review benchmark: `86/422` listed identities encyclopedia-grade (`20.38%`), `336` remaining;": "- Windows Security Log UWS review benchmark: `96/422` listed identities encyclopedia-grade (`22.75%`), `326` remaining;",
        "- newly promoted Security-Auditing IDs in this batch: `4710`, `4711`, `4712`, `4713`, `4714`, `4715`, `4716`, `4717`, `4718`, `4719`;": "- newly promoted Security-Auditing IDs in this batch: `4720`, `4722`, `4723`, `4724`, `4725`, `4726`, `4727`, `4728`, `4729`, `4730`;",
        "- Windows Security Auditing provider coverage: `80/423` encyclopedia-grade with `343` provider-specific identities remaining;": "- Windows Security Auditing provider coverage: `90/423` encyclopedia-grade with `333` provider-specific identities remaining;",
    }
    for old, new in replacements.items(): assert text.count(old) == 1; text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")
    path = ROOT / "docs/releases/third-party-redistribution-inventory.json"; data = json.loads(path.read_text(encoding="utf-8")); row = next(x for x in data["entries"] if x["id"] == "microsoft-windows-security-documentation")
    additions = [*[f"content/encyclopedia/sources/microsoft-windows-security-event-{eid}.json" for eid in IDS], "ingestion/inventories/windows-security-auditing-4720-4730-26100.telemetry.json", "content/encyclopedia/sources/microsoft-windows-security-auditing-provider-26100-4720-4730.json"]
    parts = [x.strip() for x in row.get("review_evidence", "").split(" + ") if x.strip()]
    for item in additions:
        if item not in parts: parts.append(item)
    row["review_evidence"] = " + ".join(parts); base.dump(path, data)


def main():
    batch08 = load_previous(); batch07 = batch08.load_previous(); batch06 = batch07.load_impl(); base = batch06.load_base(); batch06.configure_base(base)
    discovery = raw_discovery(); shapes = provider_shapes(discovery); inventory = build_inventory(base, shapes)
    base.dump(ROOT / "ingestion/inventories/windows-security-auditing-4720-4730-26100.telemetry.json", inventory)
    write_sources(base); base.update_blueprint(shapes); update_coverage(base); rebuild_snapshot(); update_tests(); write_batch_test(shapes); update_docs(base)
    print("batch_ids=" + ",".join(IDS)); print("inventory_digest=" + inventory["digest"]); print("coverage=96/422"); print("security_auditing=90/423")


if __name__ == "__main__":
    main()
