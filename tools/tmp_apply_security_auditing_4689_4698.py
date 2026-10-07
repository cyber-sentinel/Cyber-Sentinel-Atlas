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
BASE_COMMIT = "3feda12eecc037fb4039cd6040b485eba29c3393"
BASE_PATH = "tools/tmp_apply_security_auditing_4654_4663.py"
NOW = "2026-10-07T09:50:00Z"
IDS = ["4689","4690","4691","4692","4693","4694","4695","4696","4697","4698"]
RUN_ID = 37602920128
ARTIFACT_ID = 11473885860
ARTIFACT_DIGEST = "sha256:532f141c53f9af4bbe5553c969444ee57322c7c98bbe0c04a391670c48e0ec83"
RAW_SHA256 = "sha256-42f992beda2ee6963d14ea2e475722a4a99324332c900a763167d6f9a55079b1"
STRUCTURAL_ID = "atlas:source:atlas.source:microsoft-windows-security-auditing-provider-26100-4689-4698"
STRUCTURAL_VERSION = "windows-server-2025-build-26100-security-auditing-4689-4698"

META = {
    "4689": {
        "title": "A process has exited",
        "category": "Detailed Tracking",
        "subcategory": "Audit Process Termination",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4689",
        "source_version": "event-4689-v0-doc",
        "summary": "Records process termination and exposes the subject, process identifier/name and provider-native exit status for lifecycle correlation.",
        "requirements": ["Enable Audit Process Termination success auditing where process-lifecycle visibility is required.", "Preserve ProcessId, ProcessName, Status and subject logon context."],
        "interpretation": "Process exit is common lifecycle telemetry; security value increases for critical processes, unusual paths, abnormal exit patterns or tight correlation with suspicious process creation.",
        "analysis": ["Correlate ProcessId and ProcessName with Event 4688 using host and tight time bounds because PIDs are reusable.", "Review Status using application-specific exit-code semantics rather than assuming a universal meaning."],
        "correlations": [{"target":"4688","key":"ProcessId + ProcessName + Computer + time","purpose":"pair process termination with process creation"}],
    },
    "4690": {
        "title": "An attempt was made to duplicate a handle to an object",
        "category": "Object Access",
        "subcategory": "Audit Handle Manipulation",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4690",
        "source_version": "event-4690-v0-doc",
        "summary": "Records duplication of an object handle from one process into another and preserves source/target handle and process identifiers.",
        "requirements": ["Enable Audit Handle Manipulation success auditing only where handle-level visibility is intentionally required.", "Preserve SourceHandleId, SourceProcessId, TargetHandleId and TargetProcessId."],
        "interpretation": "Microsoft notes that this event usually has little standalone security relevance; it is most useful for narrowly scoped handle-lifecycle investigations.",
        "analysis": ["Correlate source and target process identifiers with process creation telemetry.", "Use the source and target handle identifiers to follow activity involving a specifically monitored object handle."],
        "correlations": [{"target":"4688","key":"SourceProcessId or TargetProcessId + Computer + time","purpose":"resolve the processes participating in handle duplication"},{"target":"4663","key":"TargetHandleId + Computer + time","purpose":"follow later access using the duplicated handle where available"}],
    },
    "4691": {
        "title": "Indirect access to an object was requested",
        "category": "Object Access",
        "subcategory": "Audit Other Object Access Events",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4691",
        "source_version": "event-4691-v0-doc",
        "summary": "Records an indirect object-access request; Microsoft documents this identity for ALPC port access-request activity.",
        "requirements": ["Enable Audit Other Object Access Events success auditing when ALPC indirect-access telemetry is required.", "Preserve ObjectType, ObjectName, AccessList/AccessMask, ProcessId and subject context."],
        "interpretation": "This event is generally low-value outside targeted ALPC investigations; interpret requested rights according to the object type and local context.",
        "analysis": ["Review ObjectType/ObjectName and requested access only in scenarios where the ALPC object is security-relevant.", "Correlate ProcessId with process creation telemetry before attributing the request."],
        "correlations": [{"target":"4688","key":"ProcessId + Computer + time","purpose":"resolve the requesting process"}],
    },
    "4692": {
        "title": "Backup of data protection master key was attempted",
        "category": "Detailed Tracking",
        "subcategory": "Audit DPAPI Activity",
        "event_type": "Success/Failure",
        "marker": "S,F",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4692",
        "source_version": "event-4692-v0-doc",
        "summary": "Records an attempted backup of a DPAPI master key, including recovery-server/key identifiers and a provider-native status/failure value.",
        "requirements": ["Enable Audit DPAPI Activity success/failure auditing when DPAPI troubleshooting or master-key lifecycle visibility is required.", "Preserve MasterKeyId, RecoveryServer, RecoveryKeyId, FailureReason and subject context."],
        "interpretation": "Microsoft characterizes DPAPI Activity events primarily as informational/troubleshooting telemetry; unexpected failures or unusual recovery infrastructure merit contextual review.",
        "analysis": ["Correlate MasterKeyId with nearby DPAPI events for the same subject and host.", "Interpret FailureReason using Windows status semantics and verify RecoveryServer/RecoveryKeyId against expected domain recovery configuration."],
        "correlations": [{"target":"4693","key":"MasterKeyId + SubjectLogonId + Computer + time","purpose":"compare master-key backup and recovery activity"}],
    },
    "4693": {
        "title": "Recovery of data protection master key was attempted",
        "category": "Detailed Tracking",
        "subcategory": "Audit DPAPI Activity",
        "event_type": "Success/Failure",
        "marker": "S,F",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693",
        "source_version": "event-4693-v0-doc",
        "summary": "Records an attempted DPAPI master-key recovery and identifies the master key, recovery reason/server/key and failure status.",
        "requirements": ["Enable Audit DPAPI Activity success/failure auditing when master-key recovery visibility is required.", "Preserve MasterKeyId, RecoveryReason, RecoveryServer, RecoveryKeyId, FailureId and subject context."],
        "interpretation": "Master-key recovery is usually operational DPAPI behavior; failures or recovery activity outside expected domain/user workflows require contextual validation.",
        "analysis": ["Review RecoveryReason and FailureId alongside recovery infrastructure and account context.", "Correlate MasterKeyId with Event 4692 and other DPAPI activity."],
        "correlations": [{"target":"4692","key":"MasterKeyId + SubjectLogonId + Computer + time","purpose":"compare master-key recovery with backup activity"}],
    },
    "4694": {
        "title": "Protection of auditable protected data was attempted",
        "category": "Detailed Tracking",
        "subcategory": "Audit DPAPI Activity",
        "event_type": "Success/Failure",
        "marker": "S,F",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4694",
        "source_version": "event-4694-v0-doc",
        "summary": "Records use of DPAPI CryptProtectData with the CRYPTPROTECT_AUDIT flag and exposes data description, master-key identifier, flags, algorithms and status.",
        "requirements": ["Enable Audit DPAPI Activity when auditable DPAPI protection operations are required.", "Preserve DataDescription, MasterKeyId, ProtectedDataFlags, CryptoAlgorithms, FailureReason and subject context."],
        "interpretation": "Microsoft documents this event mainly for informational/troubleshooting use; security meaning depends on the protected-data purpose, caller context and result.",
        "analysis": ["Baseline DataDescription and CryptoAlgorithms for applications expected to emit auditable DPAPI operations.", "Investigate unexpected failures, subjects or protected-data descriptions in conjunction with application telemetry."],
        "correlations": [{"target":"4695","key":"MasterKeyId + DataDescription + SubjectLogonId + Computer + time","purpose":"compare protection and unprotection operations"}],
    },
    "4695": {
        "title": "Unprotection of auditable protected data was attempted",
        "category": "Detailed Tracking",
        "subcategory": "Audit DPAPI Activity",
        "event_type": "Success/Failure",
        "marker": "S,F",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4695",
        "source_version": "event-4695-v0-doc",
        "summary": "Records an auditable DPAPI unprotection/decryption attempt and exposes the protected-data description, master-key identifier, flags, algorithms and status.",
        "requirements": ["Enable Audit DPAPI Activity when auditable DPAPI unprotection operations are required.", "Preserve DataDescription, MasterKeyId, ProtectedDataFlags, CryptoAlgorithms, FailureReason and subject context."],
        "interpretation": "Failures can arise from normal key/password/user-context conditions as well as abnormal access; avoid treating a failure alone as malicious.",
        "analysis": ["Assess FailureReason together with subject identity and the application/data description.", "Correlate repeated failures or unusual subjects with authentication, credential-access and process telemetry."],
        "correlations": [{"target":"4694","key":"MasterKeyId + DataDescription + SubjectLogonId + Computer + time","purpose":"compare unprotection with prior protection activity"}],
    },
    "4696": {
        "title": "A primary token was assigned to process",
        "category": "Detailed Tracking",
        "subcategory": "Audit Process Creation",
        "event_type": "Success / deprecated",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4696",
        "source_version": "event-4696-v0-doc",
        "summary": "Microsoft defines this event for assignment of a non-current primary access token to a process but documents the event as deprecated starting with Windows 7 / Windows Server 2008 R2; controlled build-26100 provider evidence still defines Version 0 structurally.",
        "requirements": ["Treat this as a deprecated provider identity rather than expected modern operational telemetry.", "If observed, preserve subject, target token/account, target process and assigning process context."],
        "interpretation": "Unexpected presence on a modern host should first trigger provider/platform provenance verification; only then interpret the token-assignment context.",
        "analysis": ["Verify OS build/provider authenticity before relying on an observed modern event.", "Correlate TargetProcessId and ProcessId with process creation telemetry and the two logon identifiers with authentication context."],
        "correlations": [{"target":"4688","key":"TargetProcessId or ProcessId + Computer + time","purpose":"resolve process context around primary-token assignment"},{"target":"4624","key":"TargetLogonId or SubjectLogonId + Computer","purpose":"resolve authentication context"}],
    },
    "4697": {
        "title": "A service was installed in the system",
        "category": "System",
        "subcategory": "Audit Security System Extension",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697",
        "source_version": "event-4697-v0-doc-plus-provider-v1",
        "summary": "Records installation of a Windows service. Controlled provider evidence preserves Version 0 and Version 1; Version 1 adds client-process start key, client PID and parent PID context.",
        "requirements": ["Enable Audit Security System Extension success auditing and collect this event on systems where service-install visibility is required.", "Preserve service configuration, subject context and the exact event version; retain Version 1 client-process fields."],
        "interpretation": "Service installation is high-value persistence/execution telemetry. Validate service binary path, account, start type and creating process against approved software and administrative change context.",
        "analysis": ["Prioritize unexpected ServiceFileName paths, service accounts, auto-start configuration and newly introduced service names.", "For Version 1, correlate ClientProcessId/ParentProcessId with 4688 and use ClientProcessStartKey to reduce PID-reuse ambiguity."],
        "correlations": [{"target":"4688","key":"ClientProcessId or ParentProcessId + Computer + time","purpose":"resolve service-creation process lineage"}],
    },
    "4698": {
        "title": "A scheduled task was created",
        "category": "Object Access",
        "subcategory": "Audit Other Object Access Events",
        "event_type": "Success",
        "marker": "S",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698",
        "source_version": "event-4698-v0-doc-plus-provider-v1",
        "summary": "Records creation of a scheduled task. Controlled provider evidence preserves Version 0 and Version 1; Version 1 adds client process identity/lineage plus RPC locality and FQDN context.",
        "requirements": ["Enable Audit Other Object Access Events success auditing and collect scheduled-task creation on systems where persistence visibility is required.", "Preserve TaskName, TaskContent and exact event-version fields; retain Version 1 client/RPC/FQDN context."],
        "interpretation": "Scheduled-task creation is high-value persistence/execution telemetry. Review task XML, trigger/action, principal/logon type and creating client context against approved automation and administration.",
        "analysis": ["Parse TaskContent XML for executable/script actions, unusual paths, privileged principals, hidden settings and suspicious triggers.", "For Version 1, correlate ClientProcessId/ParentProcessId with 4688 and evaluate RpcCallClientLocality/FQDN for remote creation context."],
        "correlations": [{"target":"4688","key":"ClientProcessId or ParentProcessId + Computer + time","purpose":"resolve scheduled-task creation process lineage"},{"target":"4702","key":"TaskName + Computer + time","purpose":"track subsequent scheduled-task updates"}],
    },
}

FIELD_DETAILS = {
    "Status": ("Result", "status", "Provider-native process exit or operation status value; interpret in event-specific context."),
    "SourceHandleId": ("Handle Duplication", "source-handle-id", "Source object handle being duplicated."),
    "SourceProcessId": ("Handle Duplication", "source-process-id", "Process identifier owning the source handle."),
    "TargetHandleId": ("Handle Duplication", "target-handle-id", "New duplicated handle identifier in the target process."),
    "TargetProcessId": ("Process", "target-process-id", "Target process identifier associated with the event."),
    "MasterKeyId": ("DPAPI", "master-key-id", "Identifier of the DPAPI master key involved in the operation."),
    "RecoveryServer": ("DPAPI", "recovery-server", "Recovery server/domain controller associated with DPAPI master-key backup or recovery."),
    "RecoveryKeyId": ("DPAPI", "recovery-key-id", "Identifier of the DPAPI recovery key."),
    "FailureReason": ("Result", "failure-reason", "Provider-native status/failure code for the attempted operation."),
    "RecoveryReason": ("DPAPI", "recovery-reason", "Provider-native reason code for DPAPI master-key recovery."),
    "FailureId": ("Result", "failure-id", "Provider-native failure/status identifier for DPAPI master-key recovery."),
    "DataDescription": ("DPAPI", "data-description", "Description associated with the auditable protected-data operation."),
    "ProtectedDataFlags": ("DPAPI", "protected-data-flags", "Flags supplied to the DPAPI protected-data operation."),
    "CryptoAlgorithms": ("DPAPI", "crypto-algorithms", "Provider-rendered cryptographic algorithm information for the DPAPI operation."),
    "TargetLogonId": ("Target Account", "target-logon-id", "Logon-session identifier associated with the target account/token."),
    "TargetProcessName": ("Process", "target-process-name", "Executable path/name of the target process."),
    "ServiceName": ("Service", "service-name", "Name of the newly installed service."),
    "ServiceFileName": ("Service", "service-file-name", "Binary path or command configured for the service."),
    "ServiceType": ("Service", "service-type", "Provider-native service type value."),
    "ServiceStartType": ("Service", "service-start-type", "Configured service start type."),
    "ServiceAccount": ("Service", "service-account", "Account configured to run the service."),
    "ClientProcessStartKey": ("Client Process", "client-process-start-key", "Stable process-start key added by newer provider versions for process correlation."),
    "ClientProcessId": ("Client Process", "client-process-id", "Client process identifier added by newer provider versions."),
    "ParentProcessId": ("Client Process", "parent-process-id", "Parent process identifier added by newer provider versions."),
    "TaskName": ("Task", "task-name", "Task Scheduler path/name of the newly created scheduled task."),
    "TaskContent": ("Task", "task-content", "XML task definition captured when the scheduled task was created."),
    "RpcCallClientLocality": ("RPC Context", "rpc-call-client-locality", "Provider-native locality indicator for the RPC client that created the task."),
    "FQDN": ("RPC Context", "fqdn", "FQDN context supplied by the newer scheduled-task event version."),
}


def load_base():
    text = subprocess.check_output(["git", "show", f"{BASE_COMMIT}:{BASE_PATH}"], text=True)
    tmp = Path(tempfile.mkdtemp()) / "base_batch.py"
    tmp.write_text(text, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("base_batch", tmp)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load reusable Batch 04 helper")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.ROOT = ROOT
    return mod


def raw_discovery():
    path = Path(os.environ["ATLAS_DISCOVERY_JSON"])
    blob = path.read_bytes()
    assert "sha256-" + hashlib.sha256(blob).hexdigest() == RAW_SHA256
    data = json.loads(blob)
    assert data["provider"] == "Microsoft-Windows-Security-Auditing"
    assert data["channel_scope"] == "Security"
    assert data["unique_event_id_count"] == 10
    assert data["event_version_definition_count"] == 12
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
        "4689": [0], "4690": [0], "4691": [0], "4692": [0], "4693": [0],
        "4694": [0], "4695": [0], "4696": [0], "4697": [0, 1], "4698": [0, 1],
    }
    expected_counts = {
        "4689": {0: 7}, "4690": {0: 8}, "4691": {0: 9}, "4692": {0: 8}, "4693": {0: 9},
        "4694": {0: 9}, "4695": {0: 9}, "4696": {0: 12}, "4697": {0: 9, 1: 12}, "4698": {0: 6, 1: 11},
    }
    actual_versions = {eid: [row["version"] for row in rows] for eid, rows in result.items()}
    assert actual_versions == expected_versions
    actual_counts = {eid: {row["version"]: len(row["fields"]) for row in rows} for eid, rows in result.items()}
    assert actual_counts == expected_counts
    v4697 = {row["version"]: [f[0] for f in row["fields"]] for row in result["4697"]}
    assert v4697[1][-3:] == ["ClientProcessStartKey", "ClientProcessId", "ParentProcessId"]
    v4698 = {row["version"]: [f[0] for f in row["fields"]] for row in result["4698"]}
    assert v4698[1][-5:] == ["ClientProcessStartKey", "ClientProcessId", "ParentProcessId", "RpcCallClientLocality", "FQDN"]
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
        "inventory_id": "atlas:inventory:atlas.ingestion:windows-security-auditing-4689-4698-26100",
        "inventory_kind": "telemetry",
        "declared_scope": "Microsoft-Windows-Security-Auditing provider Event IDs 4689 through 4698 linked to Security on controlled Windows Server 2025 Datacenter build 26100",
        "source_ids": [STRUCTURAL_ID],
        "inventory_method": "provider-runtime-metadata",
        "inventory_source_version": STRUCTURAL_VERSION,
        "expected_identity_count": 10,
        "identity_dimensions": ["provider", "channel", "native-id", "product", "platform", "version"],
        "scope_metadata": {
            "provider": "Microsoft-Windows-Security-Auditing",
            "channel": "Security",
            "product": "Windows Server 2025 Datacenter",
            "platform": "Windows",
            "windows_build": "26100",
            "architecture": "64-bit",
            "workflow_run_id": RUN_ID,
            "artifact_id": ARTIFACT_ID,
            "artifact_digest": ARTIFACT_DIGEST,
            "raw_artifact_sha256": RAW_SHA256,
            "provider_event_version_definition_count": 12,
            "provider_unique_event_id_count": 10,
            "expected_identities": identities,
            "completeness_semantics": "bounded structural evidence for ten identities already inside the separately frozen 423-ID provider denominator; twelve version definitions are preserved and do not alter that denominator",
        },
        "guardrails": {"max_unexplained_shrink_percent": 0, "max_unexplained_growth_percent": 0},
    }
    doc["digest"] = base.digest_without_field(doc)
    return doc


def configure_base(base):
    base.ROOT = ROOT
    base.NOW = NOW
    base.IDS = IDS
    base.RUN_ID = RUN_ID
    base.ARTIFACT_ID = ARTIFACT_ID
    base.ARTIFACT_DIGEST = ARTIFACT_DIGEST
    base.RAW_SHA256 = RAW_SHA256
    base.STRUCTURAL_ID = STRUCTURAL_ID
    base.STRUCTURAL_VERSION = STRUCTURAL_VERSION
    base.META = META
    base.FIELD_DETAILS.update(FIELD_DETAILS)


def write_sources(base):
    source_dir = ROOT / "content/encyclopedia/sources"
    provider = base.source_record(
        STRUCTURAL_ID,
        "microsoft-windows-security-auditing-provider-26100-4689-4698",
        "Microsoft-Windows-Security-Auditing Security Provider Metadata — Windows Server 2025 build 26100 — bounded Event IDs 4689–4698 batch",
        ["https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log"],
        change={"strategy": "checksum", "notes": f"Bound to workflow {RUN_ID}, artifact {ARTIFACT_ID}, artifact digest {ARTIFACT_DIGEST}, raw JSON {RAW_SHA256}, and normalized inventory."},
    )
    base.dump(source_dir / "microsoft-windows-security-auditing-provider-26100-4689-4698.json", provider)
    for eid in IDS:
        meta = META[eid]
        base.dump(
            source_dir / f"microsoft-windows-security-event-{eid}.json",
            base.source_record(
                f"atlas:source:atlas.source:microsoft-windows-security-event-{eid}",
                f"microsoft-windows-security-event-{eid}",
                f"Microsoft Windows Security Auditing Event {eid} Documentation",
                [meta["url"], "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/Appendix-L--Events-to-Monitor"],
                change={"strategy": "content-diff", "notes": "Microsoft event/audit-policy material is semantic authority; controlled provider evidence is structural authority for exact version and field shape."},
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
                change={"strategy": "manual", "notes": "Coverage / Quick Detail benchmark only. No automated or bulk ingestion is authorized."},
            ),
        )


def update_coverage(base):
    path = ROOT / "content/encyclopedia/coverage-manifest.json"
    data = json.loads(path.read_text())
    benchmark = data["windows_security_log_review_benchmark"]
    assert (benchmark["listed_unique_event_id_count"], benchmark["encyclopedia_grade_listed_id_count"], benchmark["remaining_listed_id_count"]) == (422, 56, 366)
    covered = sorted(set(benchmark["covered_event_ids"]) | set(IDS), key=int)
    assert len(covered) == 66
    benchmark.update({"covered_event_ids": covered, "encyclopedia_grade_listed_id_count": 66, "remaining_listed_id_count": 356, "completion_ratio": "66/422", "completion_percent": 15.64})
    family = next(x for x in data["families"] if x["id"] == "windows-security-auditing")
    assert (family["denominator_count"], family["encyclopedia_grade_count"], family["remaining_count"]) == (423, 50, 373)
    family.update({"encyclopedia_grade_count": 60, "remaining_count": 363})
    base.dump(path, data)


def rebuild_snapshot():
    path = ROOT / "tools/content/build_windows_security_coverage_snapshot.py"
    spec = importlib.util.spec_from_file_location("coverage_builder", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load coverage snapshot builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    snapshot = module.build_snapshot()
    assert (snapshot["denominator_count"], snapshot["encyclopedia_grade_count"], snapshot["remaining_count"], snapshot["completion_ratio"], snapshot["completion_percent"]) == (423, 60, 363, "60/423", 14.18)
    (ROOT / "content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json").write_text(json.dumps(snapshot, sort_keys=True, indent=2) + "\n")


def update_tests():
    path = ROOT / "tests/phase51010/test_windows_security_coverage_snapshot.py"
    text = path.read_text()
    replacements = [("== 50", "== 60"), ("== 373", "== 363"), ('== "50/423"', '== "60/423"'), ("== 11.82", "== 14.18")]
    for old, new in replacements:
        assert old in text, old
        text = text.replace(old, new)
    path.write_text(text)

    path = ROOT / "tests/phase51010/test_windows_security_auditing_4664_4675.py"
    text = path.read_text()
    old = 'assert (b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(56,366,"56/422",13.27); assert set(IDS).issubset(set(b["covered_event_ids"])); w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert (w["denominator_count"],w["encyclopedia_grade_count"],w["remaining_count"])==(423,50,373)'
    new = 'assert b["listed_unique_event_id_count"]==422 and set(IDS).issubset(set(b["covered_event_ids"])) and b["encyclopedia_grade_listed_id_count"]>=56; w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert w["denominator_count"]==423 and w["encyclopedia_grade_count"]>=50 and w["remaining_count"]==423-w["encyclopedia_grade_count"]'
    assert old in text
    path.write_text(text.replace(old, new))


def write_batch_test(base, shapes):
    expected = {eid: {str(row["version"]): len(row["fields"]) for row in shapes[eid]} for eid in IDS}
    text = f'''#!/usr/bin/env python3\nfrom __future__ import annotations\nimport importlib.util,json\nfrom pathlib import Path\nROOT=Path(__file__).resolve().parents[2]\nIDS={IDS!r}\nSTRUCTURAL={STRUCTURAL_ID!r}\nEXPECTED={expected!r}\ndef mod(n,p):\n s=importlib.util.spec_from_file_location(n,p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m\nbuilder=mod("b",ROOT/"tools/content/build_encyclopedia_records.py"); validator=mod("v",ROOT/"tools/validate_phase52.py")\ndef records(): return builder.build_records()\ndef bp():\n d=json.loads((ROOT/"content/encyclopedia/approved-exemplars.json").read_text()); return {{str(x["native_event_id"]):x for x in d["events"] if x.get("namespace")=="microsoft.windows.security"}}\ndef test_01_canonical():\n pairs=[(ROOT/"content/encyclopedia/approved-exemplars.json",x) for x in records()]; e=validator.validate_schema_records(pairs)+validator.validate_semantics(pairs,validator.load_registries()); assert e==[],"\\n".join(e)\ndef test_02_search_and_scope():\n pairs=[(ROOT/"content/encyclopedia/approved-exemplars.json",x) for x in records()]; data={{x["id"]:x for x in records()}}\n for eid in IDS:\n  rid=f"atlas:event:microsoft.windows.security:{{eid}}"; assert validator.resolve_query(pairs,eid)==[rid]; c=data[rid]["native_identifiers"][0]["context"]; assert (c["provider"],c["channel"])==("Microsoft-Windows-Security-Auditing","Security")\ndef test_03_versions_exact():\n d=bp()\n for eid,want in EXPECTED.items(): assert {{str(r["version"]):r["field_count"] for r in d[eid]["overview"]["event_versions"]}}==want\n assert EXPECTED["4697"]=={{"0":9,"1":12}} and EXPECTED["4698"]=={{"0":6,"1":11}}\ndef test_04_semantics():\n d=bp(); assert d["4689"]["overview"]["event_type"]=="Success"; assert d["4692"]["overview"]["event_type"]=="Success/Failure"; assert d["4696"]["overview"]["event_type"]=="Success / deprecated"; assert d["4697"]["overview"]["event_type"]=="Success"; assert d["4698"]["overview"]["event_type"]=="Success"\ndef test_05_evidence_and_redistribution():\n data={{x["id"]:x for x in records()}}\n for eid in IDS:\n  cs=[x for x in data.values() if x.get("record_kind")=="claim" and x.get("subject_id")==f"atlas:event:microsoft.windows.security:{{eid}}" and x.get("predicate")=="telemetry.represents"]; assert len(cs)==1 and STRUCTURAL in {{e["source_id"] for e in cs[0]["evidence"]}}; assert data[f"atlas:source:atlas.source:ultimate-windows-security-event-{{eid}}"]["redistribution"]["policy"]=="prohibited"\ndef test_06_coverage():\n m=json.loads((ROOT/"content/encyclopedia/coverage-manifest.json").read_text()); b=m["windows_security_log_review_benchmark"]; assert (b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(66,356,"66/422",15.64); assert set(IDS).issubset(set(b["covered_event_ids"])); w=next(x for x in m["families"] if x["id"]=="windows-security-auditing"); assert (w["denominator_count"],w["encyclopedia_grade_count"],w["remaining_count"])==(423,60,363)\ndef test_07_discovery_binding():\n x=json.loads((ROOT/"ingestion/inventories/windows-security-auditing-4689-4698-26100.telemetry.json").read_text()); s=x["scope_metadata"]; assert (s["workflow_run_id"],s["artifact_id"],s["provider_event_version_definition_count"],s["provider_unique_event_id_count"])==({RUN_ID},{ARTIFACT_ID},12,10); assert s["artifact_digest"]=={ARTIFACT_DIGEST!r} and s["raw_artifact_sha256"]=={RAW_SHA256!r}\n'''
    (ROOT / "tests/phase51010/test_windows_security_auditing_4689_4698.py").write_text(text)


def update_docs(base):
    path = ROOT / "docs/windows-security-log-scope.md"
    text = path.read_text()
    assert "Current controlled progress after the fifth bounded Windows Security Log batch:" in text
    text = text.replace("Current controlled progress after the fifth bounded Windows Security Log batch:", "Current controlled progress after the sixth bounded Windows Security Log batch:")
    assert "- Windows Security Log UWS review benchmark: `56/422` listed identities encyclopedia-grade (`13.27%`), `366` remaining;" in text
    text = text.replace("- Windows Security Log UWS review benchmark: `56/422` listed identities encyclopedia-grade (`13.27%`), `366` remaining;", "- Windows Security Log UWS review benchmark: `66/422` listed identities encyclopedia-grade (`15.64%`), `356` remaining;")
    old_ids = "- newly promoted Security-Auditing IDs in this batch: `4664`, `4665`, `4666`, `4667`, `4668`, `4670`, `4671`, `4673`, `4674`, `4675`;"
    new_ids = "- newly promoted Security-Auditing IDs in this batch: `4689`, `4690`, `4691`, `4692`, `4693`, `4694`, `4695`, `4696`, `4697`, `4698`;"
    assert old_ids in text
    text = text.replace(old_ids, new_ids)
    assert "- Windows Security Auditing provider coverage: `50/423` encyclopedia-grade with `373` provider-specific identities remaining;" in text
    text = text.replace("- Windows Security Auditing provider coverage: `50/423` encyclopedia-grade with `373` provider-specific identities remaining;", "- Windows Security Auditing provider coverage: `60/423` encyclopedia-grade with `363` provider-specific identities remaining;")
    path.write_text(text)

    path = ROOT / "docs/releases/third-party-redistribution-inventory.json"
    data = json.loads(path.read_text())
    row = next(x for x in data["entries"] if x["id"] == "microsoft-windows-security-documentation")
    additions = [*[f"content/encyclopedia/sources/microsoft-windows-security-event-{eid}.json" for eid in IDS], "ingestion/inventories/windows-security-auditing-4689-4698-26100.telemetry.json", "content/encyclopedia/sources/microsoft-windows-security-auditing-provider-26100-4689-4698.json"]
    parts = [x.strip() for x in row.get("review_evidence", "").split(" + ") if x.strip()]
    for item in additions:
        if item not in parts:
            parts.append(item)
    row["review_evidence"] = " + ".join(parts)
    base.dump(path, data)


def main():
    base = load_base()
    configure_base(base)
    discovery = raw_discovery()
    shapes = provider_shapes(discovery)
    inventory = build_inventory(base, shapes)
    base.dump(ROOT / "ingestion/inventories/windows-security-auditing-4689-4698-26100.telemetry.json", inventory)
    write_sources(base)
    base.update_blueprint(shapes)
    update_coverage(base)
    rebuild_snapshot()
    update_tests()
    write_batch_test(base, shapes)
    update_docs(base)
    print("batch_ids=" + ",".join(IDS))
    print("inventory_digest=" + inventory["digest"])
    print("coverage=66/422")
    print("security_auditing=60/423")


if __name__ == "__main__":
    main()
