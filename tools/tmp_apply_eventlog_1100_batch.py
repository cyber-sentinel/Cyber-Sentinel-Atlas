#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAMP = "2026-10-06T11:49:30Z"
BATCH_IDS = ["1100", "1101", "1102", "1104", "1105", "1108"]
STRUCTURAL_SOURCE_ID = "atlas:source:atlas.source:microsoft-windows-eventlog-provider-26100-1100-series"
STRUCTURAL_VERSION = "windows-server-2025-build-26100-eventlog-provider-1100-series"
INVENTORY_PATH = ROOT / "ingestion/inventories/windows-eventlog-security-1100-series-26100.telemetry.json"

def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))

def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def source_record(*, key, title, publisher, source_class, urls, official_status, license_status, redistribution_policy, redistribution_notes, cadence, stale_days, strategy, change_notes):
    return {
        "schema_version": "1.0.0", "record_kind": "source", "id": f"atlas:source:atlas.source:{key}",
        "record_revision": 1, "created_at": STAMP, "updated_at": STAMP, "curation_status": "validated",
        "namespace": "atlas.source", "canonical_key": key, "title": title, "publisher": publisher,
        "source_class": source_class, "canonical_urls": urls, "official_status": official_status,
        "license": {"status": license_status},
        "redistribution": {"policy": redistribution_policy, "notes": redistribution_notes},
        "freshness_policy": {"expected_update_cadence": cadence, "stale_after_days": stale_days},
        "change_detection_policy": {"strategy": strategy, "notes": change_notes},
    }

def field(key, section, native_name, typ, meaning, versions=None, notes=None, correlation=None):
    out = {"key": key, "section": section, "native_name": native_name, "type": typ, "meaning": meaning}
    if versions is not None: out["versions"] = versions
    if notes is not None: out["notes"] = notes
    if correlation is not None: out["correlation"] = correlation
    return out

def external_ref(event_id):
    return {"source_id": f"atlas:source:atlas.source:ultimate-windows-security-event-{event_id}", "url": f"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={event_id}", "role": "PRIMARY_EXTERNAL_QUICK_DETAIL_REFERENCE", "redistribution": "source-link-and-coverage-benchmark-only"}

def structural_ref(event_id, versions):
    return {"source_id": STRUCTURAL_SOURCE_ID, "source_version": STRUCTURAL_VERSION, "locator": f"Microsoft-Windows-Eventlog / Security / Event ID {event_id} / versions {','.join(versions)}"}

def base_event(event_id, title, semantic_source_id, semantic_version, semantic_url, locator, overview, collection, correlations, analysis, fields):
    return {"id": f"atlas:event:microsoft.windows.security:{event_id}", "namespace": "microsoft.windows.security", "canonical_key": event_id, "title": f"Windows Security Event {event_id} — {title}", "provider": "Microsoft-Windows-Eventlog", "channel": "Security", "product": "Windows Security Log", "platform": "Windows", "native_event_id": event_id, "aliases": [event_id, f"Event ID {event_id}", f"Windows {event_id}", title], "lifecycle": "current", "source_id": semantic_source_id, "source_version": semantic_version, "source_url": semantic_url, "source_locator": locator, "structural_source": structural_ref(event_id, [row["version"] for row in overview["event_versions"]]), "external_reference": external_ref(event_id), "overview": overview, "collection": collection, "correlations": correlations, "analysis": analysis, "fields": fields}

def build_events():
    provider_url = "https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log"
    old = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-"
    events = []
    events.append(base_event("1100", "The event logging service has shut down", "atlas:source:atlas.source:microsoft-windows-eventlog-event-1100", "event-1100-v0-doc", old + "1100", "1100(S): The event logging service has shut down", {"summary": "Records shutdown of the Windows Event Log service in the Security log. It is expected during normal system shutdown and is useful as a timeline boundary, but the event alone does not establish malicious activity.", "category": "System", "subcategory": "Other Events", "event_type": "Success", "provider_level": "Informational", "provider_task": "Shutdown", "minimum_supported_generation": "Windows Server 2008 / Windows Vista", "event_versions": [{"version": "0", "generation": "Documented and provider-validated shape", "field_count": 0, "notes": "No event-specific payload fields are present in the controlled provider template."}]}, {"requirements": ["Security log collection must preserve Microsoft-Windows-Eventlog Event ID 1100 and its standard Event/System envelope."], "interpretation_note": "Normal shutdown generates this event. Unexpected occurrence should be correlated with system shutdown/restart evidence and administrative activity before escalation."}, [{"target": "4608", "key": "Computer + time", "purpose": "compare Event Log service shutdown with the next audited Windows startup boundary", "limitation": "Timeline correlation does not prove the cause of a restart."}, {"target": "Windows System shutdown/startup telemetry", "key": "Computer + time", "purpose": "corroborate whether the service shutdown aligned with an expected operating-system shutdown"}], ["Use Event 1100 as a low-volume Security-log timeline marker for Event Log service shutdown.", "Investigate unexpected or repeated service shutdowns when they coincide with outages, suspicious administration, log-integrity anomalies or other reboot evidence.", "Do not classify Event 1100 as malicious by itself because Microsoft documents it during normal shutdown."], []))
    events.append(base_event("1101", "Audit events have been dropped by the transport", STRUCTURAL_SOURCE_ID, STRUCTURAL_VERSION, provider_url, "Microsoft-Windows-Eventlog / Security / Event ID 1101 / Version 0", {"summary": "Records that the Windows Event Log transport dropped audit events. Controlled Windows Server 2025 provider metadata exposes one Reason byte but does not provide a reviewed authoritative value dictionary for that byte.", "category": "System", "subcategory": "Other Events", "event_type": "Success audit keyword", "provider_level": "Error", "provider_task": "EventProcessing", "event_versions": [{"version": "0", "generation": "Windows Server 2025 provider-validated shape", "field_count": 1, "notes": "Provider metadata exposes Reason as UInt8."}]}, {"requirements": ["Security log collection must preserve Microsoft-Windows-Eventlog Event ID 1101 and the Reason field."], "interpretation_note": "Treat this event as an audit-visibility loss signal. No ATLAS Reason-code mapping is published until an authoritative value dictionary is independently verified."}, [{"target": "1108", "key": "Computer + time", "purpose": "look for nearby Event Log processing errors that may explain audit transport loss", "limitation": "Temporal proximity is not proof of causation."}, {"target": "1100 / 4608", "key": "Computer + time", "purpose": "place dropped audit transport events around shutdown/startup boundaries"}], ["Prioritize Event 1101 as a telemetry-integrity signal because audit records were dropped before durable logging.", "Correlate with system stability, Event Log service state, forwarding health and nearby Event Log processing errors.", "Do not invent a Reason value dictionary; the reviewed provider metadata establishes the field shape, not undocumented value semantics."], [field("reason", "Transport Status", "Reason", "UInt8", "Provider-supplied reason value associated with audit events dropped by the Event Log transport.", ["0"], "No authoritative Reason-code dictionary was established during this review; retain the raw value.")]))
    events.append(base_event("1102", "The audit log was cleared", "atlas:source:atlas.source:microsoft-windows-eventlog-event-1102", "event-1102-v0-doc+provider-v1", old + "1102", "1102(S): The audit log was cleared", {"summary": "Records clearing of the Security audit log and identifies the subject that performed the action. Windows Server 2025 provider metadata adds Version 1 process-correlation fields beyond the older documented Version 0 payload.", "category": "System", "subcategory": "Other Events", "event_type": "Success", "provider_level": "Informational", "provider_task": "LogClear", "minimum_supported_generation": "Windows Server 2008 / Windows Vista", "event_versions": [{"version": "0", "generation": "Microsoft documentation / legacy documented shape", "field_count": 4, "notes": "Subject identity and SubjectLogonId."}, {"version": "1", "generation": "Windows Server 2025 build 26100 provider-validated shape", "field_count": 6, "notes": "Adds ClientProcessId and ClientProcessStartKey."}]}, {"requirements": ["Security log collection must preserve Event.Version because Version 1 adds client-process correlation fields.", "Forwarding/retention controls should protect Event 1102 from loss when the local Security log is cleared."], "interpretation_note": "Security log clearing is high-value administrative telemetry but is not, by itself, proof of malicious intent."}, [{"target": "4624", "key": "SubjectLogonId + Computer + time", "purpose": "correlate the clearing subject to the associated logon session where available"}, {"target": "4688 / process telemetry", "key": "ClientProcessId + time", "purpose": "investigate the client process responsible for Version 1 log clearing", "limitation": "PIDs can be reused; use time and additional process evidence."}], ["Treat Event 1102 as a high-priority audit-integrity event and establish who cleared the log, from which session, and under what change/incident context.", "For Version 1, use ClientProcessId and ClientProcessStartKey as additional process pivots while retaining subject/logon correlation.", "Do not assume maliciousness when log clearing is authorized maintenance; verify change context and surrounding activity."], [field("subject.security-id", "Subject", "SubjectUserSid", "SID", "Security identifier of the account that cleared the audit log.", ["0", "1"]), field("subject.account-name", "Subject", "SubjectUserName", "UnicodeString", "Account name of the subject that cleared the audit log.", ["0", "1"]), field("subject.domain-name", "Subject", "SubjectDomainName", "UnicodeString", "Domain or authority associated with the subject account.", ["0", "1"]), field("subject.logon-id", "Subject", "SubjectLogonId", "HexInt64", "Logon-session identifier of the subject that cleared the audit log.", ["0", "1"], correlation="Correlate with Security logon events such as 4624 on the same computer and time window."), field("process.client-process-id", "Process Information", "ClientProcessId", "UInt32", "Client process identifier exposed by the Version 1 provider payload.", ["1"], correlation="Use with time and independent process telemetry because process IDs can be reused."), field("process.client-process-start-key", "Process Information", "ClientProcessStartKey", "UInt64", "Provider-supplied process start key exposed by the Version 1 payload for stronger client-process correlation.", ["1"])]))
    events.append(base_event("1104", "The security log is now full", "atlas:source:atlas.source:microsoft-windows-eventlog-event-1104", "event-1104-v0-doc", old + "1104", "1104(S): The security log is now full", {"summary": "Records that the Security event log reached its configured capacity. This is an audit-availability condition and can precede loss of new Security events depending on retention policy.", "category": "System", "subcategory": "Other Events", "event_type": "Success audit keyword", "provider_level": "Error", "provider_task": "EventProcessing", "event_versions": [{"version": "0", "generation": "Documented and provider-validated shape", "field_count": 0, "notes": "No event-specific payload fields are present in the controlled provider template."}]}, {"requirements": ["Security log sizing and retention policy should be governed so the log does not silently stop accepting required audit data.", "Collection should preserve Event 1104 as an audit-availability alert."], "interpretation_note": "A full Security log is a visibility and operations problem; it is not proof of deliberate tampering."}, [{"target": "1105", "key": "Computer + time", "purpose": "determine whether archive-on-full behavior created a backup log"}, {"target": "1101 / 1108", "key": "Computer + time", "purpose": "check for nearby audit loss or Event Log processing errors"}], ["Investigate Event 1104 promptly because full-log conditions can create an audit visibility gap under some retention policies.", "Verify Security log maximum size, retention mode, archival/forwarding health and disk capacity.", "Distinguish configuration/capacity failures from deliberate log-integrity interference using surrounding evidence."], []))
    events.append(base_event("1105", "Event log automatic backup", "atlas:source:atlas.source:microsoft-windows-eventlog-event-1105", "event-1105-v0-doc", old + "1105", "1105(S): Event log automatic backup", {"summary": "Records automatic creation of an archived event-log file when the log becomes full under archive-on-full retention behavior, including the channel and backup path.", "category": "System", "subcategory": "Other Events", "event_type": "Success", "provider_level": "Informational", "provider_task": "AutoBackup", "event_versions": [{"version": "0", "generation": "Documented and provider-validated shape", "field_count": 2, "notes": "Provider-native fields are Channel and BackupPath."}]}, {"requirements": ["Archive-on-full behavior must be configured for this event to represent automatic backup of a full log.", "Collectors should preserve the Channel and BackupPath values."], "interpretation_note": "The event can be normal under deliberate retention policy. Investigate unusual frequency, unexpected paths, or paired capacity problems rather than treating the backup itself as malicious."}, [{"target": "1104", "key": "Computer + time", "purpose": "correlate automatic backup with the Security log reaching capacity"}, {"target": "Archived EVTX file", "key": "BackupPath", "purpose": "locate the archived log for retention and forensic review"}], ["Use Channel and BackupPath to verify that the expected Security log was archived to an expected location.", "Repeated backups in short intervals can indicate undersized logs, excessive audit volume or retention problems.", "Preserve archived EVTX files according to evidence and retention requirements when an investigation is active."], [field("channel", "Backup Context", "Channel", "UnicodeString", "Name of the event-log channel that was automatically backed up.", ["0"]), field("backup-path", "Backup Context", "BackupPath", "UnicodeString/path", "Path of the archived event-log file created by automatic backup.", ["0"], correlation="Use as the file-system pivot for the archived EVTX artifact.")]))
    events.append(base_event("1108", "The event logging service encountered an error while processing an incoming event", "atlas:source:atlas.source:microsoft-windows-eventlog-event-1108", "event-1108-v0-doc", old + "1108", "1108(S): The event logging service encountered an error while processing an incoming event", {"summary": "Records an Event Log service error while processing an incoming event. Controlled provider metadata exposes ErrorCode, EventID and PubID; older Microsoft rendering labels the publisher field as PublisherID.", "category": "System", "subcategory": "Other Events", "event_type": "Success audit keyword", "provider_level": "Error", "provider_task": "EventProcessing", "minimum_supported_generation": "Windows Server 2008 R2 / Windows 7", "event_versions": [{"version": "0", "generation": "Documented and provider-validated shape", "field_count": 3, "notes": "Provider-native fields: ErrorCode, EventID, PubID."}]}, {"requirements": ["Security log collection must preserve Event 1108 and all three provider-native fields.", "Investigation should retain the nearby event that failed processing when available."], "interpretation_note": "This is a logging-integrity/error signal. It can follow a malformed or otherwise unprocessable incoming event and should be investigated without assuming malicious intent."}, [{"target": "Referenced incoming event", "key": "EventID + PubID + time", "purpose": "identify the event/publisher associated with the processing failure"}, {"target": "1101", "key": "Computer + time", "purpose": "check whether Event Log processing problems coincided with dropped audit transport records"}], ["Monitor Event 1108 because it indicates that an incoming event could not be processed correctly by the Event Log service.", "Use ErrorCode, EventID, PubID and nearby log entries to identify the defective or incompatible publisher/event.", "Preserve the provider-native field name PubID in ATLAS; document that older Microsoft rendered examples may label the same publisher concept as PublisherID."], [field("error-code", "Processing Failure", "ErrorCode", "UInt32", "Provider error code associated with the incoming-event processing failure.", ["0"]), field("event-id", "Processing Failure", "EventID", "UInt16", "Native event identifier of the incoming event associated with the processing failure.", ["0"], correlation="Use with PubID and time to locate the related event."), field("publisher-id", "Processing Failure", "PubID", "UnicodeString", "Provider/publisher identifier associated with the incoming event that could not be processed.", ["0"], notes="The Windows Server 2025 provider template names this field PubID; older Microsoft rendered XML examples label the publisher element PublisherID.")]))
    return events

def apply_builder_refactor():
    path = ROOT / "tools/content/build_encyclopedia_records.py"
    text = path.read_text(encoding="utf-8")
    old = '    else:\n        ev = [evidence(event["source_id"], event["source_version"], f"{event[\'source_locator\']} / {field[\'section\']} / {field[\'native_name\']}")]\n        if field.get("provider_scope"):\n'
    new = '    else:\n        ev = [evidence(event["source_id"], event["source_version"], f"{event[\'source_locator\']} / {field[\'section\']} / {field[\'native_name\']}")]\n        structural = event.get("structural_source")\n        if structural:\n            ev.append(evidence(\n                structural["source_id"], structural["source_version"],\n                f"{structural[\'locator\']} / {field[\'native_name\']}",\n                transformation="normalized-fact",\n            ))\n        if field.get("provider_scope"):\n'
    if old not in text: raise SystemExit("builder field structural insertion point drifted")
    text = text.replace(old, new, 1)
    old = 'def event_claims(item: dict[str, Any]) -> list[dict[str, Any]]:\n    base_ev = [evidence(item["source_id"], item["source_version"], item["source_locator"])]\n    claims = [\n'
    new = 'def event_claims(item: dict[str, Any]) -> list[dict[str, Any]]:\n    base_ev = [evidence(item["source_id"], item["source_version"], item["source_locator"])]\n    structural = item.get("structural_source")\n    if structural:\n        base_ev.append(evidence(\n            structural["source_id"], structural["source_version"], structural["locator"],\n            transformation="normalized-fact",\n        ))\n    claims = [\n'
    if old not in text: raise SystemExit("builder event structural insertion point drifted")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")

def write_sources():
    source_dir = ROOT / "content/encyclopedia/sources"; source_dir.mkdir(parents=True, exist_ok=True)
    write_json(source_dir / "microsoft-windows-eventlog-provider-26100-1100-series.json", source_record(key="microsoft-windows-eventlog-provider-26100-1100-series", title="Microsoft-Windows-Eventlog Security Provider Metadata — Windows Server 2025 build 26100 — Event IDs 1100/1101/1102/1104/1105/1108", publisher="Microsoft", source_class="tier-a-authoritative", urls=["https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log"], official_status="official-runtime-provider-evidence", license_status="unknown", redistribution_policy="restricted", redistribution_notes="ATLAS stores independently authored normalized provider facts, hashes and locators. Raw Microsoft message/template prose is not packaged as encyclopedia content.", cadence="provider-build-bound", stale_days=180, strategy="controlled-provider-export", change_notes="Bound to GitHub workflow run 37458952335, artifact 11411012754, artifact digest sha256:cc93b81627495898362de99e71a39fa7f213a57cc9ed842e6deee779c52968f0 and normalized inventory ingestion/inventories/windows-eventlog-security-1100-series-26100.telemetry.json. Raw discovery JSON sha256 is 6b8bd9a58483296a67e6762fb4840ca7275e83c3109d74b99f6ca6d393d230b0."))
    old = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-"
    for event_id in ["1100", "1102", "1104", "1105", "1108"]:
        write_json(source_dir / f"microsoft-windows-eventlog-event-{event_id}.json", source_record(key=f"microsoft-windows-eventlog-event-{event_id}", title=f"Microsoft Windows Event Log Event {event_id} Documentation", publisher="Microsoft", source_class="tier-a-authoritative", urls=[old + event_id], official_status="official", license_status="unknown", redistribution_policy="restricted", redistribution_notes="ATLAS stores independently authored normalized facts and source locators; substantial Microsoft documentation prose is not redistributed by this exemplar.", cadence="documentation-maintained", stale_days=180, strategy="content-diff", change_notes=f"Event {event_id} semantic documentation is reviewed together with controlled Microsoft-Windows-Eventlog provider metadata; provider shape changes require controlled re-review."))
    for event_id in BATCH_IDS:
        write_json(source_dir / f"ultimate-windows-security-event-{event_id}.json", source_record(key=f"ultimate-windows-security-event-{event_id}", title=f"Ultimate Windows Security — Windows Security Log Event ID {event_id}", publisher="Monterey Technology Group, Inc.", source_class="tier-c-secondary-research", urls=[f"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={event_id}"], official_status="secondary-reference", license_status="restricted", redistribution_policy="prohibited", redistribution_notes="External analyst-reference and coverage benchmark only. ATLAS does not package substantial page prose/examples without explicit permission from the rights holder.", cadence="web-reference", stale_days=90, strategy="manual", change_notes="No automated or bulk prose ingestion is authorized. Review remains controlled under the ATLAS source-authority policy."))

def write_inventory():
    identities = [{"event_id":"1100","versions":[{"version":0,"field_count":0,"level":"win:Informational","task":"el:Shutdown","fields":[]}]},{"event_id":"1101","versions":[{"version":0,"field_count":1,"level":"win:Error","task":"el:EventProcessing","fields":[{"name":"Reason","in_type":"win:UInt8","out_type":"xs:unsignedByte"}]}]},{"event_id":"1102","versions":[{"version":0,"field_count":4,"level":"win:Informational","task":"el:LogClear","fields":[{"name":"SubjectUserSid","in_type":"win:SID","out_type":"xs:string"},{"name":"SubjectUserName","in_type":"win:UnicodeString","out_type":"xs:string"},{"name":"SubjectDomainName","in_type":"win:UnicodeString","out_type":"xs:string"},{"name":"SubjectLogonId","in_type":"win:HexInt64","out_type":"win:HexInt64"}]},{"version":1,"field_count":6,"level":"win:Informational","task":"el:LogClear","fields":[{"name":"SubjectUserSid","in_type":"win:SID","out_type":"xs:string"},{"name":"SubjectUserName","in_type":"win:UnicodeString","out_type":"xs:string"},{"name":"SubjectDomainName","in_type":"win:UnicodeString","out_type":"xs:string"},{"name":"SubjectLogonId","in_type":"win:HexInt64","out_type":"win:HexInt64"},{"name":"ClientProcessId","in_type":"win:UInt32","out_type":"xs:unsignedInt"},{"name":"ClientProcessStartKey","in_type":"win:UInt64","out_type":"xs:unsignedLong"}]}]},{"event_id":"1104","versions":[{"version":0,"field_count":0,"level":"win:Error","task":"el:EventProcessing","fields":[]}]},{"event_id":"1105","versions":[{"version":0,"field_count":2,"level":"win:Informational","task":"el:AutoBackup","fields":[{"name":"Channel","in_type":"win:UnicodeString","out_type":"xs:string"},{"name":"BackupPath","in_type":"win:UnicodeString","out_type":"xs:string"}]}]},{"event_id":"1108","versions":[{"version":0,"field_count":3,"level":"win:Error","task":"el:EventProcessing","fields":[{"name":"ErrorCode","in_type":"win:UInt32","out_type":"xs:unsignedInt"},{"name":"EventID","in_type":"win:UInt16","out_type":"xs:unsignedShort"},{"name":"PubID","in_type":"win:UnicodeString","out_type":"xs:string"}]}]}]
    payload = {"ingestion_contract_version":"1.0.0","inventory_contract_version":"1.0.0","inventory_id":"atlas:inventory:atlas.ingestion:windows-eventlog-security-1100-series-26100","inventory_kind":"telemetry","declared_scope":"Microsoft-Windows-Eventlog provider Event IDs 1100, 1101, 1102, 1104, 1105 and 1108 linked to the Security channel on a controlled Windows Server 2025 Datacenter build 26100 GitHub runner","source_ids":[STRUCTURAL_SOURCE_ID],"inventory_method":"provider-runtime-metadata","inventory_source_version":STRUCTURAL_VERSION,"expected_identity_count":6,"identity_dimensions":["provider","channel","native-id","product","platform","version"],"scope_metadata":{"provider":"Microsoft-Windows-Eventlog","channel":"Security","product":"Windows Server 2025 Datacenter","platform":"Windows","windows_build":"26100","architecture":"64-bit","workflow_run_id":37458952335,"artifact_id":11411012754,"artifact_digest":"sha256:cc93b81627495898362de99e71a39fa7f213a57cc9ed842e6deee779c52968f0","raw_artifact_sha256":"sha256-6b8bd9a58483296a67e6762fb4840ca7275e83c3109d74b99f6ca6d393d230b0","provider_event_version_definition_count":7,"provider_unique_event_id_count":6,"expected_identities":identities,"completeness_semantics":"bounded structural evidence for the six UWS benchmark identities omitted from the Microsoft-Windows-Security-Auditing provider denominator; not a global Windows EventLog denominator"},"guardrails":{"max_unexplained_shrink_percent":0,"max_unexplained_growth_percent":0}}
    payload["digest"] = "sha256-" + hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest(); write_json(INVENTORY_PATH, payload)

def update_blueprint():
    path=ROOT/"content/encyclopedia/approved-exemplars.json"; doc=read_json(path); events=doc["events"]
    overlap=sorted(set(BATCH_IDS)&{str(e["native_event_id"]) for e in events})
    if overlap: raise SystemExit(f"batch IDs already exist in approved exemplars: {overlap}")
    idx=next(i for i,e in enumerate(events) if str(e.get("native_event_id"))=="4608" and e.get("namespace")=="microsoft.windows.security"); events[idx:idx]=build_events(); write_json(path,doc)

def update_manifest():
    path=ROOT/"content/encyclopedia/coverage-manifest.json"; doc=read_json(path); benchmark=doc["windows_security_log_review_benchmark"]
    for key,value in {"minimum_listed_event_id":1100,"maximum_listed_event_id":8191,"listed_unique_event_id_count":422,"continuous_numeric_range":False}.items():
        if benchmark.get(key)!=value: raise SystemExit(f"benchmark scope drifted at {key}: {benchmark.get(key)!r}")
    covered=["1100","1101","1102","1104","1105","1108","4608","4624","4625","4648","4672","4688","4740","4768","4769","4771"]
    benchmark["encyclopedia_grade_listed_id_count"]=len(covered); benchmark["remaining_listed_id_count"]=benchmark["listed_unique_event_id_count"]-len(covered); benchmark["completion_ratio"]=f"{len(covered)}/{benchmark['listed_unique_event_id_count']}"; benchmark["completion_percent"]=round(len(covered)*100/benchmark["listed_unique_event_id_count"],2); benchmark["covered_event_ids"]=covered
    windows=next(item for item in doc["families"] if item["id"]=="windows-security-auditing")
    if (windows["denominator_count"],windows["encyclopedia_grade_count"],windows["remaining_count"])!=(423,10,413): raise SystemExit("Security-Auditing provider coverage unexpectedly drifted")
    write_json(path,doc)

def refactor_coverage_validator():
    path=ROOT/"tools/content/validate_encyclopedia_coverage.py"; text=path.read_text(encoding="utf-8")
    if 'APPROVED = ROOT / "content" / "encyclopedia" / "approved-exemplars.json"' not in text: text=text.replace('MANIFEST = ROOT / "content" / "encyclopedia" / "coverage-manifest.json"\n','MANIFEST = ROOT / "content" / "encyclopedia" / "coverage-manifest.json"\nAPPROVED = ROOT / "content" / "encyclopedia" / "approved-exemplars.json"\n',1)
    start=text.index('    security_log_benchmark = manifest.get("windows_security_log_review_benchmark", {})'); end=text.index('\n    families = manifest.get("families", [])',start)
    replacement='''    security_log_benchmark = manifest.get("windows_security_log_review_benchmark", {})
    expected_security_log_static = {
        "state": "CONTROLLED_REVIEW_BENCHMARK_DEFINED",
        "source": "Ultimate Windows Security — Windows Security Log Encyclopedia",
        "source_url": "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx",
        "scope_role": "coverage-and-quick-detail-review-benchmark-only",
        "minimum_listed_event_id": 1100,
        "maximum_listed_event_id": 8191,
        "listed_unique_event_id_count": 422,
        "continuous_numeric_range": False,
        "semantic_authority": "Microsoft official documentation plus controlled provider/channel/version evidence",
        "ingestion_policy": "Do not bulk-ingest third-party prose. UWS remains a controlled Quick Detail and coverage benchmark; every promoted Event ID requires independent Microsoft/provider evidence and provenance review.",
    }
    for key, expected in expected_security_log_static.items():
        if security_log_benchmark.get(key) != expected:
            errors.append(f"Windows Security Log review benchmark drifted at {key}")
    covered = security_log_benchmark.get("covered_event_ids")
    grade = security_log_benchmark.get("encyclopedia_grade_listed_id_count")
    remaining_benchmark = security_log_benchmark.get("remaining_listed_id_count")
    listed = security_log_benchmark.get("listed_unique_event_id_count")
    if not isinstance(covered, list) or not all(isinstance(item, str) and item.isdigit() for item in covered):
        errors.append("Windows Security Log covered_event_ids must be a list of numeric strings"); covered = []
    if covered != sorted(set(covered), key=int): errors.append("Windows Security Log covered_event_ids must be unique and numerically sorted")
    if not isinstance(grade, int) or grade != len(covered): errors.append("Windows Security Log benchmark numerator must equal covered_event_ids length")
    if not isinstance(remaining_benchmark, int) or not isinstance(listed, int) or not isinstance(grade, int) or grade + remaining_benchmark != listed: errors.append("Windows Security Log benchmark coverage arithmetic is invalid")
    if isinstance(grade, int) and isinstance(listed, int):
        if security_log_benchmark.get("completion_ratio") != f"{grade}/{listed}": errors.append("Windows Security Log benchmark completion ratio drifted")
        expected_percent = round(grade * 100 / listed, 2) if listed else None
        if security_log_benchmark.get("completion_percent") != expected_percent: errors.append("Windows Security Log benchmark completion percent drifted")
    approved = load(APPROVED)
    approved_by_native = {str(item.get("native_event_id")): item for item in approved.get("events", []) if item.get("namespace") == "microsoft.windows.security"}
    for event_id in covered:
        item = approved_by_native.get(event_id)
        if not item: errors.append(f"Windows Security Log covered Event ID {event_id} lacks an approved exemplar"); continue
        external = item.get("external_reference", {})
        if "ultimatewindowssecurity.com/securitylog/encyclopedia/" not in str(external.get("url", "")): errors.append(f"Windows Security Log covered Event ID {event_id} lacks controlled UWS Quick Detail reference")
'''
    text=text[:start]+replacement+text[end:]
    old='        f"Windows Security Log review benchmark={benchmark[\'listed_unique_event_id_count\']} listed IDs/"\n        f"{benchmark[\'minimum_listed_event_id\']}..{benchmark[\'maximum_listed_event_id\']} sparse range; "\n'; new='        f"Windows Security Log review benchmark={benchmark[\'encyclopedia_grade_listed_id_count\']}/"\n        f"{benchmark[\'listed_unique_event_id_count\']} encyclopedia-grade listed IDs "\n        f"({benchmark[\'minimum_listed_event_id\']}..{benchmark[\'maximum_listed_event_id\']} sparse range); "\n'
    if old not in text: raise SystemExit("coverage validator print block drifted")
    path.write_text(text.replace(old,new,1),encoding="utf-8")

def add_tests():
    (ROOT/"tests/phase51010/test_windows_security_eventlog_1100_series.py").write_text(TEST_FILE,encoding="utf-8")

def update_third_party_inventory():
    path=ROOT/"docs/releases/third-party-redistribution-inventory.json"; doc=read_json(path); entries=doc["entries"]
    if any(item["id"]=="microsoft-windows-eventlog-documentation" for item in entries): raise SystemExit("microsoft-windows-eventlog-documentation already exists")
    insert_at=next(i for i,item in enumerate(entries) if item["id"]=="ultimate-windows-security-encyclopedia")
    entries.insert(insert_at,{"id":"microsoft-windows-eventlog-documentation","class":"knowledge-content-source-only","included":False,"upstream_revision":"Microsoft Learn Event 1100, 1102, 1104, 1105, 1108 pages plus controlled Microsoft-Windows-Eventlog provider metadata for 1100/1101/1102/1104/1105/1108; source prose excluded from Public Preview pack","license_or_terms":"Microsoft Learn Terms of Use; verbatim/substantial Microsoft documentation excluded from Public Preview pack unless separately cleared","license_source":"https://learn.microsoft.com/en-us/legal/termsofuse","redistribution_state":"EXCLUDED","required_notices":"none for excluded Microsoft source text; retain source citation/provenance for independently authored ATLAS facts, field semantics and analysis","review_evidence":"ingestion/inventories/windows-eventlog-security-1100-series-26100.telemetry.json + content/encyclopedia/sources/microsoft-windows-eventlog-provider-26100-1100-series.json + content/encyclopedia/sources/microsoft-windows-eventlog-event-1100.json + content/encyclopedia/sources/microsoft-windows-eventlog-event-1102.json + content/encyclopedia/sources/microsoft-windows-eventlog-event-1104.json + content/encyclopedia/sources/microsoft-windows-eventlog-event-1105.json + content/encyclopedia/sources/microsoft-windows-eventlog-event-1108.json"}); write_json(path,doc)

def update_scope_doc():
    path=ROOT/"docs/windows-security-log-scope.md"; text=path.read_text(encoding="utf-8")
    old='''At the time this scope correction was introduced:

- Windows Security Auditing provider coverage: `10/423` encyclopedia-grade;
- remaining provider-specific identities: `413`;
- Sysmon 15.22: `30/30` complete;
- global Windows denominator: intentionally unfrozen.

This document changes the **review and product scope framing**; it does not falsely convert the external benchmark into a release denominator and does not grant encyclopedia-grade status to any newly admitted Event ID.
'''
    new='''Current controlled progress after the first EventLog-provider batch:

- Windows Security Log UWS review benchmark: `16/422` listed identities encyclopedia-grade (`3.79%`), `406` remaining;
- benchmark-covered IDs: `1100`, `1101`, `1102`, `1104`, `1105`, `1108`, `4608`, `4624`, `4625`, `4648`, `4672`, `4688`, `4740`, `4768`, `4769`, `4771`;
- Windows Security Auditing provider coverage remains independently `10/423` encyclopedia-grade with `413` provider-specific identities remaining;
- Sysmon 15.22: `30/30` complete;
- global Windows denominator: intentionally unfrozen.

The benchmark progress counter is an analyst-facing Security-log coverage measure, not a replacement for provider-specific denominators and not an all-Windows completion percentage.
'''
    if old not in text: raise SystemExit("scope doc current coverage block drifted")
    text=text.replace(old,new,1)
    old2='''The next Security Log coverage work must prioritize the previously omitted `1100`-series identities (`1100`, `1101`, `1102`, `1104`, `1105`, `1108`) before continuing the later uncovered Security-Auditing queue, while preserving provider-specific denominators and provenance.
'''; new2='''After the `1100`-series identities are promoted, rebuild the UWS benchmark queue and continue with the next uncovered listed identity. Because `4608` is already encyclopedia-grade, the next numeric benchmark candidate is `4609`, subject to the same Microsoft/provider/UWS controlled review and provider-specific denominator rules.
'''
    if old2 not in text: raise SystemExit("scope doc planning block drifted")
    path.write_text(text.replace(old2,new2,1),encoding="utf-8")

TEST_FILE = r'''#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; IDS=["1100","1101","1102","1104","1105","1108"]; STRUCTURAL="atlas:source:atlas.source:microsoft-windows-eventlog-provider-26100-1100-series"
def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
builder=load_module("eventlog1100_builder",ROOT/"tools/content/build_encyclopedia_records.py"); validator=load_module("eventlog1100_validator",ROOT/"tools/validate_phase52.py")
def records(): return builder.build_records()
def by_id(): return {item["id"]:item for item in records()}
def blueprint_by_native():
    doc=json.loads((ROOT/"content/encyclopedia/approved-exemplars.json").read_text(encoding="utf-8")); return {str(item["native_event_id"]):item for item in doc["events"] if item.get("namespace")=="microsoft.windows.security"}
def test_01_batch_records_validate_canonical_v1():
    pairs=[(ROOT/"content/encyclopedia/approved-exemplars.json",item) for item in records()]; errors=validator.validate_schema_records(pairs); errors+=validator.validate_semantics(pairs,validator.load_registries()); assert errors==[],"\n".join(errors)
def test_02_eventlog_provider_and_search_identities():
    pairs=[(ROOT/"content/encyclopedia/approved-exemplars.json",item) for item in records()]; data=by_id()
    for event_id in IDS:
        rid=f"atlas:event:microsoft.windows.security:{event_id}"; assert rid in data; context=data[rid]["native_identifiers"][0]["context"]; assert context["provider"]=="Microsoft-Windows-Eventlog"; assert context["channel"]=="Security"; assert validator.resolve_query(pairs,event_id)==[rid]
def test_03_version_aware_field_shapes_match_provider_inventory():
    bp=blueprint_by_native(); expected={"1100":{"0":0},"1101":{"0":1},"1102":{"0":4,"1":6},"1104":{"0":0},"1105":{"0":2},"1108":{"0":3}}
    for event_id,want in expected.items(): assert {row["version"]:row["field_count"] for row in bp[event_id]["overview"]["event_versions"]}==want
    assert bp["1100"]["fields"]==[] and bp["1104"]["fields"]==[]; assert {f["native_name"] for f in bp["1101"]["fields"]}=={"Reason"}; assert {f["native_name"] for f in bp["1105"]["fields"]}=={"Channel","BackupPath"}; assert {f["native_name"] for f in bp["1108"]["fields"]}=={"ErrorCode","EventID","PubID"}; assert {f["native_name"] for f in bp["1102"]["fields"] if f.get("versions")==["1"]}=={"ClientProcessId","ClientProcessStartKey"}
def test_04_structural_provider_evidence_is_attached():
    data=by_id()
    for event_id in IDS:
        subject=f"atlas:event:microsoft.windows.security:{event_id}"; represents=[item for item in data.values() if item.get("record_kind")=="claim" and item.get("subject_id")==subject and item.get("predicate")=="telemetry.represents"]; assert len(represents)==1; assert STRUCTURAL in {ev["source_id"] for ev in represents[0]["evidence"]}
    for event_id in ["1101","1102","1105","1108"]:
        prefix=f"atlas:field:microsoft.windows.security:{event_id}."; claims=[item for item in data.values() if item.get("record_kind")=="claim" and item.get("predicate")=="telemetry.field-semantics" and str(item.get("subject_id","")).startswith(prefix)]; assert claims
        for item in claims: assert STRUCTURAL in {ev["source_id"] for ev in item["evidence"]}
def test_05_uws_is_reference_only_and_not_semantic_authority():
    data=by_id()
    for event_id in IDS:
        source_id=f"atlas:source:atlas.source:ultimate-windows-security-event-{event_id}"; source=data[source_id]; assert source["redistribution"]["policy"]=="prohibited"; subject=f"atlas:event:microsoft.windows.security:{event_id}"; claims=[item for item in data.values() if item.get("record_kind")=="claim" and item.get("subject_id")==subject and item.get("predicate")=="telemetry.source" and any(ev.get("source_id")==source_id for ev in item.get("evidence",[]))]; assert len(claims)==1; assert claims[0]["object"]["value"]["redistribution"]=="source-link-and-coverage-benchmark-only"
def test_06_benchmark_progress_is_separate_from_security_auditing_denominator():
    m=json.loads((ROOT/"content/encyclopedia/coverage-manifest.json").read_text(encoding="utf-8")); b=m["windows_security_log_review_benchmark"]; assert (b["listed_unique_event_id_count"],b["encyclopedia_grade_listed_id_count"],b["remaining_listed_id_count"],b["completion_ratio"],b["completion_percent"])==(422,16,406,"16/422",3.79); assert b["covered_event_ids"][:6]==IDS; w=next(item for item in m["families"] if item["id"]=="windows-security-auditing"); assert (w["denominator_count"],w["encyclopedia_grade_count"],w["remaining_count"])==(423,10,413)
def test_07_structural_inventory_is_bound_to_exact_discovery_evidence():
    inv=json.loads((ROOT/"ingestion/inventories/windows-eventlog-security-1100-series-26100.telemetry.json").read_text(encoding="utf-8")); s=inv["scope_metadata"]; assert inv["expected_identity_count"]==6; assert (s["provider"],s["channel"],s["windows_build"])==("Microsoft-Windows-Eventlog","Security","26100"); assert (s["workflow_run_id"],s["artifact_id"])==(37458952335,11411012754); assert s["artifact_digest"]=="sha256:cc93b81627495898362de99e71a39fa7f213a57cc9ed842e6deee779c52968f0"; assert s["raw_artifact_sha256"]=="sha256-6b8bd9a58483296a67e6762fb4840ca7275e83c3109d74b99f6ca6d393d230b0"; assert s["provider_event_version_definition_count"]==7; assert [row["event_id"] for row in s["expected_identities"]]==IDS
'''

def main():
    write_sources(); write_inventory(); apply_builder_refactor(); update_blueprint(); update_manifest(); refactor_coverage_validator(); add_tests(); update_third_party_inventory(); update_scope_doc(); print("eventlog_1100_batch_applied=6"); return 0
if __name__=="__main__": raise SystemExit(main())
