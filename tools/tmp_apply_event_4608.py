#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APPROVED = ROOT / "content/encyclopedia/approved-exemplars.json"
SNAPSHOT = ROOT / "content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json"
MANIFEST = ROOT / "content/encyclopedia/coverage-manifest.json"
SOURCES = ROOT / "content/encyclopedia/sources"
TEST_CONTENT = ROOT / "tests/phase51010/test_approved_exemplar_content.py"
TEST_SNAPSHOT = ROOT / "tests/phase51010/test_windows_security_coverage_snapshot.py"
TEST_QUEUE = ROOT / "tests/phase51010/test_windows_security_review_queue.py"
REDIST = ROOT / "docs/releases/third-party-redistribution-inventory.json"

EVENT_ID = "4608"
EVENT_CANONICAL_ID = "atlas:event:microsoft.windows.security:4608"
MICROSOFT_SOURCE_ID = "atlas:source:atlas.source:microsoft-windows-security-event-4608"
UWS_SOURCE_ID = "atlas:source:atlas.source:ultimate-windows-security-event-4608"
MICROSOFT_URL = "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4608"
UWS_URL = "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4608"
FIXED_TIME = "2026-10-05T16:10:00Z"


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def source_record(*, source_id: str, key: str, title: str, publisher: str, source_class: str,
                  url: str, official_status: str, license_status: str, redistribution_policy: str,
                  redistribution_notes: str, cadence: str, stale_after_days: int, strategy: str,
                  change_notes: str):
    return {
        "schema_version": "1.0.0",
        "record_kind": "source",
        "id": source_id,
        "record_revision": 1,
        "created_at": FIXED_TIME,
        "updated_at": FIXED_TIME,
        "curation_status": "validated",
        "namespace": "atlas.source",
        "canonical_key": key,
        "title": title,
        "publisher": publisher,
        "source_class": source_class,
        "canonical_urls": [url],
        "official_status": official_status,
        "license": {"status": license_status},
        "redistribution": {
            "policy": redistribution_policy,
            "notes": redistribution_notes,
        },
        "freshness_policy": {
            "expected_update_cadence": cadence,
            "stale_after_days": stale_after_days,
        },
        "change_detection_policy": {
            "strategy": strategy,
            "notes": change_notes,
        },
    }


approved = read_json(APPROVED)
if approved.get("status") != "MAINTAINER_APPROVED_PRODUCTION_EXEMPLARS":
    raise SystemExit("approved exemplar contract is not maintainer-approved")
if any(str(item.get("native_event_id")) == EVENT_ID and item.get("namespace") == "microsoft.windows.security" for item in approved["events"]):
    raise SystemExit("Event 4608 is already present; refusing duplicate promotion")

entry = {
    "id": EVENT_CANONICAL_ID,
    "namespace": "microsoft.windows.security",
    "canonical_key": EVENT_ID,
    "title": "Windows Security Event 4608 — Windows is starting up",
    "provider": "Microsoft-Windows-Security-Auditing",
    "channel": "Security",
    "product": "Windows Security Auditing",
    "platform": "Windows",
    "native_event_id": EVENT_ID,
    "aliases": [
        "4608",
        "Event ID 4608",
        "Windows 4608",
        "Windows startup",
        "Windows is starting up",
    ],
    "lifecycle": "current",
    "source_id": MICROSOFT_SOURCE_ID,
    "source_version": "event-4608-v0-doc",
    "source_url": MICROSOFT_URL,
    "source_locator": "4608(S): Windows is starting up",
    "external_reference": {
        "source_id": UWS_SOURCE_ID,
        "url": UWS_URL,
        "role": "PRIMARY_EXTERNAL_QUICK_DETAIL_REFERENCE",
        "redistribution": "source-link-and-coverage-benchmark-only",
    },
    "overview": {
        "summary": "Records initialization of the Windows security auditing subsystem when LSASS starts during operating-system startup, providing a low-volume Security-log marker for the beginning of an audited boot session.",
        "category": "System",
        "subcategory": "Audit Security State Change",
        "event_type": "Success",
        "minimum_supported_generation": "Windows Server 2008 / Windows Vista",
        "event_versions": [
            {
                "version": "0",
                "generation": "Windows Server 2008 / Windows Vista and later documented shape",
                "field_count": 0,
                "notes": "Microsoft documents an empty EventData element; the useful identity and timing context is carried by the standard Event/System envelope rather than event-specific fields.",
            }
        ],
    },
    "collection": {
        "requirements": [
            "Audit Security State Change success auditing must be enabled where this startup marker is required.",
            "Security log collection must preserve the provider Event/System envelope and Event.Version; Event 4608 has no event-specific EventData fields in the documented Version 0 shape.",
        ],
        "interpretation_note": "Microsoft documents Event 4608 as generated when LSASS starts and the auditing subsystem is initialized, typically during operating-system startup. It is a startup/audit-initialization observation, not evidence by itself that a restart was malicious or unexpected.",
        "scope_note": "Required server roles: none. Microsoft classifies Audit Security State Change as low-volume and recommends Success auditing for domain controllers, member servers and workstations.",
    },
    "correlations": [
        {
            "target": "4609",
            "key": "Computer + time",
            "purpose": "compare startup with a preceding audited shutdown when Event 4609 is available",
            "limitation": "Microsoft notes Event 4609 is defined but may not currently be generated by the operating system, so its absence is not proof of an unclean shutdown.",
        },
        {
            "target": "Windows System startup telemetry",
            "key": "Computer + boot time",
            "purpose": "corroborate operating-system startup and distinguish planned maintenance, reboot loops and collection gaps using independent system telemetry",
        },
        {
            "target": "4624 and subsequent Security activity",
            "key": "Computer + time",
            "purpose": "establish authentication and security activity observed after the audited startup boundary",
            "limitation": "This is a timeline correlation, not a direct causal relationship.",
        },
    ],
    "analysis": [
        "Use Event 4608 as a Security-log boot boundary marking LSASS/auditing-subsystem initialization, then correlate with independent startup/uptime evidence before classifying the reboot as expected or suspicious.",
        "Investigate repeated or unexpected 4608 events when they align with service interruption, crash, maintenance anomalies or other reboot evidence; the event alone is not a malicious verdict.",
        "Treat missing 4608 telemetry as a collection/integrity question rather than proof that Windows did not start, because Security-log retention, forwarding and tampering can affect visibility.",
        "Do not invent event-specific fields for Version 0: Microsoft documents an empty EventData element, so event-specific field count is zero.",
    ],
    "fields": [],
}

insert_at = len(approved["events"])
for index, item in enumerate(approved["events"]):
    if item.get("namespace") == "microsoft.windows.security" and int(item["native_event_id"]) > int(EVENT_ID):
        insert_at = index
        break
approved["events"].insert(insert_at, entry)
write_json(APPROVED, approved)

ms_path = SOURCES / "microsoft-windows-security-event-4608.json"
uws_path = SOURCES / "ultimate-windows-security-event-4608.json"
if ms_path.exists() or uws_path.exists():
    raise SystemExit("Event 4608 source file already exists; refusing overwrite")
write_json(ms_path, source_record(
    source_id=MICROSOFT_SOURCE_ID,
    key="microsoft-windows-security-event-4608",
    title="Microsoft Windows Security Auditing Event 4608 Documentation",
    publisher="Microsoft",
    source_class="tier-a-authoritative",
    url=MICROSOFT_URL,
    official_status="official",
    license_status="unknown",
    redistribution_policy="restricted",
    redistribution_notes="ATLAS stores independently authored normalized facts and source locators; substantial Microsoft documentation prose is not redistributed by this exemplar.",
    cadence="documentation-maintained",
    stale_after_days=180,
    strategy="content-diff",
    change_notes="Event 4608 is documented as Version 0 with an empty EventData element; changes to versioning or event-specific payload structure require controlled re-review.",
))
write_json(uws_path, source_record(
    source_id=UWS_SOURCE_ID,
    key="ultimate-windows-security-event-4608",
    title="Ultimate Windows Security — Windows Security Log Event ID 4608",
    publisher="Monterey Technology Group, Inc.",
    source_class="tier-c-secondary-research",
    url=UWS_URL,
    official_status="secondary-reference",
    license_status="restricted",
    redistribution_policy="prohibited",
    redistribution_notes="External analyst-reference and coverage benchmark only. ATLAS does not package substantial page prose/examples without explicit permission from the rights holder.",
    cadence="web-reference",
    stale_after_days=90,
    strategy="manual",
    change_notes="No automated or bulk ingestion is authorized. Review remains controlled under the ATLAS source-authority policy.",
))

snapshot = read_json(SNAPSHOT)
by_id = {item["event_id"]: item for item in snapshot["events"]}
row = by_id.get(EVENT_ID)
if not row or row["coverage_state"] != "IDENTIFIED_PROVIDER_SCOPE" or row["counts_toward_release_coverage"] is not False:
    raise SystemExit("Event 4608 is not an uncovered member of the frozen denominator")
row["coverage_state"] = "ENCYCLOPEDIA_GRADE"
row["counts_toward_release_coverage"] = True
row["canonical_id"] = EVENT_CANONICAL_ID
snapshot["encyclopedia_grade_count"] = 10
snapshot["remaining_count"] = 413
snapshot["completion_ratio"] = "10/423"
snapshot["completion_percent"] = 2.36
write_json(SNAPSHOT, snapshot)

manifest = read_json(MANIFEST)
windows = next(item for item in manifest["families"] if item["id"] == "windows-security-auditing")
if windows["denominator_count"] != 423 or windows["encyclopedia_grade_count"] != 9 or windows["remaining_count"] != 414:
    raise SystemExit("coverage manifest drifted before Event 4608 promotion")
windows["encyclopedia_grade_count"] = 10
windows["remaining_count"] = 413
manifest["as_of"] = "2026-10-05"
write_json(MANIFEST, manifest)

snapshot_test = TEST_SNAPSHOT.read_text(encoding="utf-8")
for old, new in [
    ('assert snapshot["encyclopedia_grade_count"] == 9', 'assert snapshot["encyclopedia_grade_count"] == 10'),
    ('assert snapshot["remaining_count"] == 414', 'assert snapshot["remaining_count"] == 413'),
    ('assert snapshot["completion_ratio"] == "9/423"', 'assert snapshot["completion_ratio"] == "10/423"'),
    ('assert snapshot["completion_percent"] == 2.13', 'assert snapshot["completion_percent"] == 2.36'),
    ('for event_id in ("4624", "4625", "4648", "4672", "4688", "4740", "4768", "4769", "4771"):',
     'for event_id in ("4608", "4624", "4625", "4648", "4672", "4688", "4740", "4768", "4769", "4771"):'),
]:
    if old not in snapshot_test:
        raise SystemExit(f"snapshot test anchor missing: {old}")
    snapshot_test = snapshot_test.replace(old, new, 1)
TEST_SNAPSHOT.write_text(snapshot_test, encoding="utf-8")

queue_test = TEST_QUEUE.read_text(encoding="utf-8")
old_queue = '    altered = copy.deepcopy(snapshot)\n    altered["events"][0]["coverage_state"] = "ENCYCLOPEDIA_GRADE"\n'
new_queue = ('    altered = copy.deepcopy(snapshot)\n'
             '    first_uncovered = next(item for item in altered["events"] if not item["counts_toward_release_coverage"])\n'
             '    first_uncovered["coverage_state"] = "ENCYCLOPEDIA_GRADE"\n')
if old_queue not in queue_test:
    raise SystemExit("queue test stale-state anchor missing")
TEST_QUEUE.write_text(queue_test.replace(old_queue, new_queue, 1), encoding="utf-8")

content_test = TEST_CONTENT.read_text(encoding="utf-8")
anchor = '    assert validator.resolve_query(records, "4624") == ["atlas:event:microsoft.windows.security:4624"]\n'
addition = ('    assert validator.resolve_query(records, "4608") == ["atlas:event:microsoft.windows.security:4608"]\n'
            '    assert validator.resolve_query(records, "Windows startup") == ["atlas:event:microsoft.windows.security:4608"]\n')
if anchor not in content_test:
    raise SystemExit("approved-content search anchor missing")
content_test = content_test.replace(anchor, addition + anchor, 1)
fn_anchor = '\ndef test_04_windows_4624_field_dictionary_matches_approved_exemplar():\n'
fn = '''\ndef test_03b_windows_4608_fieldless_shape_and_uws_boundary():\n    records = by_id(records_with_paths())\n    prefix = "atlas:field:microsoft.windows.security:4608."\n    assert not any(key.startswith(prefix) for key in records)\n    event = records["atlas:event:microsoft.windows.security:4608"]\n    assert event["native_identifiers"][0]["value"] == "4608"\n    source = records["atlas:source:atlas.source:ultimate-windows-security-event-4608"]\n    assert source["redistribution"]["policy"] == "prohibited"\n    uws_claims = [\n        r for r in records.values()\n        if r.get("record_kind") == "claim"\n        and r.get("subject_id") == "atlas:event:microsoft.windows.security:4608"\n        and r.get("predicate") == "telemetry.source"\n        and any(e.get("source_id") == source["id"] for e in r.get("evidence", []))\n    ]\n    assert len(uws_claims) == 1\n    assert uws_claims[0]["object"]["value"]["redistribution"] == "source-link-and-coverage-benchmark-only"\n\n'''
if fn_anchor not in content_test:
    raise SystemExit("approved-content function anchor missing")
TEST_CONTENT.write_text(content_test.replace(fn_anchor, fn + fn_anchor, 1), encoding="utf-8")

redist = read_json(REDIST)
ms = next(item for item in redist if item.get("id") == "microsoft-windows-security-documentation") if isinstance(redist, list) else next(item for item in redist["entries"] if item.get("id") == "microsoft-windows-security-documentation")
if "4608" not in ms["upstream_revision"]:
    ms["upstream_revision"] = ms["upstream_revision"].replace("Event 4624", "Event 4608, 4624", 1)
if "microsoft-windows-security-event-4608.json" not in ms["review_evidence"]:
    ms["review_evidence"] = ms["review_evidence"].replace(
        "content/encyclopedia/sources/microsoft-windows-security-event-4624.json",
        "content/encyclopedia/sources/microsoft-windows-security-event-4608.json + content/encyclopedia/sources/microsoft-windows-security-event-4624.json",
        1,
    )
write_json(REDIST, redist)

print("event_4608_applied=true")
