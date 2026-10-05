from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVENT_ID = "4769"
FIXED_TIME = "2026-10-05T09:00:00Z"
EVENT_LIST_OLD = "`4624`, `4625`, `4648`, `4672`, `4688`, `4740`, `4768`, `4771`"
EVENT_LIST_NEW = "`4624`, `4625`, `4648`, `4672`, `4688`, `4740`, `4768`, `4769`, `4771`"


def load_json(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def write_json(path: str, value):
    (ROOT / path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def replace_once(path: str, old: str, new: str):
    p = ROOT / path
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one occurrence, found {count}: {old[:120]!r}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


def replace_all_if_present(path: str, old: str, new: str):
    p = ROOT / path
    text = p.read_text(encoding="utf-8")
    if old in text:
        p.write_text(text.replace(old, new), encoding="utf-8")


def replace_regex_once(path: str, pattern: str, replacement: str):
    p = ROOT / path
    text = p.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.M)
    if count != 1:
        raise SystemExit(f"{path}: expected one regex match, found {count}: {pattern}")
    p.write_text(updated, encoding="utf-8")


microsoft_source = {
    "schema_version": "1.0.0",
    "record_kind": "source",
    "id": "atlas:source:atlas.source:microsoft-windows-security-event-4769",
    "record_revision": 1,
    "created_at": FIXED_TIME,
    "updated_at": FIXED_TIME,
    "curation_status": "validated",
    "namespace": "atlas.source",
    "canonical_key": "microsoft-windows-security-event-4769",
    "title": "Microsoft Windows Security Auditing Event 4769 Documentation",
    "publisher": "Microsoft",
    "source_class": "tier-a-authoritative",
    "canonical_urls": [
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769"
    ],
    "official_status": "official",
    "license": {"status": "unknown"},
    "redistribution": {
        "policy": "restricted",
        "notes": "ATLAS stores independently authored normalized facts and source locators; substantial Microsoft documentation prose is not redistributed by this exemplar.",
    },
    "freshness_policy": {
        "expected_update_cadence": "documentation-maintained",
        "stale_after_days": 180,
    },
    "change_detection_policy": {
        "strategy": "content-diff",
        "notes": "Event 4769 has a legacy Version 0 shape and an updated Version 2 shape on supported post-January-2025 Windows Server builds; both are modeled explicitly.",
    },
}

uws_source = {
    "schema_version": "1.0.0",
    "record_kind": "source",
    "id": "atlas:source:atlas.source:ultimate-windows-security-event-4769",
    "record_revision": 1,
    "created_at": FIXED_TIME,
    "updated_at": FIXED_TIME,
    "curation_status": "validated",
    "namespace": "atlas.source",
    "canonical_key": "ultimate-windows-security-event-4769",
    "title": "Ultimate Windows Security — Windows Security Log Event ID 4769",
    "publisher": "Monterey Technology Group, Inc.",
    "source_class": "tier-c-secondary-research",
    "canonical_urls": [
        "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4769"
    ],
    "official_status": "secondary-reference",
    "license": {"status": "restricted"},
    "redistribution": {
        "policy": "prohibited",
        "notes": "External analyst-reference and coverage benchmark only. ATLAS does not package substantial page prose/examples without explicit permission from the rights holder.",
    },
    "freshness_policy": {
        "expected_update_cadence": "web-reference",
        "stale_after_days": 90,
    },
    "change_detection_policy": {
        "strategy": "manual",
        "notes": "No automated or bulk ingestion is authorized. Review remains human-controlled under the ATLAS source-authority policy.",
    },
}

EVENT = {
    "id": "atlas:event:microsoft.windows.security:4769",
    "namespace": "microsoft.windows.security",
    "canonical_key": "4769",
    "title": "Windows Security Event 4769 — A Kerberos service ticket was requested",
    "provider": "Microsoft-Windows-Security-Auditing",
    "channel": "Security",
    "product": "Windows Security Auditing",
    "platform": "Windows",
    "native_event_id": "4769",
    "aliases": [
        "4769",
        "Event ID 4769",
        "Windows 4769",
        "Kerberos TGS requested",
        "A Kerberos service ticket was requested",
    ],
    "lifecycle": "current",
    "source_id": "atlas:source:atlas.source:microsoft-windows-security-event-4769",
    "source_version": "event-4769-v0-v2-doc",
    "source_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769",
    "source_locator": "4769(S, F): A Kerberos service ticket was requested",
    "external_reference": {
        "source_id": "atlas:source:atlas.source:ultimate-windows-security-event-4769",
        "url": "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4769",
        "role": "PRIMARY_EXTERNAL_QUICK_DETAIL_REFERENCE",
        "redistribution": "source-link-and-coverage-benchmark-only",
    },
    "overview": {
        "summary": "Records a Kerberos Ticket Granting Service (TGS) service-ticket request on a domain controller, including requesting account, target service, network origin, result and ticket cryptography plus Version 2 encryption-capability and request/response-ticket hash context.",
        "category": "Account Logon",
        "subcategory": "Audit Kerberos Service Ticket Operations",
        "event_type": "Success/Failure",
        "minimum_supported_generation": "Windows Server 2008",
        "event_versions": [
            {
                "version": "0",
                "generation": "Windows Server 2008 and later legacy shape",
                "field_count": 11,
                "notes": "Legacy Event 4769 structure with account, service, network, ticket options/encryption, result, Logon GUID and transited-services fields.",
            },
            {
                "version": "2",
                "generation": "Windows Server 2016 and later after January 14, 2025 or later Security Cumulative Update",
                "field_count": 21,
                "notes": "Updated Event 4769 adds request/response ticket hashes plus account/service/domain-controller encryption capability, client-advertised etype and session-key encryption fields.",
            },
        ],
    },
    "collection": {
        "requirements": [
            "Audit Kerberos Service Ticket Operations success/failure auditing must be enabled on domain controllers where this telemetry is required.",
            "Collection and normalization must preserve Event.Version because Version 2 contains security-relevant cryptographic capability and ticket-hash fields absent from the legacy Version 0 event.",
        ],
        "interpretation_note": "Event 4769 is high-volume domain-controller Kerberos service-ticket telemetry. Failure Code 0x0 represents successful ticket issuance; non-zero values represent failures. Microsoft notes that 0x20 ticket-expiration failures are commonly informational, so result code, account, service, client and encryption context must be evaluated together.",
        "scope_note": "Microsoft documents Event 4769 as generated only on Active Directory domain controllers.",
    },
    "correlations": [
        {
            "target": "4768",
            "key": "Account Name + Client Address + host/time",
            "purpose": "follow Kerberos TGT issuance into subsequent service-ticket requests",
        },
        {
            "target": "4624",
            "key": "Logon GUID",
            "purpose": "correlate service-ticket activity with the resulting logon session on the accessed system when the GUID is populated",
        },
        {
            "target": "4648 / 4964",
            "key": "Logon GUID",
            "purpose": "pivot to explicit-credential or special-group logon context when those events contain the same GUID",
        },
        {
            "target": "service endpoint telemetry",
            "key": "Service Name + Client Address + time",
            "purpose": "corroborate access to the requested Kerberos service with endpoint/network observations",
        },
        {
            "target": "4740 / authentication failures",
            "key": "Account Name + time",
            "purpose": "place repeated failed service-ticket activity in broader account/authentication context",
        },
    ],
    "analysis": [
        "Investigate service tickets using DES or RC4 where account, service, domain-controller and client capability context indicates AES should normally be available; distinguish compatibility requirements from an actual downgrade.",
        "Prioritize unusual or bursty requests for high-value service principals, uncommon Service Name values and anomalous client origins; repeated service-ticket requests can support Kerberoasting hypotheses only when surrounding identity and service context also aligns.",
        "Use Logon GUID to pivot to 4624, 4648 and 4964 when populated, while treating an all-zero or absent GUID as a correlation limitation rather than missing proof.",
        "Treat Version 0 and Version 2 separately in analytics: absence of Version 2 capability/hash fields on a legacy event is not missing telemetry, and common 0x20 ticket-expiration failures should not be elevated without additional evidence.",
    ],
    "value_dictionaries": {
        "result_code": [
            {"value": "0x0", "meaning": "KDC_ERR_NONE — service-ticket request completed without an error."},
            {"value": "0x6", "meaning": "KDC_ERR_C_PRINCIPAL_UNKNOWN — client principal/account was not found in the Kerberos database."},
            {"value": "0x7", "meaning": "KDC_ERR_S_PRINCIPAL_UNKNOWN — requested server/service principal was not found."},
            {"value": "0xC", "meaning": "KDC_ERR_POLICY — request was rejected by KDC policy."},
            {"value": "0xD", "meaning": "KDC_ERR_BADOPTION — KDC cannot accommodate the requested option."},
            {"value": "0xE", "meaning": "KDC_ERR_ETYPE_NOTSUPP — requested encryption type is not supported."},
            {"value": "0x12", "meaning": "KDC_ERR_CLIENT_REVOKED — client credentials are revoked or otherwise restricted."},
            {"value": "0x13", "meaning": "KDC_ERR_SERVICE_REVOKED — credentials for the requested service are revoked."},
            {"value": "0x17", "meaning": "KDC_ERR_KEY_EXPIRED — password/key is expired."},
            {"value": "0x20", "meaning": "KRB_AP_ERR_TKT_EXPIRED — presented ticket has expired; Microsoft notes this is commonly informational."},
            {"value": "0x21", "meaning": "KRB_AP_ERR_TKT_NYV — ticket is not yet valid."},
            {"value": "0x22", "meaning": "KRB_AP_ERR_REPEAT — replay was detected."},
            {"value": "0x25", "meaning": "KRB_AP_ERR_SKEW — clock skew is too great."},
            {"value": "0x29", "meaning": "KRB_AP_ERR_MODIFIED — message integrity/checksum did not match."},
        ],
        "encryption_type": [
            {"value": "0x1", "meaning": "DES-CBC-CRC — legacy DES; disabled by default on modern Windows."},
            {"value": "0x3", "meaning": "DES-CBC-MD5 — legacy DES; disabled by default on modern Windows."},
            {"value": "0x11", "meaning": "AES128-CTS-HMAC-SHA1-96."},
            {"value": "0x12", "meaning": "AES256-CTS-HMAC-SHA1-96."},
            {"value": "0x17", "meaning": "RC4-HMAC."},
            {"value": "0x18", "meaning": "RC4-HMAC-EXP."},
            {"value": "0xFFFFFFFF", "meaning": "Failure placeholder/no issued ticket encryption type."},
        ],
        "ticket_options_common": [
            {"value": "0x40810010", "meaning": "Common combination: Forwardable, Renewable, Canonicalize, Renewable-ok."},
            {"value": "0x40810000", "meaning": "Common combination: Forwardable, Renewable, Canonicalize."},
            {"value": "0x60810010", "meaning": "Common combination: Forwardable, Forwarded, Renewable, Canonicalize, Renewable-ok."},
        ],
    },
    "fields": [
        {"key": "account-information.account-name", "section": "Account Information", "native_name": "Account Name", "type": "UnicodeString", "meaning": "Account principal that requested the service ticket."},
        {"key": "account-information.account-domain", "section": "Account Information", "native_name": "Account Domain", "type": "UnicodeString", "meaning": "Kerberos realm/domain associated with the requesting account."},
        {"key": "account-information.logon-guid", "section": "Account Information", "native_name": "Logon GUID", "type": "GUID", "meaning": "Correlation GUID that can link the domain-controller ticket request to logon/security events on the accessed system when populated.", "correlation": "Use with 4624, 4648 and 4964 when the same non-zero GUID is present."},
        {"key": "account-information.msds-supported-encryption-types", "section": "Account Information", "native_name": "MSDS-SupportedEncryptionTypes", "type": "UnicodeString", "meaning": "Version 2 field: encryption types supported/configured for the requesting account in Active Directory.", "versions": ["2"]},
        {"key": "account-information.available-keys", "section": "Account Information", "native_name": "Available Keys", "type": "UnicodeString", "meaning": "Version 2 field: Kerberos keys available for the requesting account.", "versions": ["2"]},
        {"key": "service-information.service-name", "section": "Service Information", "native_name": "Service Name", "type": "UnicodeString", "meaning": "Account/computer service principal for which the Kerberos service ticket was requested."},
        {"key": "service-information.service-id", "section": "Service Information", "native_name": "Service ID", "type": "SID", "meaning": "SID of the account/computer object for the requested service; failure events can contain NULL SID."},
        {"key": "service-information.msds-supported-encryption-types", "section": "Service Information", "native_name": "MSDS-SupportedEncryptionTypes", "type": "UnicodeString", "meaning": "Version 2 field: encryption types supported by the Active Directory account on which the requested service is registered.", "versions": ["2"]},
        {"key": "service-information.available-keys", "section": "Service Information", "native_name": "Available Keys", "type": "UnicodeString", "meaning": "Version 2 field: Kerberos keys available for the service account.", "versions": ["2"]},
        {"key": "domain-controller-information.msds-supported-encryption-types", "section": "Domain Controller Information", "native_name": "MSDS-SupportedEncryptionTypes", "type": "UnicodeString", "meaning": "Version 2 field: encryption types supported by the issuing domain controller.", "versions": ["2"]},
        {"key": "domain-controller-information.available-keys", "section": "Domain Controller Information", "native_name": "Available Keys", "type": "UnicodeString", "meaning": "Version 2 field: Kerberos keys available to the issuing domain controller.", "versions": ["2"]},
        {"key": "network-information.client-address", "section": "Network Information", "native_name": "Client Address", "type": "UnicodeString/IP", "meaning": "IP address from which the TGS request reached the domain controller."},
        {"key": "network-information.client-port", "section": "Network Information", "native_name": "Client Port", "type": "UnicodeString/port", "meaning": "Source port of the client Kerberos connection; zero can represent localhost."},
        {"key": "network-information.advertized-etypes", "section": "Network Information", "native_name": "Advertized Etypes", "type": "UnicodeString", "meaning": "Version 2 field: encryption types advertised by the Kerberos client.", "versions": ["2"]},
        {"key": "additional-information.ticket-options", "section": "Additional Information", "native_name": "Ticket Options", "type": "HexInt32", "meaning": "Kerberos ticket-option bitmask requested by the client.", "values_ref": "ticket_options_common"},
        {"key": "additional-information.ticket-encryption-type", "section": "Additional Information", "native_name": "Ticket Encryption Type", "type": "HexInt32", "meaning": "Cryptographic suite used for the issued service ticket; failure events can use 0xFFFFFFFF.", "values_ref": "encryption_type"},
        {"key": "additional-information.session-encryption-type", "section": "Additional Information", "native_name": "Session Encryption Type", "type": "HexInt32", "meaning": "Version 2 field: cryptographic suite selected for the issued service-ticket session key.", "values_ref": "encryption_type", "versions": ["2"]},
        {"key": "additional-information.failure-code", "section": "Additional Information", "native_name": "Failure Code", "type": "HexInt32", "meaning": "KDC/Kerberos result code for the service-ticket request; 0x0 indicates success.", "values_ref": "result_code"},
        {"key": "additional-information.transited-services", "section": "Additional Information", "native_name": "Transited Services", "type": "UnicodeString", "meaning": "Intermediate services represented in the Kerberos delegation/transited-services context when applicable."},
        {"key": "ticket-information.request-ticket-hash", "section": "Ticket Information", "native_name": "Request ticket hash", "type": "UnicodeString", "meaning": "Version 2 field: hash associated with the Kerberos ticket request.", "versions": ["2"]},
        {"key": "ticket-information.response-ticket-hash", "section": "Ticket Information", "native_name": "Response ticket hash", "type": "UnicodeString", "meaning": "Version 2 field: hash associated with the issued Kerberos service ticket response.", "versions": ["2"]},
    ],
}


def main() -> int:
    if not (ROOT / "content/encyclopedia/approved-exemplars.json").exists():
        raise SystemExit(f"repository root resolution failed: {ROOT}")

    write_json("content/encyclopedia/sources/microsoft-windows-security-event-4769.json", microsoft_source)
    write_json("content/encyclopedia/sources/ultimate-windows-security-event-4769.json", uws_source)

    approved_path = "content/encyclopedia/approved-exemplars.json"
    approved = load_json(approved_path)
    ids = [str(item["native_event_id"]) for item in approved["events"]]
    if EVENT_ID in ids:
        raise SystemExit("Event 4769 already exists in approved exemplars")
    insert_at = ids.index("4768") + 1
    approved["events"].insert(insert_at, EVENT)
    write_json(approved_path, approved)

    manifest_path = "content/encyclopedia/coverage-manifest.json"
    manifest = load_json(manifest_path)
    manifest["as_of"] = "2026-10-05"
    win = next(item for item in manifest["families"] if item["id"] == "windows-security-auditing")
    if (win["denominator_count"], win["encyclopedia_grade_count"], win["remaining_count"]) != (423, 8, 415):
        raise SystemExit(f"unexpected coverage-manifest baseline: {win}")
    win["encyclopedia_grade_count"] = 9
    win["remaining_count"] = 414
    write_json(manifest_path, manifest)

    builder = "tools/content/build_encyclopedia_records.py"
    replace_once(builder, '    ROOT / "content" / "encyclopedia" / "sources" / "microsoft-windows-security-event-4768.json",\n    ROOT / "content" / "encyclopedia" / "sources" / "microsoft-windows-security-event-4771.json",', '    ROOT / "content" / "encyclopedia" / "sources" / "microsoft-windows-security-event-4768.json",\n    ROOT / "content" / "encyclopedia" / "sources" / "microsoft-windows-security-event-4769.json",\n    ROOT / "content" / "encyclopedia" / "sources" / "microsoft-windows-security-event-4771.json",')
    replace_once(builder, '    ROOT / "content" / "encyclopedia" / "sources" / "ultimate-windows-security-event-4768.json",\n    ROOT / "content" / "encyclopedia" / "sources" / "ultimate-windows-security-event-4771.json",', '    ROOT / "content" / "encyclopedia" / "sources" / "ultimate-windows-security-event-4768.json",\n    ROOT / "content" / "encyclopedia" / "sources" / "ultimate-windows-security-event-4769.json",\n    ROOT / "content" / "encyclopedia" / "sources" / "ultimate-windows-security-event-4771.json",')

    pack = "tools/release/build_engineering_preview_pack.py"
    replace_once(pack, '        "atlas:event:microsoft.windows.security:4768",\n        "atlas:event:microsoft.windows.security:4771",', '        "atlas:event:microsoft.windows.security:4768",\n        "atlas:event:microsoft.windows.security:4769",\n        "atlas:event:microsoft.windows.security:4771",')
    replace_once(pack, '        "contains_windows_4768": True,\n        "contains_windows_4771": True,', '        "contains_windows_4768": True,\n        "contains_windows_4769": True,\n        "contains_windows_4771": True,')

    probe = "tools/release/probe_engineering_preview.py"
    replace_once(probe, 'EXPECTED_EVENT_4768 = "atlas:event:microsoft.windows.security:4768"\nEXPECTED_EVENT_4771 = "atlas:event:microsoft.windows.security:4771"', 'EXPECTED_EVENT_4768 = "atlas:event:microsoft.windows.security:4768"\nEXPECTED_EVENT_4769 = "atlas:event:microsoft.windows.security:4769"\nEXPECTED_EVENT_4771 = "atlas:event:microsoft.windows.security:4771"')
    probe_path = ROOT / probe
    probe_text = probe_path.read_text(encoding="utf-8")
    marker = "        search_4771 = request(\n"
    if probe_text.count(marker) != 1:
        raise SystemExit("probe 4771 insertion marker drift")
    probe_block = '''        search_4769 = request(
            process.stdin,
            process.stdout,
            "q3f",
            "search.query",
            {"query": "4769", "graph_depth": 1, "limit": 10},
        )
        windows_4769_search_ok = search_contains_target(search_4769, EXPECTED_EVENT_4769)
        if not windows_4769_search_ok:
            raise RuntimeError(
                f"Windows Event 4769 was not returned by deterministic search: {search_4769}"
            )
        record_4769 = request(
            process.stdin,
            process.stdout,
            "r3f",
            "record.get",
            {"id": EXPECTED_EVENT_4769},
        )
        if record_4769.get("id") != EXPECTED_EVENT_4769:
            raise RuntimeError("Windows Event 4769 record identity mismatch")

'''
    probe_path.write_text(probe_text.replace(marker, probe_block + marker, 1), encoding="utf-8")
    replace_once(probe, '            "windows_4768_search_ok": windows_4768_search_ok,\n            "windows_4768_record_ok": True,\n            "windows_4771_search_ok": windows_4771_search_ok,', '            "windows_4768_search_ok": windows_4768_search_ok,\n            "windows_4768_record_ok": True,\n            "windows_4769_search_ok": windows_4769_search_ok,\n            "windows_4769_record_ok": True,\n            "windows_4771_search_ok": windows_4771_search_ok,')

    workflow = ".github/workflows/phase5105-usable-data-preview.yml"
    replace_once(workflow, "windows_event_4740=$true; windows_event_4768=$true; windows_event_4771=$true", "windows_event_4740=$true; windows_event_4768=$true; windows_event_4769=$true; windows_event_4771=$true")
    replace_all_if_present(workflow, "4740, 4768 and 4771", "4740, 4768, 4769 and 4771")
    replace_once(workflow, "$probe.windows_4768_record_ok -ne $true -or $probe.windows_4771_search_ok", "$probe.windows_4768_record_ok -ne $true -or $probe.windows_4769_search_ok -ne $true -or $probe.windows_4769_record_ok -ne $true -or $probe.windows_4771_search_ok")

    tests = "tests/phase51010/test_approved_exemplar_content.py"
    replace_once(tests, '    assert validator.resolve_query(records, "Kerberos TGT requested") == ["atlas:event:microsoft.windows.security:4768"]\n    assert validator.resolve_query(records, "4771")', '    assert validator.resolve_query(records, "Kerberos TGT requested") == ["atlas:event:microsoft.windows.security:4768"]\n    assert validator.resolve_query(records, "4769") == ["atlas:event:microsoft.windows.security:4769"]\n    assert validator.resolve_query(records, "Kerberos TGS requested") == ["atlas:event:microsoft.windows.security:4769"]\n    assert validator.resolve_query(records, "4771")')
    tests_path = ROOT / tests
    tests_text = tests_path.read_text(encoding="utf-8")
    marker = "def test_04h_windows_4771_field_dictionary_matches_approved_exemplar():\n"
    if tests_text.count(marker) != 1:
        raise SystemExit("approved-exemplar test insertion marker drift")
    test_block = '''def test_04n_windows_4769_field_dictionary_matches_version_aware_exemplar():
    records = by_id(records_with_paths())
    prefix = "atlas:field:microsoft.windows.security:4769."
    fields = sorted(key for key in records if key.startswith(prefix))
    assert len(fields) == 21
    required = {
        "4769.account-information.account-name",
        "4769.account-information.account-domain",
        "4769.account-information.logon-guid",
        "4769.service-information.service-name",
        "4769.service-information.service-id",
        "4769.network-information.client-address",
        "4769.network-information.client-port",
        "4769.additional-information.ticket-options",
        "4769.additional-information.ticket-encryption-type",
        "4769.additional-information.failure-code",
        "4769.additional-information.transited-services",
        "4769.ticket-information.request-ticket-hash",
        "4769.ticket-information.response-ticket-hash",
        "4769.account-information.msds-supported-encryption-types",
        "4769.account-information.available-keys",
        "4769.service-information.msds-supported-encryption-types",
        "4769.service-information.available-keys",
        "4769.domain-controller-information.msds-supported-encryption-types",
        "4769.domain-controller-information.available-keys",
        "4769.network-information.advertized-etypes",
        "4769.additional-information.session-encryption-type",
    }
    actual = {value.rsplit(":", 1)[-1] for value in fields}
    assert required == actual


def test_04o_windows_4769_versions_dictionaries_and_uws_boundary():
    records = by_id(records_with_paths())
    event = next(item for item in load_blueprint()["events"] if item["native_event_id"] == "4769")
    versions = {row["version"]: row["field_count"] for row in event["overview"]["event_versions"]}
    assert versions == {"0": 11, "2": 21}

    event_claims = [r for r in records.values() if r.get("record_kind") == "claim" and r.get("subject_id") == "atlas:event:microsoft.windows.security:4769" and r.get("predicate") == "telemetry.field-semantics"]
    dictionaries = [r["object"]["value"].get("event_value_dictionaries", {}) for r in event_claims if r.get("object", {}).get("kind") == "json"]
    result_codes = next(value["result_code"] for value in dictionaries if "result_code" in value)
    assert {"0x0", "0x6", "0x7", "0xD", "0xE", "0x12", "0x13", "0x20", "0x25"} <= {row["value"] for row in result_codes}
    etypes = next(value["encryption_type"] for value in dictionaries if "encryption_type" in value)
    assert {"0x1", "0x3", "0x11", "0x12", "0x17", "0x18", "0xFFFFFFFF"} <= {row["value"] for row in etypes}
    ticket_options = next(value["ticket_options_common"] for value in dictionaries if "ticket_options_common" in value)
    assert {"0x40810010", "0x40810000", "0x60810010"} == {row["value"] for row in ticket_options}

    v2_field_ids = {
        "4769.account-information.msds-supported-encryption-types",
        "4769.account-information.available-keys",
        "4769.service-information.msds-supported-encryption-types",
        "4769.service-information.available-keys",
        "4769.domain-controller-information.msds-supported-encryption-types",
        "4769.domain-controller-information.available-keys",
        "4769.network-information.advertized-etypes",
        "4769.additional-information.session-encryption-type",
        "4769.ticket-information.request-ticket-hash",
        "4769.ticket-information.response-ticket-hash",
    }
    for field_key in v2_field_ids:
        field_id = f"atlas:field:microsoft.windows.security:{field_key}"
        claims = [r for r in records.values() if r.get("record_kind") == "claim" and r.get("subject_id") == field_id and r.get("predicate") == "telemetry.field-semantics"]
        assert len(claims) == 1
        assert claims[0]["object"]["value"]["versions"] == ["2"]
        locators = [e["locator"]["other"] for e in claims[0]["evidence"]]
        assert any("4769(S, F)" in locator and "/" in locator for locator in locators)

    source = records["atlas:source:atlas.source:ultimate-windows-security-event-4769"]
    assert source["redistribution"]["policy"] == "prohibited"
    uws_evidence = [r for r in records.values() if r.get("record_kind") == "claim" and any(e.get("source_id") == source["id"] for e in r.get("evidence", []))]
    assert len(uws_evidence) == 1
    assert uws_evidence[0]["predicate"] == "telemetry.source"
    assert uws_evidence[0]["object"]["value"]["redistribution"] == "source-link-and-coverage-benchmark-only"


'''
    tests_path.write_text(tests_text.replace(marker, test_block + marker, 1), encoding="utf-8")
    replace_once(tests, "    assert len(field_ids) == 402\n", "    assert len(field_ids) == 423\n")

    coverage_test = "tests/phase51010/test_windows_security_coverage_snapshot.py"
    replace_once(coverage_test, '    assert snapshot["encyclopedia_grade_count"] == 8\n    assert snapshot["remaining_count"] == 415\n    assert snapshot["completion_ratio"] == "8/423"\n    assert snapshot["completion_percent"] == 1.89\n', '    assert snapshot["encyclopedia_grade_count"] == 9\n    assert snapshot["remaining_count"] == 414\n    assert snapshot["completion_ratio"] == "9/423"\n    assert snapshot["completion_percent"] == 2.13\n')
    replace_once(coverage_test, '    for event_id in ("4624", "4625", "4648", "4672", "4688", "4740", "4768", "4771"):', '    for event_id in ("4624", "4625", "4648", "4672", "4688", "4740", "4768", "4769", "4771"):')

    inventory_path = "docs/releases/third-party-redistribution-inventory.json"
    inventory = load_json(inventory_path)
    microsoft = next(item for item in inventory["items"] if item["id"] == "microsoft-windows-security-documentation")
    microsoft["upstream_revision"] = microsoft["upstream_revision"].replace("4768 and 4771", "4768, 4769 and 4771")
    microsoft["review_evidence"] = microsoft["review_evidence"].replace("content/encyclopedia/sources/microsoft-windows-security-event-4768.json + content/encyclopedia/sources/microsoft-windows-security-event-4771.json", "content/encyclopedia/sources/microsoft-windows-security-event-4768.json + content/encyclopedia/sources/microsoft-windows-security-event-4769.json + content/encyclopedia/sources/microsoft-windows-security-event-4771.json")
    write_json(inventory_path, inventory)

    for path in ["README.md", "docs/README.md", "docs/product-surfaces.md", "docs/roadmap.md", "docs/windows-sysmon-coverage-plan.md", "ingestion/connectors/README.md", "docs/releases/third-party-redistribution-closure.md"]:
        replace_all_if_present(path, EVENT_LIST_OLD, EVENT_LIST_NEW)
        replace_all_if_present(path, "`4768`, and `4771`", "`4768`, `4769`, and `4771`")
        replace_all_if_present(path, "`4768` and `4771`", "`4768`, `4769` and `4771`")
        replace_all_if_present(path, "4740, 4768 and 4771", "4740, 4768, 4769 and 4771")

    coverage_files = ["README.md", "docs/README.md", "docs/product-surfaces.md", "docs/roadmap.md", "docs/windows-sysmon-coverage-plan.md"]
    for path in coverage_files:
        p = ROOT / path
        text = p.read_text(encoding="utf-8")
        lines = []
        for line in text.splitlines(keepends=True):
            if "Windows Security" in line and ("8/423" in line or "| 8 —" in line):
                line = line.replace("8/423", "9/423").replace("| 8 —", "| 9 —").replace("415", "414")
            lines.append(line)
        p.write_text("".join(lines), encoding="utf-8")

    replace_regex_once("docs/current-status.md", r"^Status timestamp: .*?$", "Status timestamp: 2026-10-05")
    replace_regex_once("docs/current-status.md", r"^- Reviewed `main` corpus baseline: .*?$", "- Reviewed `main` corpus baseline: `9d54501bd3d7013637d7e83c9174d3f91a683aac` — PR #148 promoted Event 4768 after all nine exact-head workflows completed **SUCCESS**. Windows Security is `8/423` with `415` remaining; Sysmon remains `30/30`. This branch proposes Event 4769 as the next increment; branch coverage becomes `9/423` with `414` remaining pending review and merge.")
    replace_regex_once("docs/current-status.md", r"^  - Windows Security encyclopedia-grade: `8/423` .*?$", f"  - Windows Security encyclopedia-grade: `9/423` — Event IDs {EVENT_LIST_NEW}; remaining `414`")

    replace_regex_once("docs/project-state.md", r"^- Last Reviewed Main SHA: `[^`]+`$", "- Last Reviewed Main SHA: `6de84bf13010ca869587eaa49ef24ce5017bad07`")
    replace_regex_once("docs/project-state.md", r"^- Latest reviewed merged corpus baseline: .*?$", "- Latest reviewed merged corpus baseline: `9d54501bd3d7013637d7e83c9174d3f91a683aac` — PR #148 promoted Event 4768; Windows Security is `8/423` with `415` remaining on merged `main`. This branch proposes Event 4769 as the next encyclopedia-grade increment, producing `9/423` with `414` remaining pending review and merge; Sysmon remains `30/30`.")
    replace_regex_once("docs/project-state.md", r"^    - Windows Security encyclopedia grade: `8/423` .*?$", f"    - Windows Security encyclopedia grade: `9/423` — Event IDs {EVENT_LIST_NEW}; remaining `414`")

    subprocess.run(["python", "tools/content/build_windows_security_coverage_snapshot.py", "--output", "content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json"], cwd=ROOT, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
