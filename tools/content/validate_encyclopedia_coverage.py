#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "content" / "encyclopedia" / "coverage-manifest.json"
SYSMON_CATALOG = ROOT / "content" / "encyclopedia" / "sysmon-15.22-event-catalog.json"
EXEMPLARS = ROOT / "content" / "encyclopedia" / "approved-exemplars.json"

REQUIRED_FAMILIES = {
    "windows-security-auditing",
    "sysmon",
    "powershell-operational",
    "windows-defender",
    "applocker",
    "wmi-activity",
    "task-scheduler-operational",
    "rdp-terminal-services",
    "windows-firewall-filtering-platform",
    "dns",
    "service-persistence",
}


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def validate() -> list[str]:
    errors: list[str] = []
    manifest = load(MANIFEST)
    catalog = load(SYSMON_CATALOG)
    exemplars = load(EXEMPLARS)

    if manifest.get("coverage_contract_version") != "1.0.0":
        errors.append("unexpected coverage contract version")
    if manifest.get("overall_state") != "IN_PROGRESS":
        errors.append("coverage ledger must remain IN_PROGRESS until all declared denominators and acceptance levels close")

    sysmon = manifest.get("sysmon", {})
    authority = sysmon.get("semantic_authority", {})
    catalog_ids = [str(item["id"]) for item in catalog.get("events", [])]
    declared_ids = [str(value) for value in authority.get("documented_event_ids", [])]
    if authority.get("product_version") != "15.22":
        errors.append("Sysmon semantic authority must be 15.22")
    if len(declared_ids) != 30 or authority.get("documented_event_count") != 30:
        errors.append("Sysmon 15.22 documented denominator must contain exactly 30 identities")
    if declared_ids != catalog_ids:
        errors.append("Sysmon coverage denominator does not exactly match the pinned 15.22 event catalog")

    events = sysmon.get("events", {})
    if set(events) != set(declared_ids):
        errors.append("Sysmon coverage ledger must classify every documented Event ID exactly once")
    if events.get("3", {}).get("content_state") != "ENCYCLOPEDIA_GRADE":
        errors.append("Sysmon Event 3 must remain encyclopedia-grade")
    if events.get("3", {}).get("engineering_pack_state") != "PACK_VERIFIED":
        errors.append("Sysmon Event 3 must remain engineering-pack verified")
    if events.get("1", {}).get("engineering_pack_state") != "PACK_VERIFIED":
        errors.append("Sysmon Event 1 must remain engineering-pack verified")
    if any(
        data.get("content_state") == "ENCYCLOPEDIA_GRADE" and event_id != "3"
        for event_id, data in events.items()
    ):
        errors.append("Sysmon ledger must not overclaim encyclopedia-grade completion beyond approved Event 3")

    schema = sysmon.get("telemetry_schema_denominator", {})
    if schema.get("controlled_reference_product_version") != "15.21":
        errors.append("controlled Sysmon schema baseline must remain 15.21 until reviewed 15.22 export replaces it")
    if schema.get("refresh_state") != "PENDING_CONTROLLED_15_22_REFERENCE_EXPORT":
        errors.append("Sysmon schema refresh state must remain explicit and fail-closed")

    windows = manifest.get("windows_security", {})
    if windows.get("controlled_provider_reference", {}).get("unique_event_id_count") != 423:
        errors.append("Windows controlled provider denominator must remain 423 for build 26100.33296")
    windows_events = windows.get("events", {})
    if windows_events.get("4624", {}).get("content_state") != "ENCYCLOPEDIA_GRADE":
        errors.append("Windows Event 4624 must remain encyclopedia-grade")
    if windows_events.get("4624", {}).get("engineering_pack_state") != "PACK_VERIFIED":
        errors.append("Windows Event 4624 must remain engineering-pack verified")
    if windows_events.get("4688", {}).get("content_state") == "ENCYCLOPEDIA_GRADE":
        errors.append("Windows Event 4688 must not be marked encyclopedia-grade before its approved expansion is materialized")
    if windows_events.get("4688", {}).get("upgrade_state") != "ENCYCLOPEDIA_EXPANSION_REQUIRED":
        errors.append("Windows Event 4688 expansion requirement must remain explicit")

    exemplar_ids = {item["id"] for item in exemplars.get("events", [])}
    expected_exemplars = {
        "atlas:event:microsoft.sysmon:3",
        "atlas:event:microsoft.windows.security:4624",
    }
    if exemplar_ids != expected_exemplars:
        errors.append("coverage ledger assumes exactly the two maintainer-approved production exemplars")

    families = {item.get("id") for item in manifest.get("mandatory_provider_families", [])}
    if families != REQUIRED_FAMILIES:
        errors.append("mandatory provider-family set drifted from the maintainer-approved corpus scope")
    for item in manifest.get("mandatory_provider_families", []):
        if item.get("id") not in {"windows-security-auditing", "sysmon"} and item.get("state") != "DENOMINATOR_NOT_FROZEN":
            errors.append(f"{item.get('id')}: denominator must not be claimed frozen before source-specific evidence exists")

    return errors


def main() -> int:
    errors = validate()
    if errors:
        print("\n".join(errors))
        return 1
    manifest = load(MANIFEST)
    sysmon = manifest["sysmon"]
    windows = manifest["windows_security"]
    print(
        "ATLAS encyclopedia coverage ledger PASSED: "
        f"Sysmon={len(sysmon['events'])}/30 classified, "
        "Sysmon encyclopedia-grade=1, "
        f"Windows controlled denominator={windows['controlled_provider_reference']['unique_event_id_count']}, "
        "Windows encyclopedia-grade=1."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
