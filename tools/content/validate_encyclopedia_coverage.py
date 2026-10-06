#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "content" / "encyclopedia" / "coverage-manifest.json"
APPROVED = ROOT / "content" / "encyclopedia" / "approved-exemplars.json"

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

    if manifest.get("coverage_contract_version") != "1.0.0":
        errors.append("unexpected coverage contract version")
    if manifest.get("overall_state") != "IN_PROGRESS":
        errors.append("coverage manifest must remain IN_PROGRESS until every mandatory family closes")
    if manifest.get("global_windows_denominator_frozen") is not False:
        errors.append("global Windows denominator must remain explicitly unfrozen")
    if manifest.get("global_windows_completion_percent") is not None:
        errors.append("global Windows completion percent must remain null until a legitimate global denominator exists")

    security_log_benchmark = manifest.get("windows_security_log_review_benchmark", {})
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

    families = manifest.get("families", [])
    by_id = {item.get("id"): item for item in families}
    if set(by_id) != REQUIRED_FAMILIES:
        errors.append("mandatory provider-family set drifted")

    windows = by_id.get("windows-security-auditing", {})
    sysmon = by_id.get("sysmon", {})
    if windows.get("state") != "ACTIVE_DENOMINATOR_FROZEN":
        errors.append("Windows Security-Auditing denominator must be frozen for the controlled provider/build scope")
    if sysmon.get("state") != "ACTIVE_DENOMINATOR_FROZEN":
        errors.append("Sysmon denominator must be frozen for the current 15.22 scope")

    for family_id, family in by_id.items():
        if family_id not in {"windows-security-auditing", "sysmon"}:
            if family.get("state") != "DENOMINATOR_NOT_FROZEN":
                errors.append(f"{family_id}: denominator must not be claimed frozen without source-specific evidence")

    for family_id, expected_denominator in {
        "windows-security-auditing": 423,
        "sysmon": 30,
    }.items():
        family = by_id[family_id]
        snapshot_path = family.get("snapshot")
        if not snapshot_path:
            errors.append(f"{family_id}: snapshot path missing")
            continue
        snapshot = load(ROOT / snapshot_path)
        denominator = snapshot.get("denominator_count")
        grade = snapshot.get("encyclopedia_grade_count")
        remaining = snapshot.get("remaining_count")
        actual = (denominator, grade, remaining)
        if denominator != expected_denominator:
            errors.append(
                f"{family_id}: denominator {denominator} != controlled denominator {expected_denominator}"
            )
        if not isinstance(grade, int) or not isinstance(remaining, int):
            errors.append(f"{family_id}: numerator/remaining counts must be integers")
        elif grade < 0 or remaining < 0 or grade + remaining != denominator:
            errors.append(f"{family_id}: invalid coverage arithmetic {actual}")
        declared = (
            family.get("denominator_count"),
            family.get("encyclopedia_grade_count"),
            family.get("remaining_count"),
        )
        if declared != actual:
            errors.append(f"{family_id}: manifest/snapshot count mismatch")

    sysmon_counts = (
        sysmon.get("denominator_count"),
        sysmon.get("encyclopedia_grade_count"),
        sysmon.get("remaining_count"),
    )
    if sysmon_counts != (30, 30, 0):
        errors.append(f"Sysmon controlled 15.22 scope must remain complete: {sysmon_counts}")

    windows_snapshot = load(ROOT / windows["snapshot"])
    if windows_snapshot.get("reference_scope", {}).get("windows_build") != "26100.33296":
        errors.append("Windows Security coverage snapshot reference build drifted")
    if windows_snapshot.get("provider") != "Microsoft-Windows-Security-Auditing":
        errors.append("Windows Security coverage snapshot provider drifted")

    sysmon_snapshot = load(ROOT / sysmon["snapshot"])
    if sysmon_snapshot.get("semantic_release") != "15.22":
        errors.append("Sysmon coverage snapshot semantic release drifted")
    if sysmon_snapshot.get("telemetry_schema_refresh_state") != "VALIDATED_CONTROLLED_SYSMON_15_22_REFERENCE_EXPORT":
        errors.append("Sysmon controlled schema baseline is not the promoted 15.22 reference")

    return errors


def main() -> int:
    errors = validate()
    if errors:
        print("\n".join(errors))
        return 1
    manifest = load(MANIFEST)
    by_id = {item["id"]: item for item in manifest["families"]}
    benchmark = manifest["windows_security_log_review_benchmark"]
    print(
        "ATLAS coverage manifest PASSED: "
        f"Windows Security Log review benchmark={benchmark['encyclopedia_grade_listed_id_count']}/"
        f"{benchmark['listed_unique_event_id_count']} encyclopedia-grade listed IDs "
        f"({benchmark['minimum_listed_event_id']}..{benchmark['maximum_listed_event_id']} sparse range); "
        f"Windows Security Auditing={by_id['windows-security-auditing']['encyclopedia_grade_count']}/"
        f"{by_id['windows-security-auditing']['denominator_count']}; "
        f"Sysmon={by_id['sysmon']['encyclopedia_grade_count']}/"
        f"{by_id['sysmon']['denominator_count']}; "
        "global Windows denominator=UNFROZEN."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
