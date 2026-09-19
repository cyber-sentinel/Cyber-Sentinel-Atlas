#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "content" / "encyclopedia" / "coverage-manifest.json"

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

    for family_id, expected in {
        "windows-security-auditing": (423, 2, 421),
        "sysmon": (30, 7, 23),
    }.items():
        family = by_id[family_id]
        snapshot_path = family.get("snapshot")
        if not snapshot_path:
            errors.append(f"{family_id}: snapshot path missing")
            continue
        snapshot = load(ROOT / snapshot_path)
        actual = (
            snapshot.get("denominator_count"),
            snapshot.get("encyclopedia_grade_count"),
            snapshot.get("remaining_count"),
        )
        if actual != expected:
            errors.append(f"{family_id}: snapshot counts {actual} != expected {expected}")
        declared = (
            family.get("denominator_count"),
            family.get("encyclopedia_grade_count"),
            family.get("remaining_count"),
        )
        if declared != actual:
            errors.append(f"{family_id}: manifest/snapshot count mismatch")

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
    print(
        "ATLAS coverage manifest PASSED: "
        f"Windows Security={by_id['windows-security-auditing']['encyclopedia_grade_count']}/"
        f"{by_id['windows-security-auditing']['denominator_count']}; "
        f"Sysmon={by_id['sysmon']['encyclopedia_grade_count']}/"
        f"{by_id['sysmon']['denominator_count']}; "
        "global Windows denominator=UNFROZEN."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
