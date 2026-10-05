#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "tools/content/validate_encyclopedia_coverage.py"
text = PATH.read_text(encoding="utf-8")
old = '''    for family_id, expected in {
        "windows-security-auditing": (423, 2, 421),
        "sysmon": (30, 30, 0),
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
'''
new = '''    for family_id, expected_denominator in {
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
'''
if old not in text:
    raise SystemExit("stale hard-coded coverage validator block not found")
PATH.write_text(text.replace(old, new, 1), encoding="utf-8")
print("dynamic_coverage_validator_applied=true")
