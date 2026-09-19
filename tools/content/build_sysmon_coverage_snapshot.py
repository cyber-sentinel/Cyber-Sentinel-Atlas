#!/usr/bin/env python3
"""Build a deterministic Sysmon 15.22 encyclopedia coverage snapshot.

The documented Microsoft Sysinternals Event ID catalog is the denominator.
Only maintainer-approved encyclopedia-grade events count toward release coverage.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "content" / "encyclopedia" / "sysmon-15.22-event-catalog.json"
APPROVED = ROOT / "content" / "encyclopedia" / "approved-exemplars.json"
PROFILE = ROOT / "ingestion" / "source-profiles" / "microsoft-sysmon-docs.release.json"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_snapshot() -> dict[str, Any]:
    catalog = load_json(CATALOG)
    approved = load_json(APPROVED)
    profile = load_json(PROFILE)

    documented = catalog["events"]
    documented_ids = [str(item["id"]) for item in documented]
    if len(documented_ids) != len(set(documented_ids)):
        raise ValueError("duplicate Sysmon Event IDs in documentation catalog")

    expected = [str(value) for value in profile["expected_documented_event_ids"]]
    if sorted(documented_ids, key=int) != sorted(expected, key=int):
        raise ValueError("Sysmon documentation catalog/profile denominator drift")

    approved_sysmon = {
        str(item["native_event_id"]): item
        for item in approved["events"]
        if item.get("namespace") == "microsoft.sysmon"
    }

    events = []
    for item in documented:
        event_id = str(item["id"])
        exemplar = approved_sysmon.get(event_id)
        events.append({
            "event_id": event_id,
            "title": item["title"],
            "configuration_tag": item.get("tag"),
            "coverage_state": "ENCYCLOPEDIA_GRADE" if exemplar else "IDENTIFIED",
            "counts_toward_release_coverage": bool(exemplar),
            "canonical_id": exemplar["id"] if exemplar else f"atlas:event:microsoft.sysmon:{event_id}",
            "semantic_authority": "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
        })

    complete = sum(1 for item in events if item["counts_toward_release_coverage"])
    total = len(events)
    return {
        "coverage_contract_version": "1.0.0",
        "product": "Microsoft Sysinternals Sysmon",
        "semantic_release": profile["release_version"],
        "denominator_kind": "documented-event-id-catalog",
        "denominator_count": total,
        "encyclopedia_grade_count": complete,
        "remaining_count": total - complete,
        "completion_ratio": f"{complete}/{total}",
        "completion_percent": round((complete / total) * 100, 2) if total else 0.0,
        "release_numerator_rule": "Only ENCYCLopedia-grade maintainer-approved records count.",
        "telemetry_schema_refresh_state": "PENDING_CONTROLLED_SYSMON_15_22_REFERENCE_EXPORT",
        "events": events,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    snapshot = build_snapshot()
    payload = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
