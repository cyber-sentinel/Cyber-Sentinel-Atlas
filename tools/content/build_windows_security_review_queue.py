#!/usr/bin/env python3
"""Plan bounded Windows Security content-review batches from the frozen ledger.

This is a planning artifact, not a content promotion or a second task registry.
Only the approved-exemplar/coverage pipeline may advance release coverage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = ROOT / "content/encyclopedia/windows-security-auditing-26100.33296-coverage.snapshot.json"
MANIFEST = ROOT / "content/encyclopedia/coverage-manifest.json"


def _read_json(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def build_queue(batch_size: int = 10, *, snapshot_path: Path = SNAPSHOT,
                manifest_path: Path = MANIFEST) -> dict[str, Any]:
    if not 1 <= batch_size <= 25:
        raise ValueError("batch_size must be between 1 and 25")
    snapshot, snapshot_sha256 = _read_json(snapshot_path)
    manifest, _ = _read_json(manifest_path)
    families = [family for family in manifest["families"] if family["id"] == "windows-security-auditing"]
    if len(families) != 1:
        raise ValueError("exactly one Windows Security family is required")
    family = families[0]
    if (snapshot["provider"] != "Microsoft-Windows-Security-Auditing"
            or snapshot["channel"] != "Security"
            or snapshot["reference_scope"]["windows_build"] != "26100.33296"
            or family["snapshot"] != SNAPSHOT.relative_to(ROOT).as_posix()):
        raise ValueError("Windows Security scope differs from the frozen denominator")
    if any(family[key] != snapshot[key] for key in (
            "denominator_count", "encyclopedia_grade_count", "remaining_count")):
        raise ValueError("coverage manifest and snapshot disagree")

    events = snapshot["events"]
    ids = [event["event_id"] for event in events]
    if (len(events) != snapshot["denominator_count"]
            or len(ids) != len(set(ids))
            or any(not event_id.isdecimal() for event_id in ids)):
        raise ValueError("Windows Security denominator has missing, duplicate, or invalid IDs")
    allowed_states = {
        "IDENTIFIED_PROVIDER_SCOPE": False,
        "IDENTIFIED": False,
        "STRUCTURED": False,
        "SEMANTIC": False,
        "PROVENANCE_VERIFIED": False,
        "ENCYCLOPEDIA_GRADE": True,
    }
    if any(event.get("counts_toward_release_coverage") is not allowed_states.get(event.get("coverage_state"))
           or event.get("canonical_id") != f"atlas:event:microsoft.windows.security:{event['event_id']}"
           for event in events):
        raise ValueError("unexpected coverage state or canonical identity")
    covered = sum(event["counts_toward_release_coverage"] for event in events)
    if (covered != snapshot["encyclopedia_grade_count"]
            or len(events) - covered != snapshot["remaining_count"]):
        raise ValueError("Windows Security coverage counters disagree")

    remaining = sorted((event["event_id"] for event in events
                        if not event["counts_toward_release_coverage"]), key=int)
    batches = [{
        "batch_index": offset // batch_size,
        "event_ids": remaining[offset:offset + batch_size],
    } for offset in range(0, len(remaining), batch_size)]
    return {
        "schema": "atlas/windows-security-review-queue/v1",
        "purpose": "planning-only; no promotion or execution authority",
        "inventory_id": snapshot["inventory_id"],
        "inventory_digest": snapshot["inventory_digest"],
        "snapshot_sha256": snapshot_sha256,
        "denominator_count": len(events),
        "encyclopedia_grade_count": covered,
        "remaining_count": len(remaining),
        "batch_size": batch_size,
        "batch_count": len(batches),
        "batches": batches,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--batch-index", type=int)
    args = parser.parse_args()
    queue = build_queue(args.batch_size)
    if args.batch_index is not None:
        if not 0 <= args.batch_index < queue["batch_count"]:
            parser.error("batch-index is outside the review queue")
        queue["batches"] = [queue["batches"][args.batch_index]]
    print(json.dumps(queue, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
