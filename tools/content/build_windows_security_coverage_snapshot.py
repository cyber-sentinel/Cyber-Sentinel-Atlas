#!/usr/bin/env python3
"""Build a deterministic Windows Security-Auditing coverage snapshot.

The denominator is the controlled Microsoft-Windows-Security-Auditing /
Security provider inventory captured from Windows Server 2025 Datacenter
24H2 build 26100.33296. It is deliberately provider/channel/build scoped and
must never be presented as the denominator for all Windows telemetry.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "ingestion" / "inventories" / "windows-security-auditing-provider-26100.33296.telemetry.json"
APPROVED = ROOT / "content" / "encyclopedia" / "approved-exemplars.json"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_snapshot() -> dict[str, Any]:
    inventory = load_json(INVENTORY)
    approved = load_json(APPROVED)
    scope = inventory["scope_metadata"]

    if inventory["inventory_kind"] != "telemetry":
        raise ValueError("Windows Security denominator must come from telemetry inventory")
    if scope["provider"] != "Microsoft-Windows-Security-Auditing":
        raise ValueError("unexpected Windows Security provider")
    if scope["channel"] != "Security":
        raise ValueError("unexpected Windows Security channel")
    if scope["windows_build"] != "26100.33296":
        raise ValueError("unexpected controlled Windows reference build")

    event_ids = [str(item["event_id"]) for item in scope["expected_identities"]]
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("duplicate Event IDs in Windows Security provider inventory")
    if len(event_ids) != inventory["expected_identity_count"]:
        raise ValueError("Windows Security inventory identity-count drift")
    if len(event_ids) != scope["provider_unique_event_id_count"]:
        raise ValueError("Windows Security provider unique-ID count drift")

    approved_windows = {
        str(item["native_event_id"]): item
        for item in approved["events"]
        if item.get("namespace") == "microsoft.windows.security"
    }
    unknown = sorted(set(approved_windows) - set(event_ids), key=int)
    if unknown:
        raise ValueError(f"approved Windows exemplars outside controlled denominator: {unknown}")

    events = []
    for event_id in sorted(event_ids, key=int):
        exemplar = approved_windows.get(event_id)
        events.append({
            "event_id": event_id,
            "coverage_state": "ENCYCLOPEDIA_GRADE" if exemplar else "IDENTIFIED_PROVIDER_SCOPE",
            "counts_toward_release_coverage": bool(exemplar),
            "canonical_id": exemplar["id"] if exemplar else f"atlas:event:microsoft.windows.security:{event_id}",
        })

    complete = sum(1 for item in events if item["counts_toward_release_coverage"])
    total = len(events)
    return {
        "coverage_contract_version": "1.0.0",
        "product": "Windows Security Auditing",
        "provider": scope["provider"],
        "channel": scope["channel"],
        "reference_scope": {
            "product": scope["product"],
            "windows_version": scope["windows_version"],
            "windows_build": scope["windows_build"],
            "architecture": scope["architecture"],
            "locale": scope["locale"],
        },
        "inventory_id": inventory["inventory_id"],
        "inventory_digest": inventory["digest"],
        "psr_representation_digest": scope["psr_representation_digest"],
        "raw_artifact_sha256": scope["raw_artifact_sha256"],
        "denominator_kind": "controlled-provider-manifest-unique-event-id",
        "denominator_count": total,
        "provider_event_version_definition_count": scope["provider_event_version_definition_count"],
        "encyclopedia_grade_count": complete,
        "remaining_count": total - complete,
        "completion_ratio": f"{complete}/{total}",
        "completion_percent": round((complete / total) * 100, 2) if total else 0.0,
        "release_numerator_rule": "Only ENCYCLOPEDIA_GRADE maintainer-approved records count.",
        "legacy_semantics": (
            "This denominator is exact for Microsoft-Windows-Security-Auditing / Security "
            "on Windows Server 2025 Datacenter 24H2 build 26100.33296. Absence of historical "
            "Event ID 592 does not remove its independently preserved legacy canonical identity "
            "and does not imply completeness across other Windows builds/providers/channels."
        ),
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
