#!/usr/bin/env python3
"""Build the MVP-2 private pack with clean analyst-facing projections.

The general engineering-preview builder intentionally preserves historical test
fixtures for old regression paths. MVP-2 must instead present the governed
encyclopedia projection. This adapter therefore:

1. removes the explicitly superseded Phase-5.2 4688 demonstration field;
2. includes the frozen PowerShell Operational canonical family; and
3. overlays a small, governed set of independently-authored sanitized analyst
   examples onto the existing ``telemetry.represents`` overview claims.

The examples are content, not UI hard-codes. They remain source-backed through
the original overview evidence, are regenerated as deterministic canonical
claims, and are explicitly marked in their governance file as synthetic,
documentation-only examples.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

from tools.content import build_encyclopedia_records as encyclopedia
from tools.content.build_powershell_operational_records import build_records as build_powershell_operational_records
from tools.release import build_engineering_preview_pack as base

ROOT = Path(__file__).resolve().parents[2]
ANALYST_EXAMPLES = ROOT / "content" / "encyclopedia" / "mvp2-analyst-examples.json"
EXPECTED_EXAMPLE_SUBJECTS = frozenset({
    "atlas:event:microsoft.windows.security:4624",
    "atlas:event:microsoft.windows.security:4688",
    "atlas:event:microsoft.sysmon:1",
})
EXPECTED_POWERSHELL_EVENT_IDS = frozenset({
    "4100","4101","4102","4103","4104","4105","4106","8193","8194","8195","8196","8197","8198",
    "12039","24577","24578","24579","24580","24581","24582","24583","24584","24592","24593","24594",
    "24595","24596","24597","24598","24599","32777","32784","40961","40962","46358","53249","53250",
    "53251","53504","53505","53506","53507","53508",
})

# These three repository-owned Phase-5.2 support records represented a single
# early 4688 demonstration field. They are superseded by the complete governed
# 4688 encyclopedia dictionary and must not leak into the analyst-facing MVP-2
# read model as a sixteenth duplicate field.
SUPERSEDED_FIXTURE_RECORD_IDS = frozenset({
    "atlas:field:microsoft.windows.security:4688.newprocessname",
    "atlas:claim:atlas.claim:sha256-01002319eb6d49dad74efe68284f646a5ebc9428131e6ad65e4e9a4fa83f6f03",
    "atlas:relationship:atlas.graph:sha256-b7ffc14a9cd3dd9838a4c94dc7610c95d63d8b7a172f6702c30b6e58cbd5af7e",
})

_original_load = base.load_canonical_records


def _include_powershell(records: list[dict]) -> list[dict]:
    by_id = {record.get("id"): record for record in records}
    if None in by_id:
        raise RuntimeError("MVP-2 baseline contains a canonical record without id")
    for record in build_powershell_operational_records():
        record_id = record.get("id")
        if not record_id:
            raise RuntimeError("PowerShell canonical record is missing id")
        previous = by_id.get(record_id)
        if previous is not None and previous != record:
            raise RuntimeError(f"conflicting PowerShell canonical record id: {record_id}")
        by_id[record_id] = record

    actual_events = {
        record_id.rsplit(":", 1)[-1]
        for record_id, record in by_id.items()
        if isinstance(record_id, str)
        and record_id.startswith("atlas:event:microsoft.windows.powershell:")
        and record.get("record_kind") == "entity"
        and record.get("entity_type") == "event"
    }
    if actual_events != EXPECTED_POWERSHELL_EVENT_IDS:
        raise RuntimeError(
            "MVP-2 PowerShell event set drift; expected 43 exact provider identities"
        )
    field_count = sum(
        1 for record in by_id.values()
        if record.get("record_kind") == "entity"
        and record.get("entity_type") == "field"
        and str(record.get("id", "")).startswith("atlas:field:microsoft.windows.powershell:")
    )
    if field_count != 71:
        raise RuntimeError(f"MVP-2 PowerShell field projection drift: expected 71, got {field_count}")
    return [by_id[key] for key in sorted(by_id)]


def _load_governed_examples() -> dict[str, dict]:
    if not ANALYST_EXAMPLES.is_file() or ANALYST_EXAMPLES.is_symlink():
        raise RuntimeError("MVP-2 governed analyst examples are missing or unsafe")
    data = json.loads(ANALYST_EXAMPLES.read_text(encoding="utf-8"))
    if data.get("status") != "MAINTAINER_APPROVED_SANITIZED_ANALYST_EXAMPLES":
        raise RuntimeError("MVP-2 analyst examples are not maintainer-approved")
    if data.get("authoring_policy") != "independently-authored":
        raise RuntimeError("MVP-2 analyst examples must be independently authored")
    sanitization = str(data.get("sanitization_policy", "")).lower()
    if "synthetic" not in sanitization or "not copied" not in sanitization:
        raise RuntimeError("MVP-2 analyst example sanitization policy is incomplete")

    examples = data.get("examples")
    if not isinstance(examples, list):
        raise RuntimeError("MVP-2 analyst examples payload must be a list")
    by_subject: dict[str, dict] = {}
    for row in examples:
        if not isinstance(row, dict):
            raise RuntimeError("MVP-2 analyst example entry must be an object")
        subject = row.get("subject_id")
        label = row.get("label")
        text = row.get("text")
        if not isinstance(subject, str) or not isinstance(label, str) or not isinstance(text, str):
            raise RuntimeError("MVP-2 analyst example identity/label/text must be strings")
        if subject in by_subject:
            raise RuntimeError(f"duplicate MVP-2 analyst example subject: {subject}")
        if not label.strip() or "sanitized" not in label.lower():
            raise RuntimeError(f"MVP-2 analyst example lacks sanitized label: {subject}")
        if len(text.strip()) < 80 or len(text) > 3000:
            raise RuntimeError(f"MVP-2 analyst example length is outside bounds: {subject}")
        lowered = text.lower()
        if "synthetic/documentation-only" not in lowered:
            raise RuntimeError(f"MVP-2 analyst example is not explicitly synthetic: {subject}")
        by_subject[subject] = row

    if frozenset(by_subject) != EXPECTED_EXAMPLE_SUBJECTS:
        raise RuntimeError(
            "MVP-2 governed example subject set drift: expected "
            + ", ".join(sorted(EXPECTED_EXAMPLE_SUBJECTS))
        )
    return by_subject


def _overlay_examples(records: list[dict]) -> list[dict]:
    examples = _load_governed_examples()
    output = list(records)
    ids = {record.get("id") for record in output}

    for subject, example in sorted(examples.items()):
        event = next((record for record in output if record.get("id") == subject), None)
        if not event or event.get("record_kind") != "entity" or event.get("entity_type") != "event":
            raise RuntimeError(f"MVP-2 analyst example subject is not a packaged event: {subject}")

        overview_claims = [
            record for record in output
            if record.get("record_kind") == "claim"
            and record.get("subject_id") == subject
            and record.get("predicate") == "telemetry.represents"
        ]
        if len(overview_claims) != 1:
            raise RuntimeError(f"MVP-2 analyst example requires exactly one overview claim: {subject}")
        old_claim = overview_claims[0]
        obj = old_claim.get("object")
        overview = copy.deepcopy(obj.get("value")) if isinstance(obj, dict) else None
        if not isinstance(overview, dict):
            raise RuntimeError(f"MVP-2 overview claim is not structured JSON: {subject}")
        if overview.get("examples") or overview.get("example"):
            raise RuntimeError(f"MVP-2 overview already has governed examples; refusing duplicate overlay: {subject}")

        overview["examples"] = [f"{example['label']}: {example['text']}"]
        replacement = encyclopedia.claim(
            subject,
            "telemetry.represents",
            overview,
            copy.deepcopy(old_claim.get("evidence", [])),
            confidence=old_claim.get("confidence", "high"),
        )
        if replacement["id"] == old_claim["id"]:
            raise RuntimeError(f"MVP-2 example overlay did not change deterministic claim identity: {subject}")
        if replacement["id"] in ids:
            raise RuntimeError(f"MVP-2 replacement overview claim collides with existing ID: {replacement['id']}")

        output = [record for record in output if record.get("id") != old_claim["id"]]
        ids.discard(old_claim["id"])
        output.append(replacement)
        ids.add(replacement["id"])

    return output


def load_mvp2_records():
    records = _original_load()
    present = {record.get("id") for record in records}
    missing = SUPERSEDED_FIXTURE_RECORD_IDS - present
    if missing:
        raise RuntimeError(
            "MVP-2 superseded-fixture contract drift; expected legacy records are missing: "
            + ", ".join(sorted(missing))
        )
    filtered = [
        record for record in records
        if record.get("id") not in SUPERSEDED_FIXTURE_RECORD_IDS
    ]
    if len(records) - len(filtered) != len(SUPERSEDED_FIXTURE_RECORD_IDS):
        raise RuntimeError("MVP-2 superseded-fixture pruning was not exact")
    with_powershell = _include_powershell(filtered)
    return _overlay_examples(with_powershell)


def main() -> int:
    base.load_canonical_records = load_mvp2_records
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
