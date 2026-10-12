#!/usr/bin/env python3
"""Build canonical v1 records for the frozen PowerShell Operational family.

The governed input is the derived provider inventory split across eight reviewed
batch files. Raw provider XML remains outside Git. This builder emits canonical
Entity/Claim/Relationship/Source records using the same primitives as the
Windows Security and Sysmon encyclopedia builder.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.content import build_encyclopedia_records as base

BATCH_GLOB = "powershell-operational-26100-batch*.json"
SOURCE_PATH = ROOT / "content" / "encyclopedia" / "sources" / "microsoft-windows-powershell-operational-provider-26100.json"
EXPECTED_IDS = {
    "4100","4101","4102","4103","4104","4105","4106","8193","8194","8195","8196","8197","8198",
    "12039","24577","24578","24579","24580","24581","24582","24583","24584","24592","24593","24594",
    "24595","24596","24597","24598","24599","32777","32784","40961","40962","46358","53249","53250",
    "53251","53504","53505","53506","53507","53508",
}
EXPECTED_NAMESPACE = "microsoft.windows.powershell"
EXPECTED_PROVIDER = "Microsoft-Windows-PowerShell"
EXPECTED_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
EXPECTED_STATUS = "MAINTAINER_APPROVED_POWERSHELL_OPERATIONAL_26100"


def load_events() -> list[dict[str, Any]]:
    directory = ROOT / "content" / "encyclopedia"
    paths = sorted(directory.glob(BATCH_GLOB), key=lambda p: p.name)
    if len(paths) != 8:
        raise ValueError(f"PowerShell Operational batch count drift: expected 8, got {len(paths)}")
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, path in enumerate(paths, start=1):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError(f"invalid PowerShell Operational batch path: {path}")
        batch = json.loads(path.read_text(encoding="utf-8"))
        if batch.get("status") != EXPECTED_STATUS:
            raise ValueError(f"unapproved PowerShell Operational batch: {path.name}")
        if batch.get("batch_index") != index:
            raise ValueError(f"PowerShell batch ordering drift in {path.name}")
        if batch.get("namespace") != EXPECTED_NAMESPACE or batch.get("provider") != EXPECTED_PROVIDER or batch.get("channel") != EXPECTED_CHANNEL:
            raise ValueError(f"PowerShell family scope drift in {path.name}")
        rows = batch.get("events")
        if not isinstance(rows, list) or not rows:
            raise ValueError(f"PowerShell batch has no events: {path.name}")
        for event in rows:
            event_id = str(event.get("native_event_id", ""))
            if event_id in seen:
                raise ValueError(f"duplicate PowerShell Event ID: {event_id}")
            if event.get("namespace") != EXPECTED_NAMESPACE or event.get("provider") != EXPECTED_PROVIDER or event.get("channel") != EXPECTED_CHANNEL:
                raise ValueError(f"PowerShell event scope drift: {event_id}")
            if event.get("id") != f"atlas:event:{EXPECTED_NAMESPACE}:{event_id}":
                raise ValueError(f"PowerShell canonical identity drift: {event_id}")
            seen.add(event_id)
            events.append(event)
    if seen != EXPECTED_IDS:
        missing = sorted(EXPECTED_IDS - seen, key=int)
        extra = sorted(seen - EXPECTED_IDS, key=int)
        raise ValueError(f"PowerShell denominator drift; missing={missing}, extra={extra}")
    if len(events) != 43:
        raise ValueError(f"PowerShell event count drift: {len(events)}")
    field_count = sum(len(event.get("fields") or []) for event in events)
    if field_count != 71:
        raise ValueError(f"PowerShell field projection drift: expected 71, got {field_count}")
    return sorted(events, key=lambda item: int(item["native_event_id"]))


def load_source() -> dict[str, Any]:
    if SOURCE_PATH.is_symlink() or not SOURCE_PATH.is_file() or SOURCE_PATH.stat().st_size > 1024 * 1024:
        raise ValueError("PowerShell governed source record is missing/unsafe")
    source = json.loads(SOURCE_PATH.read_text(encoding="utf-8"))
    if source.get("record_kind") != "source" or source.get("id") != "atlas:source:atlas.source:microsoft-windows-powershell-operational-provider-26100":
        raise ValueError("PowerShell governed source identity drift")
    if (source.get("redistribution") or {}).get("policy") != "restricted":
        raise ValueError("PowerShell raw Microsoft source redistribution must remain restricted")
    return source


def build_records() -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    source = load_source()
    records[source["id"]] = source

    for item in load_events():
        event = base.event_entity(item)
        records[event["id"]] = event
        for claim in base.event_claims(item):
            if claim["id"] in records and records[claim["id"]] != claim:
                raise ValueError(f"conflicting PowerShell claim identity: {claim['id']}")
            records[claim["id"]] = claim
        for field in item.get("fields") or []:
            entity = base.field_entity(item, field)
            records[entity["id"]] = entity
            semantics = base.field_semantics(item, field, entity["id"])
            records[semantics["id"]] = semantics
            rel = base.relationship(item["id"], entity["id"], "HAS_FIELD")
            records[rel["id"]] = rel

    event_count = sum(1 for row in records.values() if row.get("record_kind") == "entity" and row.get("entity_type") == "event")
    field_count = sum(1 for row in records.values() if row.get("record_kind") == "entity" and row.get("entity_type") == "field")
    if event_count != 43 or field_count != 71:
        raise ValueError(f"PowerShell canonical count drift: events={event_count}, fields={field_count}")
    return [records[key] for key in sorted(records)]


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    records = build_records()
    payload = "".join(base.canonical_json(record) + "\n" for record in records)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
