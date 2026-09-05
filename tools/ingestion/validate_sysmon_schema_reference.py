#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PARSER_PATH = ROOT / "ingestion" / "parsers" / "microsoft_sysmon_schema.py"
FOUNDATION_PATH = ROOT / "tools" / "ingestion" / "validate_ingestion_foundation.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


parser = load_module("atlas_sysmon_schema_parser", PARSER_PATH)
foundation = load_module("atlas_ingestion_foundation", FOUNDATION_PATH)


def validate_reference(
    path: Path,
    *,
    source_id: str,
    snapshot_id: str,
    expected_schema_count: int | None = None,
    expected_current_schema: str | None = None,
    expected_current_event_count: int | None = None,
    required_event_ids: set[str] | None = None,
) -> dict:
    records = parser.parse_bytes(path.read_bytes(), source_id=source_id, source_snapshot_id=snapshot_id)
    psr_validator = foundation.ingestion_validator("parsed-source-record.schema.json")
    validation_errors = [
        f"{record['native_key']}: {error.message}"
        for record in records
        for error in psr_validator.iter_errors(record)
    ]
    if validation_errors:
        raise ValueError("PSR schema validation failed: " + "; ".join(validation_errors[:10]))

    counts = Counter(record["native_fields"]["schema_version"] for record in records)
    if not counts:
        raise ValueError("Sysmon schema parser returned no records")
    schema_versions = sorted(counts, key=parser._version_key)
    current_schema = schema_versions[-1]
    current_records = [record for record in records if record["native_fields"]["schema_version"] == current_schema]
    current_ids = {record["native_fields"]["event_id"] for record in current_records}

    if expected_schema_count is not None and len(schema_versions) != expected_schema_count:
        raise ValueError(f"schema-count drift: expected {expected_schema_count}, got {len(schema_versions)}")
    if expected_current_schema is not None and current_schema != expected_current_schema:
        raise ValueError(f"current-schema drift: expected {expected_current_schema}, got {current_schema}")
    if expected_current_event_count is not None and len(current_records) != expected_current_event_count:
        raise ValueError(
            f"current-schema event-count drift: expected {expected_current_event_count}, got {len(current_records)}"
        )
    missing = sorted((required_event_ids or set()) - current_ids, key=int)
    if missing:
        raise ValueError(f"current Sysmon schema is missing required Event IDs: {missing}")

    return {
        "source_id": source_id,
        "snapshot_id": snapshot_id,
        "representation_digest": parser.representation_digest(records),
        "record_count": len(records),
        "schema_count": len(schema_versions),
        "schema_versions": schema_versions,
        "event_counts_by_schema": {version: counts[version] for version in schema_versions},
        "current_schema": current_schema,
        "current_event_count": len(current_records),
        "current_event_ids": sorted(current_ids, key=int),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate a controlled Sysmon schema ReferenceExport through the deterministic Atlas PSR parser.")
    ap.add_argument("input", type=Path)
    ap.add_argument("--source-id", default="atlas:source:atlas.source:microsoft-sysmon-schema-export")
    ap.add_argument("--snapshot-id", default="atlas:raw-snapshot:atlas.ingestion:reference-host-validation")
    ap.add_argument("--expected-schema-count", type=int)
    ap.add_argument("--expected-current-schema")
    ap.add_argument("--expected-current-event-count", type=int)
    ap.add_argument("--required-event-id", action="append", default=[])
    args = ap.parse_args()

    result = validate_reference(
        args.input,
        source_id=args.source_id,
        snapshot_id=args.snapshot_id,
        expected_schema_count=args.expected_schema_count,
        expected_current_schema=args.expected_current_schema,
        expected_current_event_count=args.expected_current_event_count,
        required_event_ids=set(args.required_event_id),
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
