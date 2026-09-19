#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load_module("sysmon_coverage", ROOT / "tools/content/build_sysmon_coverage_snapshot.py")
SNAPSHOT = ROOT / "content/encyclopedia/sysmon-15.22-coverage.snapshot.json"


def test_01_snapshot_matches_deterministic_builder():
    committed = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    assert committed == builder.build_snapshot()


def test_02_sysmon_denominator_is_exactly_30_documented_ids():
    snapshot = builder.build_snapshot()
    assert snapshot["semantic_release"] == "15.22"
    assert snapshot["denominator_count"] == 30
    ids = [item["event_id"] for item in snapshot["events"]]
    assert sorted(ids, key=int) == [str(i) for i in range(1, 30)] + ["255"]


def test_03_only_approved_encyclopedia_grade_records_count():
    snapshot = builder.build_snapshot()
    assert snapshot["encyclopedia_grade_count"] == 5
    assert snapshot["remaining_count"] == 25
    assert snapshot["completion_ratio"] == "5/30"
    assert snapshot["completion_percent"] == 16.67
    event5 = next(item for item in snapshot["events"] if item["event_id"] == "5")
    event4 = next(item for item in snapshot["events"] if item["event_id"] == "4")
    event3 = next(item for item in snapshot["events"] if item["event_id"] == "3")
    event2 = next(item for item in snapshot["events"] if item["event_id"] == "2")
    event1 = next(item for item in snapshot["events"] if item["event_id"] == "1")
    assert event5["coverage_state"] == "ENCYCLOPEDIA_GRADE"
    assert event5["counts_toward_release_coverage"] is True
    assert event4["coverage_state"] == "ENCYCLOPEDIA_GRADE"
    assert event4["counts_toward_release_coverage"] is True
    assert event3["coverage_state"] == "ENCYCLOPEDIA_GRADE"
    assert event3["counts_toward_release_coverage"] is True
    assert event2["coverage_state"] == "ENCYCLOPEDIA_GRADE"
    assert event2["counts_toward_release_coverage"] is True
    assert event1["coverage_state"] == "ENCYCLOPEDIA_GRADE"
    assert event1["counts_toward_release_coverage"] is True


def test_04_schema_refresh_state_records_validated_real_15_22_export():
    snapshot = builder.build_snapshot()
    assert snapshot["telemetry_schema_refresh_state"] == "VALIDATED_CONTROLLED_SYSMON_15_22_REFERENCE_EXPORT"


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
            print(f"PASS {name}")
