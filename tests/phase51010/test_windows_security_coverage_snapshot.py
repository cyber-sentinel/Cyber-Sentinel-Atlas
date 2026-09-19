#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = ROOT / "content" / "encyclopedia" / "windows-security-auditing-26100.33296-coverage.snapshot.json"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load_module(
    "windows_security_coverage",
    ROOT / "tools" / "content" / "build_windows_security_coverage_snapshot.py",
)


def test_01_snapshot_matches_deterministic_builder():
    committed = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    assert committed == builder.build_snapshot()


def test_02_denominator_is_exact_controlled_provider_scope():
    snapshot = builder.build_snapshot()
    assert snapshot["provider"] == "Microsoft-Windows-Security-Auditing"
    assert snapshot["channel"] == "Security"
    assert snapshot["reference_scope"]["windows_build"] == "26100.33296"
    assert snapshot["denominator_count"] == 423
    assert snapshot["provider_event_version_definition_count"] == 488
    ids = [item["event_id"] for item in snapshot["events"]]
    assert len(ids) == len(set(ids)) == 423
    assert "4624" in ids
    assert "4688" in ids
    assert "592" not in ids


def test_03_only_current_approved_windows_exemplars_count():
    snapshot = builder.build_snapshot()
    assert snapshot["encyclopedia_grade_count"] == 2
    assert snapshot["remaining_count"] == 421
    assert snapshot["completion_ratio"] == "2/423"
    assert snapshot["completion_percent"] == 0.47
    by_id = {item["event_id"]: item for item in snapshot["events"]}
    for event_id in ("4624", "4688"):
        assert by_id[event_id]["coverage_state"] == "ENCYCLOPEDIA_GRADE"
        assert by_id[event_id]["counts_toward_release_coverage"] is True
    assert by_id["4625"]["coverage_state"] == "IDENTIFIED_PROVIDER_SCOPE"
    assert by_id["4625"]["counts_toward_release_coverage"] is False


def test_04_inventory_binding_and_legacy_boundary_are_explicit():
    snapshot = builder.build_snapshot()
    assert snapshot["inventory_id"] == "atlas:inventory:atlas.ingestion:windows-security-auditing-provider-26100.33296"
    assert snapshot["inventory_digest"] == "sha256-fa2d7346bf7e28ada33645b232f7b556b6aff8c5def3ec2d491fb8d914b3e969"
    assert snapshot["psr_representation_digest"] == "sha256-ef6bf952ef92518ce433f643a9666a50d7824c57b8ec6c5405475864845ac839"
    assert "592" in snapshot["legacy_semantics"]
    assert "other Windows builds/providers/channels" in snapshot["legacy_semantics"]


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
            print(f"PASS {name}")
