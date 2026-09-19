#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "content" / "encyclopedia" / "coverage-manifest.json"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator = load_module(
    "encyclopedia_coverage_validator",
    ROOT / "tools" / "content" / "validate_encyclopedia_coverage.py",
)


def test_01_machine_readable_coverage_manifest_is_truthful():
    assert validator.validate() == []


def test_02_global_windows_completion_is_fail_closed():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["overall_state"] == "IN_PROGRESS"
    assert manifest["global_windows_denominator_frozen"] is False
    assert manifest["global_windows_completion_percent"] is None


def test_03_only_evidence_backed_family_denominators_are_frozen():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    by_id = {item["id"]: item for item in manifest["families"]}
    assert by_id["windows-security-auditing"]["state"] == "ACTIVE_DENOMINATOR_FROZEN"
    assert by_id["sysmon"]["state"] == "ACTIVE_DENOMINATOR_FROZEN"
    for family_id, family in by_id.items():
        if family_id not in {"windows-security-auditing", "sysmon"}:
            assert family["state"] == "DENOMINATOR_NOT_FROZEN"


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
            print(f"PASS {name}")
