#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


content_builder = load_module("encyclopedia_builder", ROOT / "tools/content/build_encyclopedia_records.py")
probe = load_module("preview_probe", ROOT / "tools/release/probe_engineering_preview.py")


def approved_windows_ids() -> list[str]:
    data = json.loads((ROOT / "content/encyclopedia/approved-exemplars.json").read_text(encoding="utf-8"))
    return sorted(
        [str(item["native_event_id"]) for item in data["events"] if item.get("namespace") == "microsoft.windows.security"],
        key=int,
    )


def test_01_all_governed_source_records_are_discovered():
    expected = sorted((ROOT / "content/encyclopedia/sources").glob("*.json"))
    discovered = [path for path in content_builder.source_paths() if path.parent == ROOT / "content/encyclopedia/sources"]
    assert discovered == expected
    assert len(discovered) == len(set(discovered))


def test_02_probe_set_is_derived_from_approved_exemplars():
    assert probe.approved_windows_event_ids() == approved_windows_ids()


def test_03_workflow_uses_aggregate_exemplar_contract():
    workflow = (ROOT / ".github/workflows/phase5105-usable-data-preview.yml").read_text(encoding="utf-8")
    assert "windows_security_exemplars_all=$true" in workflow
    assert "windows_security_event_ids=$WindowsExemplars" in workflow
    assert "$probe.windows_security_exemplars_all_ok" in workflow
    assert "$probe.windows_4769_search_ok" not in workflow


def test_04_conflicting_source_identity_fails_closed():
    original = content_builder.ENCYCLOPEDIA_SOURCE_DIR
    with tempfile.TemporaryDirectory() as directory:
        content_builder.ENCYCLOPEDIA_SOURCE_DIR = Path(directory)
        try:
            for name, title in (("first.json", "First"), ("second.json", "Conflicting")):
                (Path(directory) / name).write_text(json.dumps({
                    "record_kind": "source",
                    "id": "atlas:source:atlas.source:duplicate-test",
                    "title": title,
                }), encoding="utf-8")
            try:
                content_builder.source_records()
            except ValueError as error:
                assert "conflicting governed source identity" in str(error)
            else:
                raise AssertionError("conflicting source records were silently accepted")
        finally:
            content_builder.ENCYCLOPEDIA_SOURCE_DIR = original


def test_05_duplicate_approved_event_id_fails_closed():
    original = probe.APPROVED_EXEMPLARS
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "approved-exemplars.json"
        path.write_text(json.dumps({
            "status": "MAINTAINER_APPROVED_PRODUCTION_EXEMPLARS",
            "events": [
                {"namespace": "microsoft.windows.security", "native_event_id": "4769"},
                {"namespace": "microsoft.windows.security", "native_event_id": "4769"},
            ],
        }), encoding="utf-8")
        probe.APPROVED_EXEMPLARS = path
        try:
            try:
                probe.approved_windows_event_ids()
            except RuntimeError as error:
                assert "invalid or duplicated" in str(error)
            else:
                raise AssertionError("duplicate approved Windows Event IDs were accepted")
        finally:
            probe.APPROVED_EXEMPLARS = original


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
            print(f"PASS {name}")
