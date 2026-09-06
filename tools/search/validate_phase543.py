#!/usr/bin/env python3
"""Permanent Phase 5.4.3 production SQLite search-core validation."""
from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
REFERENCE_PATH = ROOT / "tools" / "search" / "reference_search.py"
SQLITE_PATH = ROOT / "tools" / "search" / "sqlite_search.py"
FIXTURE = ROOT / "fixtures" / "phase-5.4.1" / "acceptance-corpus.json"
RESULT_SCHEMA = ROOT / "schemas" / "search" / "v1" / "search-result.schema.json"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec or not spec.loader:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    reference = _load_module("atlas_phase541_reference_for_validator", REFERENCE_PATH)
    search = _load_module("atlas_phase543_sqlite_validator", SQLITE_PATH)
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    bundle = reference.build_projection_bundle(fixture)
    result_schema = json.loads(RESULT_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(result_schema)
    validator = Draft202012Validator(result_schema)

    expected = {
        "4688": ("native_identifier", ["atlas:event:microsoft.windows.security:4688"]),
        "windows 4688": ("scoped_identifier", ["atlas:event:microsoft.windows.security:4688"]),
        "sysmon 1": ("scoped_identifier", ["atlas:event:microsoft.sysmon:1"]),
        "592": ("native_identifier", ["atlas:event:microsoft.windows.security:592"]),
        "T1059.001": ("native_identifier", ["atlas:attack-technique:mitre.attack:t1059.001"]),
        "kubectl exec": ("alias", ["atlas:activity:kubernetes.audit:create.pods.exec"]),
        "PowerShell": ("lexical", ["atlas:attack-technique:mitre.attack:t1059.001"]),
    }

    with tempfile.TemporaryDirectory() as temp_dir:
        index_path = Path(temp_dir) / "atlas-search.sqlite3"
        metadata = search.build_index(bundle, index_path)
        if metadata["index_adapter_id"] != "sqlite-fts5":
            raise SystemExit("Phase 5.4.3 adapter binding is not sqlite-fts5")
        if metadata["bundle_digest"] != bundle["bundle_digest"]:
            raise SystemExit("Phase 5.4.3 bundle binding mismatch")

        with search.SQLiteSearchCore.open(index_path, expected_bundle=bundle) as core:
            for query, (stage, target_ids) in expected.items():
                result = core.resolve(query)
                errors = sorted(validator.iter_errors(result), key=lambda error: list(error.path))
                if errors:
                    raise SystemExit(
                        f"{query!r} violates SearchResult schema: "
                        + "; ".join(error.message for error in errors)
                    )
                actual_ids = [item["target_id"] for item in result["matches"]]
                if result["match_stage"] != stage or actual_ids != target_ids:
                    raise SystemExit(
                        f"{query!r}: expected stage={stage} ids={target_ids}, "
                        f"got stage={result['match_stage']} ids={actual_ids}"
                    )

            collision = core.resolve("1")
            if collision["status"] != "disambiguation" or len(collision["matches"]) != 2:
                raise SystemExit("bare Event ID 1 did not preserve deterministic disambiguation")
            if core.resolve("provider:not-mitre PowerShell")["status"] != "no_match":
                raise SystemExit("structured filtering failed closed incorrectly")
            if [row["derived_numeric_value"] for row in core.numeric_browse(namespace="microsoft.windows.security")] != [592, 4688]:
                raise SystemExit("numeric Event ID browse is not numeric/deterministic")

    print("Phase 5.4.3 production SQLite + FTS5 search-core validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
