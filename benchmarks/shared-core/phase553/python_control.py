#!/usr/bin/env python3
"""Python semantic/control finalist for the Phase 5.5.3 Shared Core spike."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import platform
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from tools.pack.tuf_runtime import verify_pack_directory
from tools.search.sqlite_search import SQLiteSearchCore

ROOT = Path(__file__).resolve().parents[3]


def sha256_prefixed(data: bytes) -> str:
    return "sha256-" + hashlib.sha256(data).hexdigest()


def canonical_compact(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def target_ids(result: dict) -> list[str]:
    return [str(item["target_id"]) for item in result.get("matches", [])]


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * p))))
    return ordered[index]


def run_regressions() -> tuple[bool, str, float]:
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "tests/phase54/test_reference_search.py",
        "tests/phase54/test_phase543_sqlite_search.py",
        "tests/phase55/test_phase552_archive.py",
        "tests/phase55/test_phase552_tuf_runtime.py",
        "tests/phase55/test_phase552_activation.py",
    ]
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return completed.returncode == 0, completed.stdout[-12000:], time.perf_counter() - started


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    expected = json.loads((workspace / "expected.json").read_text(encoding="utf-8"))
    spc = json.loads((workspace / "search" / "spc.json").read_text(encoding="utf-8"))
    index_path = workspace / "search" / "atlas-search.sqlite3"

    compact = canonical_compact(expected["serialization_vector"])
    serialization_ok = (
        base64.b64encode(compact).decode("ascii") == expected["compact_json_base64"]
        and sha256_prefixed(compact) == expected["compact_json_sha256"]
    )

    query_results: dict[str, dict] = {}
    exact_latencies: list[float] = []
    lexical_latencies: list[float] = []
    search_ok = True
    with SQLiteSearchCore.open(index_path, expected_bundle=spc) as core:
        for query in expected["queries"]:
            samples = []
            result = None
            for _ in range(40):
                started = time.perf_counter_ns()
                current = core.resolve(query)
                samples.append((time.perf_counter_ns() - started) / 1_000_000.0)
                if result is None:
                    result = current
                elif target_ids(result) != target_ids(current):
                    search_ok = False
            assert result is not None
            wanted = expected["query_expectations"][query]
            passed = (
                target_ids(result) == wanted["targets"]
                and result["match_stage"] == wanted["stage"]
                and result["status"] == wanted["status"]
            )
            search_ok = search_ok and passed
            p95 = percentile(samples, 0.95)
            if result["match_stage"] == "lexical":
                lexical_latencies.extend(samples)
            else:
                exact_latencies.extend(samples)
            query_results[query] = {
                "pass": passed,
                "targets": target_ids(result),
                "stage": result["match_stage"],
                "p95_ms": p95,
            }

    runtime_root = workspace / "python-runtime"
    runtime_root.mkdir(exist_ok=True)
    verified = verify_pack_directory(
        workspace / "valid",
        bootstrap_root=(workspace / "bootstrap-root.json").read_bytes(),
        metadata_cache_dir=runtime_root / "metadata-cache",
        verified_targets_dir=runtime_root / "verified-targets",
    )
    pack_ok = (
        verified.manifest_digest == expected["valid_manifest_sha256"]
        and verified.manifest["spc_digest"]
        == sha256_prefixed((workspace / "valid" / "targets" / "search" / "spc.json").read_bytes())
    )

    regressions_ok, regression_log, regression_seconds = run_regressions()
    compile_options = [row[0] for row in sqlite3.connect(":memory:").execute("PRAGMA compile_options")]
    fts5_ok = any("ENABLE_FTS5" in option for option in compile_options)

    gates = {
        "G-SC1": regressions_ok,
        "G-SC2": serialization_ok,
        "G-SC3": search_ok,
        "G-SC4": fts5_ok and search_ok,
        "G-SC5": pack_ok and regressions_ok,
        "G-SC6": regressions_ok,
        "G-SC7": regressions_ok,
        "G-SC8": True,
    }
    evidence = {
        "evidence_schema_version": "1.0.0",
        "candidate": "python-control",
        "eligible": all(gates.values()),
        "gates": gates,
        "runtime": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "os": platform.system(),
            "arch": platform.machine(),
            "sqlite": sqlite3.sqlite_version,
            "fts5": fts5_ok,
        },
        "dependencies": {
            "requirements": "tools/pack/requirements-phase552.txt",
            "requirements_sha256": sha256_prefixed(
                (ROOT / "tools" / "pack" / "requirements-phase552.txt").read_bytes()
            ),
            "tuf": "7.0.0",
        },
        "bindings": {
            "spc_bundle_digest": expected["spc_bundle_digest"],
            "search_index_sha256": expected["search_index_sha256"],
            "serialization_sha256": expected["compact_json_sha256"],
        },
        "search": {
            "queries": query_results,
            "exact_p95_ms": percentile(exact_latencies, 0.95),
            "lexical_p95_ms": percentile(lexical_latencies, 0.95),
        },
        "pack": {
            "manifest_digest": verified.manifest_digest,
            "pass": pack_ok,
        },
        "regression": {
            "pass": regressions_ok,
            "seconds": regression_seconds,
            "tail": regression_log,
        },
        "known_limitations": [
            "Python is the semantic/control baseline; production packaging and embedding footprint remain scored disadvantages, not contract exceptions."
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"candidate": "python-control", "eligible": evidence["eligible"]}, sort_keys=True))
    return 0 if evidence["eligible"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
