#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Sequence

ROOT = Path(__file__).resolve().parents[3]
SEARCH_DIR = ROOT / "tools" / "search"
if str(SEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(SEARCH_DIR))

import catalog_graph  # noqa: E402

BASE_FIXTURE = ROOT / "fixtures" / "phase-5.4.4" / "catalog-graph-corpus.json"
DEFAULT_DOCS = 20_000
DEFAULT_ITERATIONS = 40


def percentile(samples: Sequence[float], p: float) -> float:
    ordered = sorted(samples)
    if not ordered:
        return 0.0
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * p
    low, high = math.floor(rank), math.ceil(rank)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


def summary(samples: Sequence[float]) -> dict[str, float]:
    return {
        "p50_ms": round(percentile(samples, 0.50), 4),
        "p95_ms": round(percentile(samples, 0.95), 4),
        "p99_ms": round(percentile(samples, 0.99), 4),
        "mean_ms": round(statistics.fmean(samples), 4),
        "max_ms": round(max(samples), 4),
    }


def timed(iterations: int, fn: Callable[[], Any]) -> dict[str, float]:
    samples = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - start) / 1_000_000)
    return summary(samples)


def expanded_fixture(total_docs: int) -> dict[str, Any]:
    fixture = json.loads(BASE_FIXTURE.read_text(encoding="utf-8"))
    records = list(fixture["records"])
    if total_docs < len(records):
        raise ValueError("document count is below the final acceptance corpus size")
    extra = total_docs - len(records)
    synthetic_ids = []
    for i in range(extra):
        target_id = f"atlas:activity:synthetic.benchmark:node-{i:08d}"
        synthetic_ids.append(target_id)
        fanout = " benchmarkfanout" if i % 5 == 0 else ""
        records.append(
            {
                "id": target_id,
                "entity_type": "activity",
                "title": f"Synthetic Benchmark Telemetry {i}",
                "namespace": "synthetic.benchmark",
                "scope": {
                    "platform": "synthetic",
                    "product": "search-benchmark",
                    "provider": f"synthetic-provider-{i % 20}",
                    "channel": f"channel-{i % 5}",
                },
                "lifecycle": "legacy" if i % 10 == 0 else "current",
                "version": "bench-v1" if i % 2 == 0 else "bench-v2",
                "description": (
                    f"Deterministic telemetry indexing benchmark record {i}"
                    f" fieldgroup-{i % 1021} uniquetoken-{i:08x}{fanout}"
                ),
                "native_identifiers": [],
                "aliases": [],
            }
        )
    edges = list(fixture.get("edges") or [])
    chain = min(1000, max(0, len(synthetic_ids) - 1))
    for i in range(chain):
        edges.append(
            {
                "source_id": synthetic_ids[i],
                "relationship_type": "RELATED_TO",
                "target_id": synthetic_ids[i + 1],
            }
        )
    fixture["canonical_corpus_id"] = f"atlas:test-corpus:phase-5.4.4-benchmark-{total_docs}"
    fixture["records"] = records
    fixture["edges"] = edges
    return fixture


def environment() -> dict[str, Any]:
    return {
        "os": platform.platform(),
        "python": platform.python_version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "cache_condition": "process-warm repeated queries; OS page cache not flushed; index opened once",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--docs", type=int, default=DEFAULT_DOCS)
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.docs < 100 or args.docs > 100_000:
        raise SystemExit("--docs must be between 100 and 100000")
    if args.iterations < 5 or args.iterations > 500:
        raise SystemExit("--iterations must be between 5 and 500")

    fixture = expanded_fixture(args.docs)
    build_start = time.perf_counter()
    bundle = catalog_graph.build_phase544_bundle(fixture)
    projection_seconds = time.perf_counter() - build_start

    with tempfile.TemporaryDirectory() as temp_dir:
        index_path = Path(temp_dir) / "atlas-phase544.sqlite3"
        index_start = time.perf_counter()
        catalog_graph.search.build_index(bundle, index_path)
        index_seconds = time.perf_counter() - index_start
        index_size = index_path.stat().st_size

        with catalog_graph.search.SQLiteSearchCore.open(
            index_path, expected_bundle=bundle
        ) as core:
            runtime = catalog_graph.CatalogGraphRuntime(core, bundle)
            synthetic_seed = "atlas:activity:synthetic.benchmark:node-00000000"
            cases: dict[str, tuple[Callable[[], Any], float]] = {
                "exact_4688": (lambda: core.resolve("4688"), 100.0),
                "lexical_high_fanout": (
                    lambda: core.resolve("benchmarkfanout", limit=20),
                    300.0,
                ),
                "provider_catalog": (
                    lambda: runtime.browse(filters={"provider": "synthetic-provider-7"}, limit=20),
                    300.0,
                ),
                "lifecycle_catalog": (
                    lambda: runtime.browse(filters={"lifecycle": "legacy"}, limit=20),
                    300.0,
                ),
                "numeric_event_browse": (
                    lambda: runtime.numeric_event_ids(namespace="microsoft.windows.security"),
                    300.0,
                ),
                "graph_depth_2": (
                    lambda: runtime.graph_expand([synthetic_seed], depth=2, direction="outgoing"),
                    300.0,
                ),
            }
            metrics = {
                name: timed(args.iterations, fn) for name, (fn, _) in cases.items()
            }

            correctness = {
                "exact_target": core.resolve("4688")["matches"][0]["target_id"],
                "lexical_count": len(core.resolve("benchmarkfanout", limit=20)["matches"]),
                "catalog_count": len(runtime.browse(filters={"provider": "synthetic-provider-7"}, limit=20)),
                "numeric_values": [
                    row["derived_numeric_value"]
                    for row in runtime.numeric_event_ids(namespace="microsoft.windows.security")
                ],
                "graph_targets": [
                    row["target_id"]
                    for row in runtime.graph_expand([synthetic_seed], depth=2, direction="outgoing")
                ],
            }

    errors = []
    for name, (_, budget) in cases.items():
        if metrics[name]["p95_ms"] >= budget:
            errors.append(
                f"{name} P95 {metrics[name]['p95_ms']}ms exceeds budget {budget}ms"
            )
    if correctness["exact_target"] != "atlas:event:microsoft.windows.security:4688":
        errors.append("exact resolver correctness mismatch")
    if correctness["lexical_count"] != 20:
        errors.append("high-fanout lexical query did not fill Top-K")
    if correctness["numeric_values"] != [592, 4688]:
        errors.append("numeric browse ordering mismatch")
    if len(correctness["graph_targets"]) != 2:
        errors.append("depth-2 graph expansion mismatch")

    result = {
        "phase": "5.4.4",
        "environment": environment(),
        "document_count": len(bundle["documents"]),
        "edge_count": len(bundle["edges"]),
        "bundle_digest": bundle["bundle_digest"],
        "projection_profile_version": bundle["build_binding"]["projection_profile_version"],
        "index_adapter_id": catalog_graph.search.INDEX_ADAPTER_ID,
        "index_adapter_version": catalog_graph.search.INDEX_ADAPTER_VERSION,
        "sqlite_version": catalog_graph.search.sqlite3.sqlite_version,
        "iterations": args.iterations,
        "projection_build_seconds": round(projection_seconds, 6),
        "index_build_seconds": round(index_seconds, 6),
        "index_size_bytes": index_size,
        "metrics": metrics,
        "correctness": correctness,
        "budgets_ms": {name: budget for name, (_, budget) in cases.items()},
        "errors": errors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
