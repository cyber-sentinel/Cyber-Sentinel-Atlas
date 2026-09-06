#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from common import (
    QUERY_SUITE,
    digest,
    environment,
    expand_documents,
    latency_summary,
    load_base_documents,
    sqlite_fts_expression as _sqlite_fts_expression,
    tokenize_lexical as _tokenize_lexical,
)
from sqlite_adapter import SQLiteAdapter
from tantivy_adapter import TantivyAdapter


def time_call(fn: Callable[[], Any], iterations: int):
    samples = []
    result = None
    first_result = None
    deterministic = True
    for iteration in range(iterations):
        started = time.perf_counter_ns()
        result = fn()
        samples.append((time.perf_counter_ns() - started) / 1_000_000)
        if iteration == 0:
            first_result = result
        elif result != first_result:
            deterministic = False
    return samples, result, deterministic


def run_suite(adapter, suite, iterations):
    metrics = {}
    errors = []
    for case in suite["cases"]:
        try:
            if case["kind"] == "exact":
                operation = lambda c=case: adapter.exact(c["target_id"])
            elif case["kind"] == "lexical":
                operation = lambda c=case: adapter.lexical(c["query"], provider=c.get("provider"))
            elif case["kind"] == "numeric_browse":
                operation = lambda c=case: adapter.numeric_browse(c["provider"])
            else:
                raise ValueError(f"unsupported kind {case['kind']}")
            samples, result, deterministic = time_call(operation, iterations)
            if not deterministic:
                errors.append(f"{adapter.engine_id}:{case['id']}: repeated result set/order was nondeterministic")
            flattened = [x[1] if isinstance(x, tuple) else x for x in result]
            for expected in case.get("expected_contains", []):
                if expected not in flattened:
                    errors.append(f"{adapter.engine_id}:{case['id']}: expected {expected} in {flattened}")
            expected_result = case.get("expected_result")
            if expected_result is not None and result != expected_result:
                errors.append(
                    f"{adapter.engine_id}:{case['id']}: exact result mismatch expected={expected_result} actual={result}"
                )
            prefix = case.get("expected_numeric_prefix")
            if prefix is not None and [x[0] for x in result[:len(prefix)]] != prefix:
                errors.append(f"{adapter.engine_id}:{case['id']}: numeric prefix mismatch")
            metrics[case["id"]] = {
                "kind": case["kind"],
                "latency": latency_summary(samples),
                "deterministic": deterministic,
                "result": result,
            }
        except Exception as exc:
            errors.append(f"{adapter.engine_id}:{case['id']}:{type(exc).__name__}:{exc}")
    return metrics, errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--docs", type=int, default=20000)
    parser.add_argument("--iterations", type=int, default=40)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.docs < 100 or not 5 <= args.iterations <= 500:
        raise SystemExit("invalid benchmark bounds")

    suite = json.loads(QUERY_SUITE.read_text(encoding="utf-8"))
    base, projection_digest = load_base_documents()
    docs = expand_documents(base, args.docs)
    result = {
        "benchmark_contract_version": "1.0.0",
        "phase": "5.4.2",
        "environment": environment(),
        "corpus": {
            "source_fixture": "fixtures/phase-5.4.1/acceptance-corpus.json",
            "phase541_projection_digest": projection_digest,
            "benchmark_corpus_digest": digest([d.__dict__ for d in docs]),
            "document_count": len(docs),
            "base_acceptance_document_count": len(base),
            "synthetic_noise_document_count": len(docs) - len(base),
            "high_fanout_modulus": 5,
        },
        "query_suite": {
            "path": "benchmarks/search/phase542/query-suite.json",
            "version": suite["version"],
            "digest": digest(suite),
            "iterations_per_case": args.iterations,
        },
        "candidates": {},
        "errors": [],
    }

    with tempfile.TemporaryDirectory(prefix="atlas-p542-") as tmp:
        root = Path(tmp)
        adapters = []
        try:
            for cls, name in ((SQLiteAdapter, "sqlite"), (TantivyAdapter, "tantivy")):
                directory = root / name
                directory.mkdir()
                adapters.append(cls(directory, docs))
            for adapter in adapters:
                metrics, errors = run_suite(adapter, suite, args.iterations)
                result["errors"].extend(errors)
                result["candidates"][adapter.engine_id] = {
                    "engine_version": adapter.version,
                    "build_seconds": round(adapter.build_seconds, 6),
                    "index_bytes": adapter.index_bytes,
                    "metrics": metrics,
                }
        finally:
            for adapter in adapters:
                try:
                    adapter.close()
                except Exception as exc:
                    result["errors"].append(f"{adapter.engine_id}:close:{type(exc).__name__}:{exc}")

    result["result_digest"] = digest(result)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
