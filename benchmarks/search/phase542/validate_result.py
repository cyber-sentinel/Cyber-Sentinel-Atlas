#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

REQUIRED_METRICS = {
    "exact-windows-4688",
    "exact-sysmon-1",
    "lexical-powershell",
    "lexical-process-creation",
    "lexical-kubectl-exec",
    "lexical-create-access-key",
    "lexical-high-fanout-deterministic-ties",
    "filtered-windows-process",
    "numeric-windows-provider",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("result", type=Path)
    parser.add_argument("--expected-docs", type=int, required=True)
    args = parser.parse_args()

    data = json.loads(args.result.read_text(encoding="utf-8"))
    assert data["benchmark_contract_version"] == "1.0.0"
    assert data["phase"] == "5.4.2"
    assert data["corpus"]["document_count"] == args.expected_docs
    assert data["corpus"]["high_fanout_modulus"] == 5
    assert data["query_suite"]["version"] == "1.1.0"
    assert set(data["candidates"]) == {"sqlite-fts5", "tantivy"}
    assert not data["errors"], data["errors"]
    for candidate in data["candidates"].values():
        assert candidate["build_seconds"] > 0
        assert candidate["index_bytes"] > 0
        assert REQUIRED_METRICS.issubset(candidate["metrics"])
        assert all(metric["deterministic"] for metric in candidate["metrics"].values())
    print("Phase 5.4.2 benchmark result envelope passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
