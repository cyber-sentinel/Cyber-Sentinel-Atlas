#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("result", type=Path)
    parser.add_argument("--expected-docs", type=int, required=True)
    args = parser.parse_args()

    data = json.loads(args.result.read_text(encoding="utf-8"))
    assert data["benchmark_contract_version"] == "1.0.0"
    assert data["phase"] == "5.4.2"
    assert data["corpus"]["document_count"] == args.expected_docs
    assert set(data["candidates"]) == {"sqlite-fts5", "tantivy"}
    assert not data["errors"], data["errors"]
    for candidate in data["candidates"].values():
        assert candidate["build_seconds"] > 0
        assert candidate["index_bytes"] > 0
        assert candidate["metrics"]
    print("Phase 5.4.2 benchmark result envelope passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
