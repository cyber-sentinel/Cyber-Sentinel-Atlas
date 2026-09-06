#!/usr/bin/env python3
"""Emit machine-readable Phase 5.5.3 evidence when a finalist cannot build/run.

A build/runtime failure is evidence about that candidate on that platform. It must not
erase successful control/finalist evidence or force the comparison harness to stop
before validation and artifact publication.
"""
from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path

GATES = [f"G-SC{i}" for i in range(1, 9)]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--runner-os", required=True)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--reason", required=True)
    args = parser.parse_args()

    expected = json.loads((args.workspace / "expected.json").read_text(encoding="utf-8"))
    evidence = {
        "evidence_schema_version": "1.0.0",
        "candidate": args.candidate,
        "eligible": False,
        "gates": {gate: False for gate in GATES},
        "runtime": {
            "os": args.runner_os,
            "platform_detail": platform.platform(),
            "failure_stage": args.stage,
        },
        "dependencies": {
            "resolution_state": "candidate-build-or-run-failed-before-complete-evidence",
        },
        "bindings": {
            "spc_bundle_digest": expected["spc_bundle_digest"],
            "search_index_sha256": expected["search_index_sha256"],
            "serialization_sha256": expected["compact_json_sha256"],
        },
        "search": {
            "queries": {},
            "exact_p95_ms": 0.0,
            "lexical_p95_ms": 0.0,
        },
        "pack": {
            "pass": False,
            "reason": "candidate did not reach complete Atlas POUF evidence",
        },
        "state": {
            "pass": False,
            "reason": "candidate did not reach complete durable-state evidence",
        },
        "known_limitations": [args.reason],
        "failure": {
            "stage": args.stage,
            "reason": args.reason,
            "hard_gate_effect": "candidate ineligible on this platform",
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"candidate": args.candidate, "eligible": False, "stage": args.stage}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
