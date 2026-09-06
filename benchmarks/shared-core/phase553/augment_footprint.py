#!/usr/bin/env python3
"""Augment Phase 5.5.3 candidate evidence with reproducible footprint/lock data."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
from pathlib import Path


def sha256_prefixed(path: Path) -> str:
    return "sha256-" + hashlib.sha256(path.read_bytes()).hexdigest()


def update(path: Path, *, binary: Path | None, lockfile: Path | None) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    runtime = value.setdefault("runtime", {})
    dependencies = value.setdefault("dependencies", {})
    if binary is not None and binary.is_file():
        runtime["compiled_binary_bytes"] = binary.stat().st_size
        runtime["compiled_binary_sha256"] = sha256_prefixed(binary)
    if lockfile is not None and lockfile.is_file():
        dependencies["lockfile_path"] = lockfile.as_posix()
        dependencies["lockfile_sha256"] = sha256_prefixed(lockfile)
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--runner-os", required=True)
    args = parser.parse_args()
    root = Path.cwd()
    evidence = args.evidence

    python_path = evidence / f"python-{args.runner_os}.json"
    python_value = json.loads(python_path.read_text(encoding="utf-8"))
    python_runtime = python_value.setdefault("runtime", {})
    python_runtime["interpreter_bytes"] = Path(sys.executable).stat().st_size
    python_runtime["interpreter_sha256"] = sha256_prefixed(Path(sys.executable))
    python_runtime["platform_detail"] = platform.platform()
    python_path.write_text(
        json.dumps(python_value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )

    go_binary = evidence / ("atlas-phase553-go.exe" if args.runner_os == "Windows" else "atlas-phase553-go")
    update(
        evidence / f"go-{args.runner_os}.json",
        binary=go_binary,
        lockfile=root / "benchmarks" / "shared-core" / "phase553" / "go" / "go.sum",
    )

    rust_binary = root / "benchmarks" / "shared-core" / "phase553" / "rust" / "target" / "release" / (
        "atlas-phase553-rust.exe" if args.runner_os == "Windows" else "atlas-phase553-rust"
    )
    update(
        evidence / f"rust-{args.runner_os}.json",
        binary=rust_binary,
        lockfile=root / "benchmarks" / "shared-core" / "phase553" / "rust" / "Cargo.lock",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
