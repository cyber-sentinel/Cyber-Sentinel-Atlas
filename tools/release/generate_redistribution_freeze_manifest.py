#!/usr/bin/env python3
"""Generate deterministic, non-authoritative PPR-04 redistribution freeze manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

COMMIT40 = re.compile(r"^[0-9a-f]{40}$")
ROLE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
KINDS = ("PUBLIC_PREVIEW_CORPUS", "SOFTWARE_PAYLOAD")


def digest(path: Path) -> dict:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
            size += len(chunk)
    return {
        "file": path.name,
        "sha256": h.hexdigest(),
        "size_bytes": size,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", choices=KINDS, required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument(
        "--input",
        action="append",
        default=[],
        metavar="ROLE=PATH",
        help="Artifact role and exact file path; repeat for every frozen artifact.",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    errors: list[str] = []
    if not COMMIT40.fullmatch(args.release_commit):
        errors.append("release commit must be an exact 40-character lowercase SHA")
    if not args.input:
        errors.append("at least one --input ROLE=PATH is required")

    resolved: dict[str, Path] = {}
    basenames: set[str] = set()
    for spec in args.input:
        if "=" not in spec:
            errors.append(f"invalid input specification: {spec!r}")
            continue
        role, raw_path = spec.split("=", 1)
        if not ROLE_RE.fullmatch(role):
            errors.append(f"invalid artifact role: {role!r}")
            continue
        if role in resolved:
            errors.append(f"duplicate artifact role: {role}")
            continue
        try:
            path = Path(raw_path).resolve(strict=True)
        except FileNotFoundError:
            errors.append(f"{role}: input does not exist: {raw_path}")
            continue
        if not path.is_file():
            errors.append(f"{role}: input must be a regular file: {raw_path}")
            continue
        if path.stat().st_size <= 0:
            errors.append(f"{role}: input must be non-empty: {raw_path}")
            continue
        if path.name in basenames:
            errors.append(f"duplicate artifact basename: {path.name}")
            continue
        basenames.add(path.name)
        resolved[role] = path

    if errors:
        print("PPR-04 redistribution freeze manifest generation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 1

    artifacts = {role: digest(path) for role, path in sorted(resolved.items())}
    manifest = {
        "schema_version": "1.0.0",
        "gate": "PPR-04",
        "evidence_class": "REDISTRIBUTION_FREEZE_MANIFEST",
        "freeze_kind": args.kind,
        "release_authority": False,
        "publication_authorized": False,
        "release_commit": args.release_commit,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"PPR-04 redistribution freeze manifest written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
