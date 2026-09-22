#!/usr/bin/env python3
"""Validate exact artifact bytes against a PPR-04 redistribution freeze manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

COMMIT40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ROLE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
KINDS = ("PUBLIC_PREVIEW_CORPUS", "SOFTWARE_PAYLOAD")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--expected-kind", choices=KINDS, required=True)
    parser.add_argument("--release-commit", required=True)
    args = parser.parse_args()

    errors: list[str] = []
    if not COMMIT40.fullmatch(args.release_commit):
        errors.append("release commit must be an exact 40-character lowercase SHA")

    try:
        data = json.loads(args.manifest.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"PPR-04 redistribution freeze manifest validation FAILED: {exc}")
        return 1

    if data.get("schema_version") != "1.0.0":
        errors.append("unexpected schema_version")
    if data.get("gate") != "PPR-04":
        errors.append("manifest must identify PPR-04")
    if data.get("evidence_class") != "REDISTRIBUTION_FREEZE_MANIFEST":
        errors.append("unexpected evidence_class")
    if data.get("freeze_kind") != args.expected_kind:
        errors.append("freeze_kind does not match --expected-kind")
    if data.get("release_authority") is not False:
        errors.append("freeze manifest must not claim release authority")
    if data.get("publication_authorized") is not False:
        errors.append("freeze manifest must not authorize publication")
    if data.get("release_commit") != args.release_commit:
        errors.append("release_commit does not match exact expected commit")

    artifacts = data.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        errors.append("artifacts must be a non-empty object")
        artifacts = {}

    artifact_count = data.get("artifact_count")
    if (
        not isinstance(artifact_count, int)
        or isinstance(artifact_count, bool)
        or artifact_count <= 0
        or artifact_count != len(artifacts)
    ):
        errors.append("artifact_count must exactly match the artifact mapping")

    try:
        root = args.artifacts_dir.resolve(strict=True)
    except FileNotFoundError:
        root = args.artifacts_dir.resolve()
        errors.append("artifacts directory does not exist")
    if root.exists() and not root.is_dir():
        errors.append("artifacts-dir must be a directory")

    seen_files: set[str] = set()
    for role, item in artifacts.items():
        if not isinstance(role, str) or not ROLE_RE.fullmatch(role):
            errors.append(f"invalid artifact role: {role!r}")
            continue
        if not isinstance(item, dict):
            errors.append(f"{role}: artifact binding must be an object")
            continue
        name = item.get("file")
        expected_hash = item.get("sha256")
        expected_size = item.get("size_bytes")
        if not isinstance(name, str) or not name or Path(name).name != name:
            errors.append(f"{role}: file must be a basename without traversal")
            continue
        if name in seen_files:
            errors.append(f"duplicate artifact filename: {name}")
            continue
        seen_files.add(name)
        if not isinstance(expected_hash, str) or not HEX64.fullmatch(expected_hash):
            errors.append(f"{role}: invalid SHA-256")
        if (
            not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size <= 0
        ):
            errors.append(f"{role}: invalid size_bytes")

        path = root / name
        if not path.is_file():
            errors.append(f"{role}: bound artifact is missing: {name}")
            continue
        if isinstance(expected_size, int) and not isinstance(expected_size, bool):
            if path.stat().st_size != expected_size:
                errors.append(f"{role}: size mismatch")
        if isinstance(expected_hash, str) and HEX64.fullmatch(expected_hash):
            if sha256(path) != expected_hash:
                errors.append(f"{role}: SHA-256 mismatch")

    if errors:
        print("PPR-04 redistribution freeze manifest validation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("PPR-04 redistribution freeze manifest validation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
