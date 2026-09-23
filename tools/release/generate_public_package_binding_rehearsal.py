#!/usr/bin/env python3
"""Generate deterministic, non-authoritative Public Preview package-binding rehearsal evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path

try:
    from tools.release.zip_safety import validate_zip_members
except ModuleNotFoundError:  # direct script execution from tools/release
    from zip_safety import validate_zip_members

COMMIT40 = re.compile(r"^[0-9a-f]{40}$")


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
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--notices", type=Path, required=True)
    parser.add_argument("--release-notes", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    errors: list[str] = []
    if not COMMIT40.fullmatch(args.release_commit):
        errors.append("release commit must be an exact 40-character lowercase SHA")

    role_paths = {
        "package": args.package,
        "sbom": args.sbom,
        "third_party_notices": args.notices,
        "release_notes": args.release_notes,
    }
    resolved: dict[str, Path] = {}
    for role, path in role_paths.items():
        try:
            candidate = path.resolve(strict=True)
        except FileNotFoundError:
            errors.append(f"{role} input does not exist: {path}")
            continue
        if not candidate.is_file():
            errors.append(f"{role} input must be a regular file: {path}")
            continue
        if candidate.stat().st_size <= 0:
            errors.append(f"{role} input must be non-empty: {path}")
            continue
        resolved[role] = candidate

    if args.package.suffix.lower() != ".zip":
        errors.append("package input must be a .zip file for the selected portable ZIP model")

    zip_entry_count = 0
    package_path = resolved.get("package")
    if package_path is not None:
        if not zipfile.is_zipfile(package_path):
            errors.append("package input is not a valid ZIP archive")
        else:
            with zipfile.ZipFile(package_path, "r") as archive:
                zip_errors, zip_entry_count = validate_zip_members(archive.infolist())
                errors.extend(zip_errors)

    unique = {str(path) for path in resolved.values()}
    if len(unique) != len(resolved):
        errors.append("package, SBOM, notices and release-notes inputs must be distinct files")

    if errors:
        print("Public package binding rehearsal generation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 1

    artifacts = {role: digest(path) for role, path in sorted(resolved.items())}
    evidence = {
        "schema_version": "1.0.0",
        "gate": "PPR-06",
        "evidence_class": "PUBLIC_PACKAGE_BINDING_REHEARSAL",
        "release_authority": False,
        "publication_authorized": False,
        "signed_candidate_claimed": False,
        "distribution_format": "SIGNED_PORTABLE_ZIP",
        "publication_channel": "GITHUB_RELEASES",
        "binary_auto_update_enabled": False,
        "release_commit": args.release_commit,
        "package_zip_entry_count": zip_entry_count,
        "artifacts": artifacts,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Public package binding rehearsal written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
