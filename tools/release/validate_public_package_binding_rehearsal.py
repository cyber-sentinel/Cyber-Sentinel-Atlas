#!/usr/bin/env python3
"""Validate deterministic, non-authoritative PPR-06 package-binding rehearsal evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path

from tools.release.zip_safety import validate_zip_members

COMMIT40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_ROLES = {"package", "sbom", "third_party_notices", "release_notes"}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    args = parser.parse_args()

    errors: list[str] = []
    try:
        data = json.loads(args.binding.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Public package binding rehearsal validation FAILED: {exc}")
        return 1

    if data.get("schema_version") != "1.0.0":
        errors.append("unexpected schema_version")
    if data.get("gate") != "PPR-06":
        errors.append("binding must identify PPR-06")
    if data.get("evidence_class") != "PUBLIC_PACKAGE_BINDING_REHEARSAL":
        errors.append("unexpected evidence_class")
    if data.get("release_authority") is not False:
        errors.append("rehearsal evidence must never claim release authority")
    if data.get("publication_authorized") is not False:
        errors.append("rehearsal evidence must never authorize publication")
    if data.get("signed_candidate_claimed") is not False:
        errors.append("rehearsal evidence must never claim a signed candidate")
    if data.get("distribution_format") != "SIGNED_PORTABLE_ZIP":
        errors.append("distribution format drifted")
    if data.get("publication_channel") != "GITHUB_RELEASES":
        errors.append("publication channel drifted")
    if data.get("binary_auto_update_enabled") is not False:
        errors.append("binary auto-update must remain disabled")
    if not isinstance(data.get("release_commit"), str) or not COMMIT40.fullmatch(data["release_commit"]):
        errors.append("release_commit must be an exact 40-character lowercase SHA")

    zip_entry_count = data.get("package_zip_entry_count")
    if not isinstance(zip_entry_count, int) or isinstance(zip_entry_count, bool) or zip_entry_count <= 0:
        errors.append("package_zip_entry_count must be a positive integer")

    artifacts = data.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != EXPECTED_ROLES:
        errors.append("binding must contain exactly package/SBOM/notices/release-notes roles")
        artifacts = {}

    root = args.artifacts_dir.resolve()
    for role, item in artifacts.items():
        if not isinstance(item, dict):
            errors.append(f"{role}: artifact binding must be an object")
            continue
        name = item.get("file")
        expected_hash = item.get("sha256")
        expected_size = item.get("size_bytes")
        if not isinstance(name, str) or not name or Path(name).name != name:
            errors.append(f"{role}: file must be a basename without traversal")
            continue
        if not isinstance(expected_hash, str) or not HEX64.fullmatch(expected_hash):
            errors.append(f"{role}: invalid SHA-256")
        if not isinstance(expected_size, int) or expected_size <= 0:
            errors.append(f"{role}: invalid size_bytes")
        path = root / name
        if not path.is_file():
            errors.append(f"{role}: bound file is missing: {name}")
            continue
        if isinstance(expected_size, int) and path.stat().st_size != expected_size:
            errors.append(f"{role}: size mismatch")
        if isinstance(expected_hash, str) and HEX64.fullmatch(expected_hash):
            actual = sha256(path)
            if actual != expected_hash:
                errors.append(f"{role}: SHA-256 mismatch")

        if role == "package":
            if not zipfile.is_zipfile(path):
                errors.append("package: bound file is not a valid ZIP archive")
            else:
                with zipfile.ZipFile(path, "r") as archive:
                    zip_errors, actual_file_entries = validate_zip_members(archive.infolist())
                    errors.extend(f"package: {message}" for message in zip_errors)
                if isinstance(zip_entry_count, int) and actual_file_entries != zip_entry_count:
                    errors.append(
                        "package: ZIP file-entry count does not match binding evidence"
                    )

    if errors:
        print("Public package binding rehearsal validation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("Public package binding rehearsal validation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
