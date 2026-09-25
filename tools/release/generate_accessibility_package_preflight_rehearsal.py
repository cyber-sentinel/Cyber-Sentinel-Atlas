#!/usr/bin/env python3
"""Generate non-authoritative PPR-07 package-bound accessibility preflight evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

try:
    from tools.release.zip_safety import validate_zip_path
except ModuleNotFoundError:
    from zip_safety import validate_zip_path

COMMIT40 = re.compile(r"^[0-9a-f]{40}$")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--clean-windows-evidence", type=Path, required=True)
    parser.add_argument("--static-validator", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    errors: list[str] = []
    if not COMMIT40.fullmatch(args.release_commit):
        errors.append("release commit must be an exact 40-character lowercase SHA")

    for role, path in (
        ("package", args.package),
        ("clean-Windows evidence", args.clean_windows_evidence),
        ("static accessibility validator", args.static_validator),
    ):
        if not path.is_file():
            errors.append(f"{role} input is missing: {path}")
        elif path.stat().st_size <= 0:
            errors.append(f"{role} input must be non-empty: {path}")

    if args.package.is_file():
        zip_errors, file_count = validate_zip_path(args.package)
        errors.extend(f"package: {message}" for message in zip_errors)
        if file_count <= 0:
            errors.append("package ZIP must contain at least one file entry")

    clean: dict = {}
    if args.clean_windows_evidence.is_file():
        try:
            clean = load_json(args.clean_windows_evidence)
        except Exception as exc:
            errors.append(f"clean-Windows evidence JSON cannot be loaded: {exc}")

    package_binding = clean.get("package") if isinstance(clean, dict) else None
    if not isinstance(package_binding, dict):
        errors.append("clean-Windows evidence package binding is missing")
        package_binding = {}

    if clean:
        if clean.get("evidence_version") != 3:
            errors.append("clean-Windows evidence_version must be 3")
        if clean.get("commit") != args.release_commit:
            errors.append("clean-Windows evidence commit mismatch")
        if clean.get("release_authority") is not False:
            errors.append("clean-Windows evidence must not claim release authority")
        if clean.get("signed_candidate_claimed") is not False:
            errors.append("clean-Windows evidence must not claim a signed candidate")
        if clean.get("clean_windows_acceptance_claimed") is not False:
            errors.append("clean-Windows engineering evidence must not claim PPR-06 acceptance")

    if args.package.is_file():
        package_sha = sha256(args.package)
        if package_binding.get("file") != args.package.name:
            errors.append("clean-Windows evidence package filename mismatch")
        if package_binding.get("sha256") != package_sha:
            errors.append("clean-Windows evidence package SHA-256 mismatch")
        if package_binding.get("size_bytes") != args.package.stat().st_size:
            errors.append("clean-Windows evidence package size mismatch")

    if errors:
        print("PPR-07 package-bound accessibility preflight generation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 1

    evidence = {
        "schema_version": "1.0.0",
        "gate": "PPR-07",
        "evidence_class": "ACCESSIBILITY_PACKAGE_PREFLIGHT_REHEARSAL",
        "release_authority": False,
        "publication_authorized": False,
        "ppr07_pass_claimed": False,
        "manual_review_complete": False,
        "manual_matrix_state": "NOT_RUN",
        "manual_review_required": True,
        "release_commit": args.release_commit,
        "package": {
            "file": args.package.name,
            "sha256": sha256(args.package),
            "size_bytes": args.package.stat().st_size,
        },
        "clean_windows_evidence": {
            "file": args.clean_windows_evidence.name,
            "sha256": sha256(args.clean_windows_evidence),
        },
        "static_preflight": {
            "result": "PASS",
            "validator_file": args.static_validator.name,
            "validator_sha256": sha256(args.static_validator),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"PPR-07 package-bound accessibility preflight rehearsal written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
