#!/usr/bin/env python3
"""Validate non-authoritative PPR-07 package-bound accessibility preflight evidence."""

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
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def validate(
    data: dict,
    *,
    package: Path,
    clean_evidence: Path,
    static_validator: Path,
    expected_commit: str,
) -> list[str]:
    errors: list[str] = []

    if not COMMIT40.fullmatch(expected_commit):
        errors.append("expected commit must be an exact 40-character lowercase SHA")
    if data.get("schema_version") != "1.0.0":
        errors.append("schema_version must be 1.0.0")
    if data.get("gate") != "PPR-07":
        errors.append("gate must be PPR-07")
    if data.get("evidence_class") != "ACCESSIBILITY_PACKAGE_PREFLIGHT_REHEARSAL":
        errors.append("unexpected evidence_class")
    for field in ("release_authority", "publication_authorized", "ppr07_pass_claimed", "manual_review_complete"):
        if data.get(field) is not False:
            errors.append(f"{field} must remain false in preflight rehearsal evidence")
    if data.get("manual_matrix_state") != "NOT_RUN":
        errors.append("manual_matrix_state must remain NOT_RUN")
    if data.get("manual_review_required") is not True:
        errors.append("manual_review_required must remain true")
    if data.get("release_commit") != expected_commit:
        errors.append("release_commit mismatch")

    for path, role in (
        (package, "package"),
        (clean_evidence, "clean-Windows evidence"),
        (static_validator, "static validator"),
    ):
        if not path.is_file():
            errors.append(f"{role} input is missing: {path}")

    if package.is_file():
        zip_errors, file_count = validate_zip_path(package)
        errors.extend(f"package: {message}" for message in zip_errors)
        if file_count <= 0:
            errors.append("package ZIP must contain at least one file entry")

    pkg = data.get("package")
    if not isinstance(pkg, dict):
        errors.append("package binding must be an object")
        pkg = {}
    if package.is_file():
        if pkg.get("file") != package.name:
            errors.append("package filename binding mismatch")
        if pkg.get("sha256") != sha256(package):
            errors.append("package SHA-256 binding mismatch")
        if pkg.get("size_bytes") != package.stat().st_size:
            errors.append("package size binding mismatch")
    if not isinstance(pkg.get("sha256"), str) or not HEX64.fullmatch(pkg["sha256"]):
        errors.append("package SHA-256 must be lowercase hex")

    clean_binding = data.get("clean_windows_evidence")
    if not isinstance(clean_binding, dict):
        errors.append("clean_windows_evidence binding must be an object")
        clean_binding = {}
    if clean_evidence.is_file():
        if clean_binding.get("file") != clean_evidence.name:
            errors.append("clean-Windows evidence filename binding mismatch")
        if clean_binding.get("sha256") != sha256(clean_evidence):
            errors.append("clean-Windows evidence SHA-256 binding mismatch")
        try:
            clean = load_json(clean_evidence)
        except Exception as exc:
            errors.append(f"clean-Windows evidence JSON cannot be loaded: {exc}")
            clean = {}
        if clean:
            if clean.get("commit") != expected_commit:
                errors.append("clean-Windows evidence commit mismatch")
            clean_pkg = clean.get("package")
            if not isinstance(clean_pkg, dict):
                errors.append("clean-Windows package binding missing")
            elif package.is_file():
                if clean_pkg.get("file") != package.name:
                    errors.append("clean-Windows package filename mismatch")
                if clean_pkg.get("sha256") != sha256(package):
                    errors.append("clean-Windows package SHA-256 mismatch")
                if clean_pkg.get("size_bytes") != package.stat().st_size:
                    errors.append("clean-Windows package size mismatch")
            if clean.get("release_authority") is not False:
                errors.append("clean-Windows evidence must not claim release authority")
            if clean.get("signed_candidate_claimed") is not False:
                errors.append("clean-Windows evidence must not claim a signed candidate")
            if clean.get("clean_windows_acceptance_claimed") is not False:
                errors.append("clean-Windows evidence must not claim PPR-06 acceptance")

    preflight = data.get("static_preflight")
    if not isinstance(preflight, dict):
        errors.append("static_preflight must be an object")
        preflight = {}
    if preflight.get("result") != "PASS":
        errors.append("static_preflight.result must be PASS")
    if static_validator.is_file():
        if preflight.get("validator_file") != static_validator.name:
            errors.append("static validator filename binding mismatch")
        if preflight.get("validator_sha256") != sha256(static_validator):
            errors.append("static validator SHA-256 binding mismatch")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--clean-windows-evidence", type=Path, required=True)
    parser.add_argument("--static-validator", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()

    try:
        data = load_json(args.evidence)
    except Exception as exc:
        print(f"PPR-07 package-bound accessibility preflight validation FAILED: {exc}")
        return 1

    errors = validate(
        data,
        package=args.package,
        clean_evidence=args.clean_windows_evidence,
        static_validator=args.static_validator,
        expected_commit=args.expected_commit,
    )
    if errors:
        print("PPR-07 package-bound accessibility preflight validation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("PPR-07 package-bound accessibility preflight rehearsal validation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
