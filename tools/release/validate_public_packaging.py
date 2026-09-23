#!/usr/bin/env python3
"""Validate Phase 5.10.3 public packaging/distribution readiness."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "docs/releases/public-packaging-readiness.json"
POLICY = ROOT / "docs/releases/public-packaging-and-distribution.md"
REHEARSAL_GENERATOR = ROOT / "tools/release/generate_public_package_binding_rehearsal.py"
REHEARSAL_VALIDATOR = ROOT / "tools/release/validate_public_package_binding_rehearsal.py"
ZIP_SAFETY = ROOT / "tools/release/zip_safety.py"

HEX64 = re.compile(r"^[0-9a-f]{64}$")
COMMIT40 = re.compile(r"^[0-9a-f]{40}$")


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()

    errors: list[str] = []
    try:
        data = json.loads(STATE.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(errors, f"invalid/missing packaging readiness JSON: {exc}")
        data = {}

    for path in (POLICY, REHEARSAL_GENERATOR, REHEARSAL_VALIDATOR, ZIP_SAFETY):
        if not path.is_file():
            fail(errors, f"missing packaging control artifact: {path.relative_to(ROOT)}")

    if data:
        if data.get("schema_version") != "1.0.0":
            fail(errors, "unexpected schema_version")
        if data.get("gate") != "PPR-06":
            fail(errors, "state must identify PPR-06")
        if data.get("state") not in {"BLOCKED", "PASS"}:
            fail(errors, "state must be BLOCKED or PASS")

        bool_fields = (
            "distribution_format_selected",
            "publication_channel_selected",
            "signature_verified",
            "timestamp_verified",
            "clean_windows_acceptance",
            "knowledge_pack_acceptance",
            "network_posture_acceptance",
            "corruption_rejection_acceptance",
            "upgrade_acceptance",
            "rollback_recovery_acceptance",
            "uninstall_or_remove_acceptance",
            "accessibility_package_sha_bound",
            "published_bytes_reverified",
            "binary_auto_update_enabled",
        )
        for field in bool_fields:
            if not isinstance(data.get(field), bool):
                fail(errors, f"{field} must be boolean")

        if data.get("distribution_format_selected") is True:
            if data.get("distribution_format") != "SIGNED_PORTABLE_ZIP":
                fail(errors, "selected Public Preview format must remain SIGNED_PORTABLE_ZIP")
        if data.get("publication_channel_selected") is True:
            if data.get("publication_channel") != "GITHUB_RELEASES":
                fail(errors, "selected Public Preview channel must remain GITHUB_RELEASES")
        if data.get("binary_auto_update_enabled") is not False:
            fail(errors, "binary auto-update must remain disabled for the initial Public Preview")

        release_commit = data.get("release_commit")
        if release_commit is not None and (
            not isinstance(release_commit, str) or not COMMIT40.fullmatch(release_commit)
        ):
            fail(errors, "release_commit must be null or an exact 40-character lowercase SHA")

        hash_fields = (
            "signed_package_sha256",
            "sbom_sha256",
            "third_party_notices_sha256",
            "release_notes_sha256",
            "package_binding_evidence_sha256",
            "clean_windows_package_sha256",
            "accessibility_package_sha256",
            "published_package_sha256",
        )
        for field in hash_fields:
            value = data.get(field)
            if value is not None and (
                not isinstance(value, str) or not HEX64.fullmatch(value)
            ):
                fail(errors, f"{field} must be null or lowercase SHA-256 hex")

        size = data.get("signed_package_size_bytes")
        if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size <= 0):
            fail(errors, "signed_package_size_bytes must be null or a positive integer")

        if data.get("signature_verified") is True and data.get("timestamp_verified") is not True:
            fail(errors, "signature_verified=true requires timestamp_verified=true")

        package_sha = data.get("signed_package_sha256")
        package_bindings = (
            ("clean_windows_package_sha256", "clean_windows_acceptance"),
            ("accessibility_package_sha256", "accessibility_package_sha_bound"),
            ("published_package_sha256", "published_bytes_reverified"),
        )
        for hash_field, flag_field in package_bindings:
            bound_sha = data.get(hash_field)
            flag = data.get(flag_field)
            if flag is True:
                if not isinstance(package_sha, str) or not HEX64.fullmatch(package_sha):
                    fail(errors, f"{flag_field}=true requires signed_package_sha256")
                if bound_sha != package_sha:
                    fail(
                        errors,
                        f"{flag_field}=true requires {hash_field} to equal signed_package_sha256",
                    )
            elif bound_sha is not None:
                fail(errors, f"{hash_field} may be set only when {flag_field}=true")

        if data.get("published_bytes_reverified") is True:
            for dependency in (
                "signature_verified",
                "timestamp_verified",
                "clean_windows_acceptance",
                "knowledge_pack_acceptance",
                "network_posture_acceptance",
                "corruption_rejection_acceptance",
                "rollback_recovery_acceptance",
                "accessibility_package_sha_bound",
            ):
                if data.get(dependency) is not True:
                    fail(
                        errors,
                        f"published_bytes_reverified=true requires {dependency}=true",
                    )
            audit_id = data.get("publication_verification_run_or_audit_id")
            if not isinstance(audit_id, str) or not audit_id.strip():
                fail(
                    errors,
                    "published_bytes_reverified=true requires publication_verification_run_or_audit_id",
                )

        required_true = (
            "distribution_format_selected",
            "publication_channel_selected",
            "signature_verified",
            "timestamp_verified",
            "clean_windows_acceptance",
            "knowledge_pack_acceptance",
            "network_posture_acceptance",
            "corruption_rejection_acceptance",
            "upgrade_acceptance",
            "rollback_recovery_acceptance",
            "uninstall_or_remove_acceptance",
            "accessibility_package_sha_bound",
            "published_bytes_reverified",
        )
        ready = all(data.get(field) is True for field in required_true)
        ready = ready and data.get("distribution_format") == "SIGNED_PORTABLE_ZIP"
        ready = ready and data.get("publication_channel") == "GITHUB_RELEASES"
        ready = ready and isinstance(release_commit, str) and bool(COMMIT40.fullmatch(release_commit))
        ready = ready and isinstance(size, int) and not isinstance(size, bool) and size > 0
        ready = ready and all(
            isinstance(data.get(field), str) and bool(HEX64.fullmatch(data[field]))
            for field in (
                "signed_package_sha256",
                "sbom_sha256",
                "third_party_notices_sha256",
                "release_notes_sha256",
                "package_binding_evidence_sha256",
            )
        )
        ready = ready and all(
            data.get(field) == data.get("signed_package_sha256")
            for field in (
                "clean_windows_package_sha256",
                "accessibility_package_sha256",
                "published_package_sha256",
            )
        )
        ready = ready and isinstance(
            data.get("publication_verification_run_or_audit_id"), str
        ) and bool(data["publication_verification_run_or_audit_id"].strip())
        ready = ready and data.get("binary_auto_update_enabled") is False

        if data.get("state") == "PASS" and not ready:
            fail(
                errors,
                "PPR-06 cannot PASS without exact selected channel/format, package identity "
                "bindings and complete acceptance/publication evidence",
            )
        if data.get("state") == "BLOCKED" and ready:
            fail(
                errors,
                "PPR-06 is mechanically ready but BLOCKED; require explicit reviewed state transition",
            )
        if args.release and data.get("state") != "PASS":
            fail(errors, "strict release mode requires PPR-06 PASS")

    if POLICY.is_file():
        text = POLICY.read_text(encoding="utf-8")
        for token in (
            "Signed portable ZIP",
            "Signed MSI",
            "Signed MSIX",
            "PPR-06 remains **BLOCKED**",
            "binary auto-update",
            "Package Binding Rehearsal",
            "release_authority=false",
            "Windows ZIP entry safety",
        ):
            if token not in text:
                fail(errors, f"packaging policy missing token: {token}")

    if errors:
        print("PPR-06 packaging validation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 1

    mode = "strict release" if args.release else "baseline"
    print(f"PPR-06 packaging validation passed ({mode} mode).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
