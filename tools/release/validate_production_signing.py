#!/usr/bin/env python3
"""Validate Phase 5.10.2 production signing and key-custody evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "docs/releases/production-signing-readiness.json"
POLICY = ROOT / "docs/releases/production-signing-and-key-custody.md"
VERIFIER = ROOT / "tools/release/verify_windows_authenticode.ps1"

HEX64 = re.compile(r"^[0-9a-f]{64}$")
COMMIT40 = re.compile(r"^[0-9a-f]{40}$")
ALLOWED_CUSTODY_CLASSES = {
    "MANAGED_CLOUD_HARDWARE_BACKED",
    "ORG_HSM_KMS_SERVICE",
    "DEDICATED_HARDWARE_TOKEN_OR_HSM",
}
ALLOWED_DIGEST_ALGORITHMS = {"SHA256", "SHA384", "SHA512"}


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def parse_timestamp(value: object, field: str, errors: list[str]) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        fail(errors, f"{field} must be null or a non-empty RFC3339 timestamp")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(errors, f"{field} must be RFC3339/ISO-8601 compatible")
        return None
    if parsed.tzinfo is None:
        fail(errors, f"{field} must include an explicit timezone")
        return None
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()

    errors: list[str] = []
    if not STATE.is_file():
        fail(errors, "missing production-signing-readiness.json")
        data: dict = {}
    else:
        try:
            data = json.loads(STATE.read_text(encoding="utf-8"))
        except Exception as exc:
            fail(errors, f"invalid signing readiness JSON: {exc}")
            data = {}

    if not POLICY.is_file():
        fail(errors, "missing production signing policy")
    if not VERIFIER.is_file():
        fail(errors, "missing provider-neutral Windows Authenticode verifier")

    if data:
        if data.get("schema_version") != "1.0.0":
            fail(errors, "unexpected signing schema_version")
        if data.get("gate") != "PPR-05":
            fail(errors, "signing state must identify PPR-05")
        if data.get("state") not in {"BLOCKED", "PASS"}:
            fail(errors, "signing state must be BLOCKED or PASS")
        if data.get("timestamp_policy") != "RFC3161_REQUIRED":
            fail(errors, "RFC3161 timestamp policy is mandatory")
        if data.get("authenticode_digest_policy") != "SHA256_OR_STRONGER":
            fail(errors, "Authenticode digest policy must remain SHA256_OR_STRONGER")
        if data.get("private_key_exportable") is True:
            fail(errors, "production signing private key must not be exportable")

        custody = data.get("custody_class")
        if custody is not None and custody not in ALLOWED_CUSTODY_CLASSES:
            fail(errors, f"unsupported custody_class: {custody!r}")

        if data.get("provider_selected") is True:
            if not isinstance(data.get("signing_provider"), str) or not data["signing_provider"].strip():
                fail(errors, "provider_selected=true requires signing_provider")
            if custody not in ALLOWED_CUSTODY_CLASSES:
                fail(errors, "provider_selected=true requires an accepted custody_class")
            if data.get("private_key_exportable") is not False:
                fail(errors, "provider_selected=true requires private_key_exportable=false")

        release_commit = data.get("release_commit")
        if release_commit is not None and (
            not isinstance(release_commit, str) or not COMMIT40.fullmatch(release_commit)
        ):
            fail(errors, "release_commit must be null or an exact 40-character lowercase commit SHA")

        hash_fields = (
            "unsigned_artifact_sha256",
            "signed_artifact_sha256",
            "sbom_sha256",
            "certificate_sha256_fingerprint",
            "verification_evidence_sha256",
            "release_attestation_sha256",
        )
        for field in hash_fields:
            value = data.get(field)
            if value is not None and (
                not isinstance(value, str) or not HEX64.fullmatch(value)
            ):
                fail(errors, f"{field} must be null or lowercase SHA-256 hex")

        for field in ("signature_digest_algorithm", "timestamp_digest_algorithm"):
            value = data.get(field)
            if value is not None and value not in ALLOWED_DIGEST_ALGORITHMS:
                fail(errors, f"{field} must be null or one of {sorted(ALLOWED_DIGEST_ALGORITHMS)}")

        not_before = parse_timestamp(data.get("certificate_not_before"), "certificate_not_before", errors)
        not_after = parse_timestamp(data.get("certificate_not_after"), "certificate_not_after", errors)
        if not_before and not_after and not_before >= not_after:
            fail(errors, "certificate_not_before must be earlier than certificate_not_after")

        bool_fields = (
            "certificate_chain_verified",
            "certificate_code_signing_eku_verified",
            "certificate_validity_verified",
            "rfc3161_timestamp_verified",
            "timestamp_chain_verified",
            "windows_trust_verified",
            "signature_verified",
            "rotation_procedure_documented",
            "revocation_procedure_documented",
            "compromise_response_documented",
        )
        for field in bool_fields:
            if not isinstance(data.get(field), bool):
                fail(errors, f"{field} must be boolean")

        if data.get("signature_verified") is True:
            for dependency in (
                "certificate_chain_verified",
                "certificate_code_signing_eku_verified",
                "certificate_validity_verified",
                "rfc3161_timestamp_verified",
                "timestamp_chain_verified",
                "windows_trust_verified",
            ):
                if data.get(dependency) is not True:
                    fail(errors, f"signature_verified=true requires {dependency}=true")

        unsigned_sha = data.get("unsigned_artifact_sha256")
        signed_sha = data.get("signed_artifact_sha256")
        if (
            isinstance(unsigned_sha, str)
            and HEX64.fullmatch(unsigned_sha)
            and isinstance(signed_sha, str)
            and HEX64.fullmatch(signed_sha)
            and unsigned_sha == signed_sha
        ):
            fail(errors, "embedded Authenticode signing must change the artifact SHA-256")

        ready = all(
            [
                data.get("provider_selected") is True,
                isinstance(data.get("signing_provider"), str) and bool(data["signing_provider"].strip()),
                custody in ALLOWED_CUSTODY_CLASSES,
                isinstance(data.get("certificate_subject"), str) and bool(data["certificate_subject"].strip()),
                isinstance(data.get("certificate_serial"), str) and bool(data["certificate_serial"].strip()),
                isinstance(data.get("certificate_sha256_fingerprint"), str)
                and bool(HEX64.fullmatch(data["certificate_sha256_fingerprint"])),
                not_before is not None,
                not_after is not None,
                data.get("private_key_exportable") is False,
                isinstance(release_commit, str) and bool(COMMIT40.fullmatch(release_commit)),
                all(
                    isinstance(data.get(field), str) and bool(HEX64.fullmatch(data[field]))
                    for field in (
                        "unsigned_artifact_sha256",
                        "signed_artifact_sha256",
                        "sbom_sha256",
                        "verification_evidence_sha256",
                        "release_attestation_sha256",
                    )
                ),
                data.get("signature_digest_algorithm") in ALLOWED_DIGEST_ALGORITHMS,
                data.get("timestamp_digest_algorithm") in ALLOWED_DIGEST_ALGORITHMS,
                data.get("certificate_chain_verified") is True,
                data.get("certificate_code_signing_eku_verified") is True,
                data.get("certificate_validity_verified") is True,
                data.get("rfc3161_timestamp_verified") is True,
                data.get("timestamp_chain_verified") is True,
                data.get("windows_trust_verified") is True,
                data.get("signature_verified") is True,
                isinstance(data.get("verification_tool"), str) and bool(data["verification_tool"].strip()),
                isinstance(data.get("signing_run_or_audit_id"), str)
                and bool(data["signing_run_or_audit_id"].strip()),
                data.get("rotation_procedure_documented") is True,
                data.get("revocation_procedure_documented") is True,
                data.get("compromise_response_documented") is True,
            ]
        )

        if data.get("state") == "PASS" and not ready:
            fail(
                errors,
                "PPR-05 cannot PASS without complete provider/custody/certificate "
                "and independently verified exact signed-artifact evidence",
            )
        if data.get("state") == "BLOCKED" and ready:
            fail(
                errors,
                "PPR-05 is mechanically ready but still BLOCKED; "
                "require explicit reviewed state transition",
            )
        if args.release and data.get("state") != "PASS":
            fail(errors, "strict release mode requires PPR-05 PASS")

    if POLICY.is_file():
        policy = POLICY.read_text(encoding="utf-8")
        for token in (
            "non-exportable",
            "RFC 3161",
            "PPR-05 remains **BLOCKED**",
            "No production private key, PFX",
            "verify_windows_authenticode.ps1",
            "Code Signing EKU",
        ):
            if token not in policy:
                fail(errors, f"signing policy missing required token: {token}")

    if VERIFIER.is_file():
        verifier = VERIFIER.read_text(encoding="utf-8")
        for token in (
            "Get-AuthenticodeSignature",
            "signtoolArgs = @('verify', '/pa', '/all', '/v', '/tw'",
            "1.3.6.1.5.5.7.3.3",
            "TimeStamperCertificate",
            "ExpectedCertificateSha256Fingerprint",
            "ExpectedCertificateSubject",
            "signed_artifact_sha256",
            "windows_trust_verification",
        ):
            if token not in verifier:
                fail(errors, f"Authenticode verifier missing required control token: {token}")

    if errors:
        print("PPR-05 signing validation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 1

    mode = "strict release" if args.release else "baseline"
    print(f"PPR-05 signing validation passed ({mode} mode).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
