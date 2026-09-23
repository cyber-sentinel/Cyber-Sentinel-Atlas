#!/usr/bin/env python3
"""Validate Phase 5.6.4 clean-Windows evidence against exact package/probe bytes."""

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


def validate_evidence(
    data: dict,
    *,
    package: Path,
    probe: Path,
    recovery_probe: Path,
    expected_commit: str,
) -> list[str]:
    errors: list[str] = []

    if not COMMIT40.fullmatch(expected_commit):
        errors.append("expected commit must be an exact 40-character lowercase SHA")
    if data.get("evidence_version") != 3:
        errors.append("evidence_version must be 3")
    if data.get("phase") != "5.6.4":
        errors.append("phase must be 5.6.4")
    if data.get("commit") != expected_commit:
        errors.append("evidence commit does not match expected commit")
    if data.get("release_authority") is not False:
        errors.append("clean-Windows evidence must not claim release authority")
    if data.get("signed_candidate_claimed") is not False:
        errors.append("engineering evidence must not claim a signed candidate")
    if data.get("clean_windows_acceptance_claimed") is not False:
        errors.append("engineering evidence must not claim PPR-06 clean-Windows acceptance")

    for path, role in (
        (package, "package"),
        (probe, "portable probe"),
        (recovery_probe, "recovery probe"),
    ):
        if not path.is_file():
            errors.append(f"{role} input is missing: {path}")

    if package.is_file():
        zip_errors, file_count = validate_zip_path(package)
        errors.extend(f"package: {message}" for message in zip_errors)
        if file_count <= 0:
            errors.append("package ZIP must contain at least one file entry")

    package_evidence = data.get("package")
    if not isinstance(package_evidence, dict):
        errors.append("package evidence must be an object")
        package_evidence = {}
    if package.is_file():
        if package_evidence.get("file") != package.name:
            errors.append("package filename binding mismatch")
        if package_evidence.get("sha256") != sha256(package):
            errors.append("package SHA-256 binding mismatch")
        if package_evidence.get("size_bytes") != package.stat().st_size:
            errors.append("package size binding mismatch")
    package_sha = package_evidence.get("sha256")
    if not isinstance(package_sha, str) or not HEX64.fullmatch(package_sha):
        errors.append("package SHA-256 must be lowercase hex")

    probes = data.get("probe_evidence")
    if not isinstance(probes, dict):
        errors.append("probe_evidence must be an object")
        probes = {}

    for key, path, expected_name in (
        ("portable_probe", probe, "phase564-probe.json"),
        ("recovery_probe", recovery_probe, "phase564-recovery-probe.json"),
    ):
        item = probes.get(key)
        if not isinstance(item, dict):
            errors.append(f"{key} binding must be an object")
            continue
        if item.get("file") != expected_name or path.name != expected_name:
            errors.append(f"{key} filename binding mismatch")
        if path.is_file() and item.get("sha256") != sha256(path):
            errors.append(f"{key} SHA-256 binding mismatch")

    for path, role in ((probe, "portable probe"), (recovery_probe, "recovery probe")):
        if not path.is_file():
            continue
        try:
            payload = load_json(path)
        except Exception as exc:
            errors.append(f"{role} JSON cannot be loaded: {exc}")
            continue
        status = payload.get("status_result")
        if not isinstance(status, dict):
            errors.append(f"{role} status_result is missing")
            continue
        if status.get("core_commit") != expected_commit:
            errors.append(f"{role} core_commit mismatch")
        if status.get("network_listener") is not False:
            errors.append(f"{role} must prove network_listener=false")
        if status.get("offline_capable") is not True:
            errors.append(f"{role} must prove offline_capable=true")

    clean = data.get("clean_environment")
    if not isinstance(clean, dict):
        errors.append("clean_environment must be an object")
    else:
        if clean.get("runner") != "github-hosted":
            errors.append("clean_environment.runner must be github-hosted")
        if clean.get("image") != "windows-latest":
            errors.append("clean_environment.image must be windows-latest")

    webview = data.get("webview2")
    if not isinstance(webview, dict):
        errors.append("webview2 evidence must be an object")
    else:
        if webview.get("required") is not True or webview.get("present") is not True:
            errors.append("WebView2 prerequisite must be required and present")
        if webview.get("downloaded_by_atlas") is not False:
            errors.append("ATLAS must not download WebView2 at runtime")

    gui = data.get("gui")
    if not isinstance(gui, dict) or gui.get("launched") is not True:
        errors.append("GUI launch evidence must be present")

    network = data.get("network")
    if not isinstance(network, dict):
        errors.append("network evidence must be an object")
    else:
        if network.get("tcp_listener_seen") is not False:
            errors.append("clean GUI tree must prove tcp_listener_seen=false")
        if network.get("atlas_or_core_udp_endpoint_seen") is not False:
            errors.append("ATLAS/Core must prove no UDP endpoint")

    if data.get("integrity_negative_test") != "PASS_FAIL_CLOSED":
        errors.append("sidecar corruption negative test must pass fail-closed")
    if data.get("recovery_after_verified_restore") != "PASS":
        errors.append("verified sidecar recovery must pass")
    if data.get("portable_relocation") != "PASS":
        errors.append("portable relocation must pass")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--recovery-probe", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()

    try:
        data = load_json(args.evidence)
    except Exception as exc:
        print(f"Phase 5.6.4 clean-Windows evidence validation FAILED: {exc}")
        return 1

    errors = validate_evidence(
        data,
        package=args.package,
        probe=args.probe,
        recovery_probe=args.recovery_probe,
        expected_commit=args.expected_commit,
    )
    if errors:
        print("Phase 5.6.4 clean-Windows evidence validation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("Phase 5.6.4 package-bound clean-Windows evidence validation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
