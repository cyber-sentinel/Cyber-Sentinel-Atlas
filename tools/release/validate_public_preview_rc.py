#!/usr/bin/env python3
"""Validate the Phase 5.10.7 Public Preview RC freeze and readiness state."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RC_PATH = ROOT / "docs/releases/public-preview-rc-readiness.json"
PPR_PATH = ROOT / "docs/releases/phase-5.10-public-preview-readiness.json"
CONTRACT_PATH = ROOT / "docs/releases/public-preview-rc-contract.md"

EXPECTED_COMMANDS = (
    "core_status",
    "search_records",
    "get_record",
    "expand_graph",
    "pack_status",
    "pack_update",
    "pack_rollback",
)

REQUIRED_ALLOWED = {
    "SECURITY_FIX",
    "CORRECTNESS_FIX",
    "RELEASE_ENGINEERING_FIX",
    "ACCESSIBILITY_FIX",
    "LICENSE_AND_ATTRIBUTION_CLOSURE",
    "PRODUCTION_SIGNING_INTEGRATION",
    "PUBLIC_PACK_CLOSURE",
    "NON_BEHAVIORAL_VISUAL_IDENTITY",
    "DOCUMENTATION_CORRECTION",
}


def load_json(path: Path, errors: list[str]) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"Cannot load {path.relative_to(ROOT)}: {exc}")
        return {}


def validate_baseline(rc: dict, ppr: dict, errors: list[str]) -> None:
    if not CONTRACT_PATH.is_file():
        errors.append("Missing Public Preview RC contract")
        contract = ""
    else:
        contract = CONTRACT_PATH.read_text(encoding="utf-8")

    if rc.get("schema_version") != "1.0.0":
        errors.append("RC readiness schema_version must be 1.0.0")
    if rc.get("phase") != "5.10.7":
        errors.append("RC readiness phase must be 5.10.7")
    if rc.get("target_version") != "0.1.0-rc.1":
        errors.append("RC target_version must be 0.1.0-rc.1")
    if rc.get("state") not in {"BLOCKED", "READY"}:
        errors.append("RC state must be BLOCKED or READY")
    if rc.get("functional_freeze") is not True:
        errors.append("Functional freeze must remain enabled")
    if rc.get("visual_identity_freeze") is not False:
        errors.append("Visual identity must remain outside the functional freeze")
    if rc.get("distribution_format") != "SIGNED_PORTABLE_ZIP":
        errors.append("RC distribution format must remain SIGNED_PORTABLE_ZIP")
    if rc.get("publication_channel") != "GITHUB_RELEASES":
        errors.append("RC publication channel must remain GITHUB_RELEASES")
    if rc.get("binary_auto_update_enabled") is not False:
        errors.append("Binary auto-update must remain disabled")

    baseline = rc.get("functional_freeze_baseline")
    if not isinstance(baseline, str) or not re.fullmatch(r"[0-9a-f]{40}", baseline):
        errors.append("functional_freeze_baseline must be an exact 40-character commit SHA")

    allowed = rc.get("allowed_post_freeze_change_classes")
    if not isinstance(allowed, list) or set(allowed) != REQUIRED_ALLOWED:
        errors.append("Allowed post-freeze change classes drifted from the accepted contract")

    reset = rc.get("freeze_reset_required_for")
    if not isinstance(reset, list) or len(reset) < 10:
        errors.append("Freeze-reset conditions are incomplete")

    for command in EXPECTED_COMMANDS:
        if ("§" + command + "§").replace("§", chr(96)) not in contract:
            errors.append(f"RC contract missing frozen desktop command: {command}")

    for token in (
        "Visual identity remains intentionally open",
        "ATLAS Blue and Tactical Dark Green",
        "no default local HTTP/TCP/WebSocket listener",
        "v0.1.0-rc.1",
    ):
        if token not in contract:
            errors.append(f"RC contract missing required token: {token}")

    gates = [
        gate for gate in ppr.get("gates", [])
        if isinstance(gate, dict) and gate.get("mandatory") is True
    ]
    open_gates = [str(gate.get("id")) for gate in gates if gate.get("state") != "PASS"]
    if open_gates and rc.get("state") != "BLOCKED":
        errors.append(
            "RC state must remain BLOCKED while mandatory PPR gates are open: "
            + ", ".join(open_gates)
        )
    if not open_gates and rc.get("state") != "READY":
        errors.append("RC state must be READY when every mandatory PPR gate is PASS")


def validate_strict_rc(rc: dict, ppr: dict, errors: list[str]) -> None:
    gates = [
        gate for gate in ppr.get("gates", [])
        if isinstance(gate, dict) and gate.get("mandatory") is True
    ]
    open_gates = [str(gate.get("id")) for gate in gates if gate.get("state") != "PASS"]
    if open_gates:
        errors.append("Strict RC gate has open mandatory PPR gates: " + ", ".join(open_gates))

    if rc.get("state") != "READY":
        errors.append("Strict RC mode requires state=READY")

    release_commit = rc.get("release_commit")
    if not isinstance(release_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", release_commit):
        errors.append("release_commit must be an exact 40-character SHA")

    for field in (
        "signed_package_sha256",
        "public_pack_sha256",
        "sbom_sha256",
        "third_party_notices_sha256",
        "release_notes_sha256",
    ):
        value = rc.get(field)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            errors.append(f"{field} must be a lowercase SHA-256")

    for field in (
        "clean_windows_acceptance",
        "accessibility_acceptance",
        "published_bytes_reverified",
    ):
        if rc.get(field) is not True:
            errors.append(f"Strict RC mode requires {field}=true")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--release-candidate",
        action="store_true",
        help="Fail unless the exact Public Preview RC is fully release-authorized.",
    )
    args = parser.parse_args()

    errors: list[str] = []
    rc = load_json(RC_PATH, errors)
    ppr = load_json(PPR_PATH, errors)
    if rc and ppr:
        validate_baseline(rc, ppr, errors)
        if args.release_candidate:
            validate_strict_rc(rc, ppr, errors)

    if errors:
        print("Public Preview RC validation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 1

    mode = "strict release-candidate" if args.release_candidate else "freeze baseline"
    print(f"Public Preview RC validation passed ({mode} mode).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
