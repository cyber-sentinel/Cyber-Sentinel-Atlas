#!/usr/bin/env python3
"""Validate the Phase 5.10 Public Preview readiness control plane."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs/releases/phase-5.10-public-preview-readiness.json"
ALLOWED_STATES = {"PASS", "PARTIAL", "BLOCKED", "DEFERRED"}
EXPECTED_GATE_IDS = [f"PPR-{n:02d}" for n in range(1, 12)]
REQUIRED_POLICY_FILES = [
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "THIRD_PARTY_NOTICES.md",
    "TRADEMARKS.md",
    "CITATION.cff",
]


def fail(message: str, errors: list[str]) -> None:
    errors.append(message)


def load_manifest(errors: list[str]) -> dict:
    try:
        return json.loads(MANIFEST.read_text(encoding="utf-8"))
    except Exception as exc:  # fail closed on malformed control data
        fail(f"Cannot load readiness manifest: {exc}", errors)
        return {}


def validate_baseline(data: dict, errors: list[str]) -> None:
    for rel in REQUIRED_POLICY_FILES:
        if not (ROOT / rel).is_file():
            fail(f"Missing required Public Preview policy file: {rel}", errors)

    if data.get("schema_version") != "1.0.0":
        fail("Readiness manifest schema_version must be 1.0.0", errors)
    if data.get("phase") != "5.10" or data.get("slice") != "5.10.0":
        fail("Readiness manifest must identify Phase 5.10 / slice 5.10.0", errors)
    if data.get("release_authority") != "main":
        fail("Public Preview release authority must remain main", errors)
    if data.get("overall_state") not in {"ACTIVE", "COMPLETE"}:
        fail("overall_state must be ACTIVE or COMPLETE", errors)
    if data.get("public_preview_state") not in {"BLOCKED", "READY"}:
        fail("public_preview_state must be BLOCKED or READY", errors)

    gates = data.get("gates")
    if not isinstance(gates, list):
        fail("Readiness manifest gates must be a list", errors)
        return

    ids = [gate.get("id") for gate in gates if isinstance(gate, dict)]
    if ids != EXPECTED_GATE_IDS:
        fail(
            "Readiness manifest must contain exactly ordered gates "
            + ", ".join(EXPECTED_GATE_IDS),
            errors,
        )

    seen: set[str] = set()
    mandatory_not_pass: list[str] = []
    gate_by_id: dict[str, dict] = {}
    for gate in gates:
        if not isinstance(gate, dict):
            fail("Every readiness gate must be an object", errors)
            continue
        gate_id = gate.get("id")
        if gate_id in seen:
            fail(f"Duplicate readiness gate: {gate_id}", errors)
        seen.add(gate_id)
        gate_by_id[str(gate_id)] = gate
        if not isinstance(gate.get("name"), str) or not gate.get("name", "").strip():
            fail(f"{gate_id}: name is required", errors)
        if not isinstance(gate.get("mandatory"), bool):
            fail(f"{gate_id}: mandatory must be boolean", errors)
        if gate.get("state") not in ALLOWED_STATES:
            fail(f"{gate_id}: invalid state {gate.get('state')!r}", errors)
        if not isinstance(gate.get("evidence"), str) or not gate.get("evidence", "").strip():
            fail(f"{gate_id}: evidence/blocker text is required", errors)
        if gate.get("mandatory") and gate.get("state") != "PASS":
            mandatory_not_pass.append(str(gate_id))

    if mandatory_not_pass and data.get("public_preview_state") != "BLOCKED":
        fail(
            "public_preview_state must be BLOCKED while mandatory gates are not PASS: "
            + ", ".join(mandatory_not_pass),
            errors,
        )
    if not mandatory_not_pass and data.get("public_preview_state") != "READY":
        fail("public_preview_state must be READY when all mandatory gates PASS", errors)

    license_exists = (ROOT / "LICENSE").is_file() or (ROOT / "LICENSE.md").is_file()
    license_gate = gate_by_id.get("PPR-03", {})
    if not license_exists and license_gate.get("state") != "BLOCKED":
        fail("PPR-03 must remain BLOCKED while no first-party LICENSE exists", errors)
    if license_gate.get("state") == "PASS" and not license_exists:
        fail("PPR-03 cannot PASS without a first-party LICENSE file", errors)

    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8") if (ROOT / "SECURITY.md").is_file() else ""
    if "current private-development stage" in security:
        fail("SECURITY.md contains obsolete private-development wording", errors)
    for token in ("private vulnerability", "Public Preview", "signing"):
        if token.lower() not in security.lower():
            fail(f"SECURITY.md must address {token}", errors)

    notices = (
        (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        if (ROOT / "THIRD_PARTY_NOTICES.md").is_file()
        else ""
    )
    if "non-waivable publication failure" not in notices:
        fail("THIRD_PARTY_NOTICES.md must retain fail-closed publication language", errors)

    readme = (ROOT / "README.md").read_text(encoding="utf-8") if (ROOT / "README.md").is_file() else ""
    for token in (
        "First Preview engineering readiness:** READY",
        "Release state:** Pre-preview / unreleased",
        "No technical claim without provenance",
    ):
        if token not in readme:
            fail(f"README missing Phase 5.10 prerequisite marker: {token}", errors)


def validate_release(data: dict, errors: list[str]) -> None:
    gates = data.get("gates", [])
    for gate in gates if isinstance(gates, list) else []:
        if isinstance(gate, dict) and gate.get("mandatory") and gate.get("state") != "PASS":
            fail(f"Strict release gate not closed: {gate.get('id')} — {gate.get('name')}", errors)

    if data.get("public_preview_state") != "READY":
        fail("Strict release mode requires public_preview_state=READY", errors)

    if not ((ROOT / "LICENSE").is_file() or (ROOT / "LICENSE.md").is_file()):
        fail("Strict release mode requires an approved first-party LICENSE", errors)

    evidence = ROOT / "docs/releases/public-preview-release-evidence.json"
    if not evidence.is_file():
        fail("Strict release mode requires docs/releases/public-preview-release-evidence.json", errors)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--release",
        action="store_true",
        help="Fail unless every mandatory Public Preview gate is closed.",
    )
    args = parser.parse_args()

    errors: list[str] = []
    data = load_manifest(errors)
    if data:
        validate_baseline(data, errors)
        if args.release:
            validate_release(data, errors)

    if errors:
        print("Phase 5.10 readiness validation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 1

    mode = "strict release" if args.release else "baseline"
    print(f"Phase 5.10 readiness validation passed ({mode} mode).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
