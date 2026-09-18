#!/usr/bin/env python3
"""Validate Phase 5.10.1 third-party redistribution closure evidence."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "docs" / "releases" / "third-party-redistribution-inventory.json"
POLICY = ROOT / "docs" / "releases" / "third-party-redistribution-closure.md"
NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"
FINAL_RELEASE_NOTICES = ROOT / "docs" / "releases" / "public-preview-third-party-notices.md"
TAURI_EVIDENCE_TOOL = ROOT / "tools" / "release" / "generate_tauri_redistribution_evidence.py"
TAURI_EVIDENCE_WORKFLOW = ROOT / ".github" / "workflows" / "phase5101-redistribution-closure.yml"
NOTICE_GENERATOR = ROOT / "tools" / "release" / "generate_public_preview_notice_bundle.py"
ALLOWED_ENTRY_STATES = {
    "ACCEPTED",
    "CONDITIONALLY_CLEARABLE",
    "REVIEW_REQUIRED",
    "BUILD_EVIDENCE_REQUIRED",
    "EXCLUDED",
    "EXCLUDED_CURRENT_MODEL",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def load_inventory(errors: list[str]) -> dict:
    try:
        return json.loads(INVENTORY.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(errors, f"cannot load redistribution inventory: {exc}")
        return {}


def validate_baseline(data: dict, errors: list[str]) -> None:
    for path in (INVENTORY, POLICY, NOTICES, TAURI_EVIDENCE_TOOL, TAURI_EVIDENCE_WORKFLOW, NOTICE_GENERATOR):
        if not path.is_file():
            fail(errors, f"missing redistribution control artifact: {path.relative_to(ROOT)}")

    if data.get("schema_version") != "1.0.0":
        fail(errors, "redistribution inventory schema_version must be 1.0.0")
    if data.get("gate") != "PPR-04":
        fail(errors, "redistribution inventory must identify PPR-04")
    if data.get("state") not in {"BLOCKED", "PASS"}:
        fail(errors, "redistribution inventory state must be BLOCKED or PASS")
    for field in ("public_preview_corpus_frozen", "software_payload_frozen"):
        if not isinstance(data.get(field), bool):
            fail(errors, f"{field} must be boolean")

    entries = data.get("entries")
    if not isinstance(entries, list) or not entries:
        fail(errors, "redistribution inventory entries must be a non-empty list")
        return

    seen: set[str] = set()
    unresolved_included: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            fail(errors, "every redistribution inventory entry must be an object")
            continue
        entry_id = entry.get("id")
        if not isinstance(entry_id, str) or not entry_id.strip():
            fail(errors, "every redistribution inventory entry needs a non-empty id")
            continue
        if entry_id in seen:
            fail(errors, f"duplicate redistribution inventory id: {entry_id}")
        seen.add(entry_id)
        if not isinstance(entry.get("included"), bool):
            fail(errors, f"{entry_id}: included must be boolean")
        state = entry.get("redistribution_state")
        if state not in ALLOWED_ENTRY_STATES:
            fail(errors, f"{entry_id}: invalid redistribution_state {state!r}")
        for field in ("class", "upstream_revision", "license_or_terms", "required_notices", "review_evidence"):
            if not isinstance(entry.get(field), str) or not entry.get(field, "").strip():
                fail(errors, f"{entry_id}: {field} is required")
        if entry.get("included") and state != "ACCEPTED":
            unresolved_included.append(entry_id)
        if entry.get("included") and state == "ACCEPTED":
            if not isinstance(entry.get("license_source"), str) or not entry.get("license_source", "").strip():
                fail(errors, f"{entry_id}: ACCEPTED included entry requires license_source")

    package_sha = data.get("release_package_sha256")
    if package_sha is not None and (not isinstance(package_sha, str) or not SHA256_RE.fullmatch(package_sha)):
        fail(errors, "release_package_sha256 must be null or 64 lowercase hex characters")

    ready_conditions = (
        data.get("public_preview_corpus_frozen") is True
        and data.get("software_payload_frozen") is True
        and isinstance(package_sha, str)
        and bool(SHA256_RE.fullmatch(package_sha))
        and not unresolved_included
    )
    if data.get("state") == "PASS" and not ready_conditions:
        fail(errors, "PPR-04 inventory cannot PASS until payload/corpus are frozen, package SHA is bound, and every included entry is ACCEPTED")
    if data.get("state") == "BLOCKED" and ready_conditions:
        fail(errors, "PPR-04 inventory is mechanically ready but still marked BLOCKED; require an explicit reviewed state transition")

    policy = POLICY.read_text(encoding="utf-8") if POLICY.is_file() else ""
    for token in (
        "Unknown, ambiguous, incompatible, or unverified rights remain a non-waivable publication failure.",
        "allowlist, not a denylist",
    ):
        if token not in policy:
            fail(errors, f"redistribution closure policy missing required token: {token}")
    if data.get("state") == "BLOCKED":
        for token in ("Status: **IN PROGRESS / FAIL-CLOSED**", "PPR-04 remains **BLOCKED**"):
            if token not in policy:
                fail(errors, f"blocked redistribution policy missing required token: {token}")
    elif data.get("state") == "PASS" and "Status: **CLOSED / RELEASE-SCOPED**" not in policy:
        fail(errors, "closed redistribution policy must record Status: **CLOSED / RELEASE-SCOPED**")

    tauri_entries = [
        entry for entry in entries
        if isinstance(entry, dict) and entry.get("id") == "tauri-rust-runtime"
    ]
    if len(tauri_entries) != 1:
        fail(errors, "redistribution inventory must contain exactly one tauri-rust-runtime entry")
    else:
        review_evidence = tauri_entries[0].get("review_evidence", "")
        for token in (
            "generate_tauri_redistribution_evidence.py",
            "phase5101-redistribution-closure.yml",
        ):
            if token not in review_evidence:
                fail(errors, f"tauri-rust-runtime review_evidence must reference {token}")

    notices = NOTICES.read_text(encoding="utf-8") if NOTICES.is_file() else ""
    if "non-waivable publication failure" not in notices:
        fail(errors, "THIRD_PARTY_NOTICES.md must preserve non-waivable publication failure wording")


def validate_release(data: dict, errors: list[str]) -> None:
    if data.get("state") != "PASS":
        fail(errors, "strict redistribution release mode requires state=PASS")
    if data.get("public_preview_corpus_frozen") is not True:
        fail(errors, "strict redistribution release mode requires frozen Public Preview corpus")
    if data.get("software_payload_frozen") is not True:
        fail(errors, "strict redistribution release mode requires frozen software payload")
    package_sha = data.get("release_package_sha256")
    if not isinstance(package_sha, str) or not SHA256_RE.fullmatch(package_sha):
        fail(errors, "strict redistribution release mode requires exact release package SHA-256")
    for entry in data.get("entries", []):
        if isinstance(entry, dict) and entry.get("included") and entry.get("redistribution_state") != "ACCEPTED":
            fail(errors, f"strict redistribution release mode unresolved included entry: {entry.get('id')}")
    if not FINAL_RELEASE_NOTICES.is_file():
        fail(errors, f"strict redistribution release mode requires {FINAL_RELEASE_NOTICES.relative_to(ROOT)}")
    else:
        final_notices = FINAL_RELEASE_NOTICES.read_text(encoding="utf-8")
        if package_sha and package_sha not in final_notices:
            fail(errors, "final third-party notices are not bound to the exact release package SHA-256")
        if "Status: **RELEASE-SCOPED / PACKAGE-BOUND**" not in final_notices:
            fail(errors, "final third-party notices must record release-scoped/package-bound status")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", action="store_true", help="Require full PPR-04 release closure")
    args = parser.parse_args()
    errors: list[str] = []
    data = load_inventory(errors)
    if data:
        validate_baseline(data, errors)
        if args.release:
            validate_release(data, errors)
    if errors:
        print("PPR-04 redistribution validation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"PPR-04 redistribution validation passed ({'strict release' if args.release else 'baseline'} mode).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
