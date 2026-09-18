#!/usr/bin/env python3
"""Generate deterministic Public Preview third-party notice metadata for PPR-04.

This tool does not grant redistribution rights and does not synthesize upstream
license text. It renders the reviewed inventory into a deterministic draft, and
fails closed in release mode unless the inventory is already release-closed and
bound to the exact package SHA-256.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INVENTORY = ROOT / "docs/releases/third-party-redistribution-inventory.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_inventory(path: Path) -> tuple[dict, bytes]:
    raw = path.read_bytes()
    data = json.loads(raw.decode("utf-8"))
    return data, raw


def validate_inventory(data: dict, package_sha: str | None, release: bool) -> list[str]:
    errors: list[str] = []
    if data.get("schema_version") != "1.0.0":
        errors.append("inventory schema_version must be 1.0.0")
    if data.get("gate") != "PPR-04":
        errors.append("inventory must identify PPR-04")

    entries = data.get("entries")
    if not isinstance(entries, list) or not entries:
        errors.append("inventory entries must be a non-empty list")
        return errors

    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            errors.append("every inventory entry must be an object")
            continue
        entry_id = entry.get("id")
        if not isinstance(entry_id, str) or not entry_id.strip():
            errors.append("every inventory entry requires a non-empty id")
            continue
        if entry_id in seen:
            errors.append(f"duplicate inventory id: {entry_id}")
        seen.add(entry_id)
        if not isinstance(entry.get("included"), bool):
            errors.append(f"{entry_id}: included must be boolean")
        for field in (
            "class",
            "upstream_revision",
            "license_or_terms",
            "redistribution_state",
            "required_notices",
            "review_evidence",
        ):
            value = entry.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{entry_id}: {field} is required")

    if package_sha is not None and not SHA256_RE.fullmatch(package_sha):
        errors.append("--package-sha256 must be 64 lowercase hex characters")

    if release:
        if data.get("state") != "PASS":
            errors.append("release mode requires inventory state=PASS")
        if data.get("public_preview_corpus_frozen") is not True:
            errors.append("release mode requires public_preview_corpus_frozen=true")
        if data.get("software_payload_frozen") is not True:
            errors.append("release mode requires software_payload_frozen=true")
        inventory_sha = data.get("release_package_sha256")
        if not isinstance(inventory_sha, str) or not SHA256_RE.fullmatch(inventory_sha):
            errors.append("release mode requires inventory release_package_sha256")
        if package_sha is None:
            errors.append("release mode requires --package-sha256")
        elif isinstance(inventory_sha, str) and package_sha != inventory_sha:
            errors.append("package SHA does not match inventory release_package_sha256")

        for entry in entries:
            if (
                isinstance(entry, dict)
                and entry.get("included") is True
                and entry.get("redistribution_state") != "ACCEPTED"
            ):
                errors.append(
                    f"{entry.get('id')}: included entry is not ACCEPTED "
                    f"({entry.get('redistribution_state')})"
                )
            if isinstance(entry, dict) and entry.get("included") is True:
                source = entry.get("license_source")
                if not isinstance(source, str) or not source.strip():
                    errors.append(f"{entry.get('id')}: included release entry requires license_source")

    return errors


def render(data: dict, inventory_digest: str, package_sha: str | None, release: bool) -> str:
    entries = [entry for entry in data["entries"] if isinstance(entry, dict)]
    included = sorted((entry for entry in entries if entry.get("included") is True), key=lambda x: x["id"])
    excluded = sorted((entry for entry in entries if entry.get("included") is False), key=lambda x: x["id"])

    status = "RELEASE-SCOPED / PACKAGE-BOUND" if release else "DRAFT / NOT RELEASE AUTHORITY"
    package_binding = package_sha if package_sha else "UNBOUND"

    lines = [
        "# Public Preview Third-Party Notices",
        "",
        f"Status: **{status}**",
        "",
        f"Inventory SHA-256: `{inventory_digest}`",
        f"Release package SHA-256: `{package_binding}`",
        "",
        "This file is generated deterministically from the PPR-04 redistribution inventory.",
        "It records reviewed source identity, declared terms, required notices and review evidence.",
        "It does **not** grant redistribution rights, replace upstream license text, or constitute legal approval.",
        "",
        "## Included payload entries",
        "",
    ]

    for entry in included:
        lines.extend(
            [
                f"### {entry['id']}",
                "",
                f"- Class: `{entry['class']}`",
                f"- Upstream revision: {entry['upstream_revision']}",
                f"- License / terms: {entry['license_or_terms']}",
                f"- License source: {entry.get('license_source') or 'NOT RECORDED'}",
                f"- Redistribution state: **{entry['redistribution_state']}**",
                f"- Required notices: {entry['required_notices']}",
                f"- Review evidence: {entry['review_evidence']}",
                "",
            ]
        )

    lines.extend(["## Excluded / prerequisite-only entries", ""])
    for entry in excluded:
        lines.extend(
            [
                f"### {entry['id']}",
                "",
                f"- Class: `{entry['class']}`",
                f"- Included: **NO**",
                f"- Redistribution state: **{entry['redistribution_state']}**",
                f"- Boundary: {entry['required_notices']}",
                f"- Review evidence: {entry['review_evidence']}",
                "",
            ]
        )

    lines.extend(
        [
            "## Release rule",
            "",
            "A final Public Preview notice bundle is valid only when every included inventory entry is `ACCEPTED`,",
            "the software payload and public corpus are frozen, and this file is bound to the exact release package SHA-256.",
            "Unknown, conditional, build-evidence-required, or otherwise unresolved included content remains fail-closed.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--package-sha256")
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()

    try:
        data, raw = load_inventory(args.inventory)
    except Exception as exc:
        print(f"PPR-04 notice generation FAILED: cannot load inventory: {exc}", file=sys.stderr)
        return 1

    errors = validate_inventory(data, args.package_sha256, args.release)
    if errors:
        print("PPR-04 notice generation FAILED:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    rendered = render(data, sha256_bytes(raw), args.package_sha256, args.release)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8", newline="\n")
    mode = "release" if args.release else "draft"
    print(f"PPR-04 {mode} notice bundle written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
