#!/usr/bin/env python3
"""Validate byte-identical pinned third-party license material for PPR-04."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MATERIAL_MANIFEST = ROOT / "third_party/license-material/manifest.json"
REDISTRIBUTION_INVENTORY = ROOT / "docs/releases/third-party-redistribution-inventory.json"
EXPECTED_IDS = {
    "mitre-attack-enterprise",
    "mitre-car",
    "mitre-d3fend-ontology",
    "microsoft-sysmon-documentation",
}
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")


def git_blob_sha1(raw: bytes) -> str:
    header = f"blob {len(raw)}\0".encode("ascii")
    return hashlib.sha1(header + raw).hexdigest()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_json(path: Path, errors: list[str]) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"cannot load {path.relative_to(ROOT)}: {exc}")
        return {}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()

    errors: list[str] = []
    manifest = load_json(MATERIAL_MANIFEST, errors)
    inventory = load_json(REDISTRIBUTION_INVENTORY, errors)

    if manifest.get("schema_version") != "1.0.0":
        errors.append("license-material manifest schema_version must be 1.0.0")
    if manifest.get("gate") != "PPR-04":
        errors.append("license-material manifest must identify PPR-04")
    if manifest.get("state") != "EVIDENCE_ONLY_NOT_ACCEPTANCE":
        errors.append("license-material manifest must remain evidence-only")

    materials = manifest.get("materials")
    if not isinstance(materials, list):
        errors.append("license-material manifest materials must be a list")
        materials = []

    ids = {item.get("id") for item in materials if isinstance(item, dict)}
    if ids != EXPECTED_IDS:
        errors.append(
            "pinned license-material set drifted; expected exactly: "
            + ", ".join(sorted(EXPECTED_IDS))
        )

    inventory_by_id = {
        entry.get("id"): entry
        for entry in inventory.get("entries", [])
        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    }

    evidence_items: list[dict] = []
    for item in sorted(
        (x for x in materials if isinstance(x, dict)),
        key=lambda x: str(x.get("id")),
    ):
        item_id = item.get("id")
        local_path = item.get("local_path")
        upstream_blob = item.get("upstream_git_blob_sha1")
        upstream_revision = item.get("upstream_revision")

        if item.get("redistribution_state_change") is not False:
            errors.append(f"{item_id}: redistribution_state_change must remain false")
        if not isinstance(upstream_blob, str) or not SHA1_RE.fullmatch(upstream_blob):
            errors.append(f"{item_id}: invalid upstream Git blob SHA-1")
        if not isinstance(upstream_revision, str) or not SHA1_RE.fullmatch(upstream_revision):
            errors.append(f"{item_id}: upstream_revision must be exact 40-char commit SHA")
        if not isinstance(local_path, str) or not local_path.strip():
            errors.append(f"{item_id}: local_path is required")
            continue

        path = ROOT / local_path
        if not path.is_file():
            errors.append(f"{item_id}: local license material missing: {local_path}")
            continue

        raw = path.read_bytes()
        actual_blob = git_blob_sha1(raw)
        if isinstance(upstream_blob, str) and actual_blob != upstream_blob:
            errors.append(
                f"{item_id}: local bytes do not match pinned upstream Git blob "
                f"(expected {upstream_blob}, got {actual_blob})"
            )

        inventory_entry = inventory_by_id.get(item_id)
        if not isinstance(inventory_entry, dict):
            errors.append(f"{item_id}: matching redistribution inventory entry missing")
        else:
            if inventory_entry.get("included") is not True:
                errors.append(f"{item_id}: pinned material exists for a non-included entry")
            if inventory_entry.get("redistribution_state") != "CONDITIONALLY_CLEARABLE":
                errors.append(
                    f"{item_id}: pinned license material must not auto-promote redistribution state; "
                    f"found {inventory_entry.get('redistribution_state')!r}"
                )
            inventory_revision = str(inventory_entry.get("upstream_revision", ""))
            if isinstance(upstream_revision, str) and upstream_revision not in inventory_revision:
                errors.append(f"{item_id}: manifest revision is not bound in redistribution inventory")
            if item.get("license_or_terms") != inventory_entry.get("license_or_terms"):
                errors.append(f"{item_id}: license/terms label drifted from redistribution inventory")

        evidence_items.append(
            {
                "id": item_id,
                "local_path": local_path,
                "upstream_repository": item.get("upstream_repository"),
                "upstream_revision": upstream_revision,
                "upstream_path": item.get("upstream_path"),
                "upstream_git_blob_sha1": upstream_blob,
                "verified_local_git_blob_sha1": actual_blob,
                "local_sha256": sha256(raw),
                "size_bytes": len(raw),
            }
        )

    evidence = {
        "schema_version": "1.0.0",
        "gate": "PPR-04",
        "evidence_class": "PINNED_THIRD_PARTY_LICENSE_MATERIAL",
        "release_authority": False,
        "material_count": len(evidence_items),
        "materials": evidence_items,
        "error_count": len(errors),
    }

    if args.evidence:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if errors:
        print("Pinned third-party license-material validation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 1

    print(
        "Pinned third-party license-material validation passed: "
        f"{len(evidence_items)} byte-identical upstream license files."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
