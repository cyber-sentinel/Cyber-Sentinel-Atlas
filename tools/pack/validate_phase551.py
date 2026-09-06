"""Closure validator for Phase 5.5.1 Pack Trust Contracts."""
from __future__ import annotations

import sys
from pathlib import Path

from contract import load_json, validate_contract_pair

ROOT = Path(__file__).resolve().parents[2]

REQUIRED_FILES = (
    ROOT / "docs" / "adr" / "0023-secure-content-pack-trust-and-update-model.md",
    ROOT / "docs" / "architecture" / "atlas-tuf-pouf-v1.md",
    ROOT / "docs" / "architecture" / "phase-5.5.1-pack-trust-contracts.md",
    ROOT / "schemas" / "pack" / "v1" / "pack-manifest.schema.json",
    ROOT / "schemas" / "pack" / "v1" / "source-license-inventory.schema.json",
    ROOT / "tests" / "fixtures" / "phase55" / "valid-pack-manifest.json",
    ROOT / "tests" / "fixtures" / "phase55" / "valid-source-license-inventory.json",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    for path in REQUIRED_FILES:
        require(path.is_file(), f"missing Phase 5.5.1 file: {path.relative_to(ROOT)}")

    adr = REQUIRED_FILES[0].read_text(encoding="utf-8")
    require(
        "**Status:** Accepted" in adr,
        "ADR-0023 must be Accepted before Phase 5.5.1 can close",
    )
    require("The Update Framework (TUF)" in adr, "ADR-0023 must bind the TUF trust model")
    require(".atlaspack" in adr, "ADR-0023 must bind the .atlaspack transport")
    require("No content activation without a trusted root chain" in adr, "ADR-0023 trust invariant missing")

    pouf = REQUIRED_FILES[1].read_text(encoding="utf-8")
    for role in ("Root", "Targets", "Snapshot", "Timestamp"):
        require(role in pouf, f"Atlas TUF profile missing role: {role}")
    require("Consistent snapshots: required" in pouf, "production consistent-snapshot policy missing")

    pack_schema = load_json(REQUIRED_FILES[3])
    inventory_schema = load_json(REQUIRED_FILES[4])
    require(pack_schema.get("$id") == "https://cyber-sentinel.net/schemas/pack/v1/pack-manifest.schema.json", "unexpected Pack Manifest schema id")
    require(inventory_schema.get("$id") == "https://cyber-sentinel.net/schemas/pack/v1/source-license-inventory.schema.json", "unexpected Source/License Inventory schema id")
    require(pack_schema.get("properties", {}).get("pack_format_version", {}).get("const") == "1.0.0", "Pack Manifest version must be 1.0.0")
    require(inventory_schema.get("properties", {}).get("inventory_version", {}).get("const") == "1.0.0", "Source/License Inventory version must be 1.0.0")

    manifest = load_json(REQUIRED_FILES[5])
    inventory = load_json(REQUIRED_FILES[6])
    validate_contract_pair(manifest, inventory, publication=True)

    # Phase 5.5.1 is a parallel pack schema family. It must never masquerade as
    # another canonical AtlasRecord family under schemas/v1.
    canonical_root = ROOT / "schemas" / "v1"
    require(canonical_root.is_dir(), "canonical schemas/v1 missing")
    require(not (canonical_root / "pack-manifest.schema.json").exists(), "pack schema leaked into canonical schemas/v1")

    print("Phase 5.5.1 Pack Trust Contracts: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Phase 5.5.1 Pack Trust Contracts: FAIL: {exc}", file=sys.stderr)
        raise
