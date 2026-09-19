#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FOUNDATION_PATH = ROOT / "tools" / "ingestion" / "validate_ingestion_foundation.py"

SPEC = importlib.util.spec_from_file_location("atlas_ingestion_foundation_inventory", FOUNDATION_PATH)
foundation = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(foundation)

INVENTORY_PATHS = {
    "windows_provider": ROOT / "ingestion/inventories/windows-security-auditing-provider-26100.33296.telemetry.json",
    "windows_4688_docs": ROOT / "ingestion/inventories/windows-security-4688-doc-learn-page-2022-01-24.documentation.json",
    "sysmon_schema": ROOT / "ingestion/inventories/sysmon-schema-15.22-4.91.telemetry.json",
    "sysmon_docs": ROOT / "ingestion/inventories/sysmon-docs-15.22.documentation.json",
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def event_ids(inventory: dict) -> list[str]:
    identities = inventory.get("scope_metadata", {}).get("expected_identities")
    if not isinstance(identities, list):
        raise ValueError(f"{inventory.get('inventory_id')}: expected_identities must be an array")
    values: list[str] = []
    for index, identity in enumerate(identities):
        if not isinstance(identity, dict) or not isinstance(identity.get("event_id"), str) or not identity["event_id"]:
            raise ValueError(f"{inventory.get('inventory_id')}: expected_identities[{index}] lacks string event_id")
        values.append(identity["event_id"])
    if len(values) != len(set(values)):
        raise ValueError(f"{inventory.get('inventory_id')}: duplicate event_id in expected_identities")
    if inventory.get("expected_identity_count") != len(values):
        raise ValueError(f"{inventory.get('inventory_id')}: expected_identity_count does not match expected_identities")
    return values


def validate_inventory(name: str, inventory: dict) -> list[str]:
    errors: list[str] = []
    validator = foundation.ingestion_validator("inventory-definition.schema.json")
    schema_errors = sorted(validator.iter_errors(inventory), key=lambda e: list(e.path))
    errors.extend(f"{name}: schema: {error.message}" for error in schema_errors)
    if inventory.get("digest") != foundation.digest_without_field(inventory, "digest"):
        errors.append(f"{name}: digest does not bind complete inventory definition")
    try:
        event_ids(inventory)
    except ValueError as exc:
        errors.append(str(exc))
    return errors


def reconcile(inventories: dict[str, dict]) -> dict:
    errors: list[str] = []
    for name, inventory in inventories.items():
        errors.extend(validate_inventory(name, inventory))

    if errors:
        return {"errors": errors}

    windows_provider = set(event_ids(inventories["windows_provider"]))
    windows_docs = set(event_ids(inventories["windows_4688_docs"]))
    sysmon_schema = set(event_ids(inventories["sysmon_schema"]))
    sysmon_docs = set(event_ids(inventories["sysmon_docs"]))

    wp = inventories["windows_provider"]["scope_metadata"]
    wd = inventories["windows_4688_docs"]["scope_metadata"]
    ss = inventories["sysmon_schema"]["scope_metadata"]
    sd = inventories["sysmon_docs"]["scope_metadata"]

    if wp.get("provider") != wd.get("provider") or wp.get("channel") != wd.get("channel"):
        errors.append("Windows documentation/provider reconciliation scope disagrees on provider or channel")
    if ss.get("provider") != sd.get("provider") or ss.get("channel") != sd.get("channel"):
        errors.append("Sysmon documentation/schema reconciliation scope disagrees on provider or channel")

    if not windows_docs.issubset(windows_provider):
        errors.append("documented Windows identities are not present in the declared current provider inventory")
    if "4688" not in windows_provider or windows_docs != {"4688"}:
        errors.append("Windows acceptance identity 4688 is not reconciled exactly")
    if "592" in windows_provider:
        errors.append("legacy acceptance identity 592 unexpectedly appears in the declared current provider inventory")

    if sysmon_docs != sysmon_schema:
        errors.append("Sysmon 15.22 documentation and controlled Sysmon 15.22/schema 4.91 identity sets drifted")
    if "1" not in sysmon_schema:
        errors.append("Sysmon acceptance identity 1 is missing from the current schema inventory")

    windows_provider_only = sorted(windows_provider - windows_docs, key=int)
    sysmon_schema_only = sorted(sysmon_schema - sysmon_docs, key=int)
    sysmon_docs_only = sorted(sysmon_docs - sysmon_schema, key=int)

    return {
        "errors": errors,
        "windows": {
            "provider_inventory_id": inventories["windows_provider"]["inventory_id"],
            "documentation_inventory_id": inventories["windows_4688_docs"]["inventory_id"],
            "provider_identity_count": len(windows_provider),
            "documented_identity_count_in_declared_scope": len(windows_docs),
            "documented_and_observed": sorted(windows_docs & windows_provider, key=int),
            "provider_only_count": len(windows_provider_only),
            "provider_only_sample": windows_provider_only[:20],
            "legacy_592_current_provider_status": "NOT_OBSERVED",
            "legacy_592_canonical_action": "PRESERVE_HISTORICAL_IDENTITY",
            "documentation_is_telemetry_denominator": False,
        },
        "sysmon": {
            "schema_inventory_id": inventories["sysmon_schema"]["inventory_id"],
            "documentation_inventory_id": inventories["sysmon_docs"]["inventory_id"],
            "current_schema_identity_count": len(sysmon_schema),
            "documented_identity_count": len(sysmon_docs),
            "schema_only": sysmon_schema_only,
            "docs_only": sysmon_docs_only,
            "identity_sets_equal_for_pinned_release": sysmon_schema == sysmon_docs,
            "independent_denominators_even_when_counts_match": True,
        },
        "semantics": {
            "not_observed_is_removed": False,
            "documentation_and_telemetry_coverage_are_independent": True,
            "event_id_is_globally_unique": False,
            "phase54_search_projection_materialized": False,
        },
    }


def validate_repository(root: Path = ROOT) -> tuple[list[str], dict]:
    global ROOT, INVENTORY_PATHS
    ROOT = Path(root)
    INVENTORY_PATHS = {
        "windows_provider": ROOT / "ingestion/inventories/windows-security-auditing-provider-26100.33296.telemetry.json",
        "windows_4688_docs": ROOT / "ingestion/inventories/windows-security-4688-doc-learn-page-2022-01-24.documentation.json",
        "sysmon_schema": ROOT / "ingestion/inventories/sysmon-schema-15.22-4.91.telemetry.json",
        "sysmon_docs": ROOT / "ingestion/inventories/sysmon-docs-15.22.documentation.json",
    }
    inventories = {name: load(path) for name, path in INVENTORY_PATHS.items()}
    report = reconcile(inventories)
    return report.get("errors", []), report


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate and reconcile Phase 5.3.3 Windows/Sysmon authoritative inventories.")
    ap.add_argument("--json", action="store_true", help="Emit deterministic JSON report")
    args = ap.parse_args()

    errors, report = validate_repository(ROOT)
    if args.json:
        print(json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    if errors:
        if not args.json:
            for error in errors:
                print(error)
        return 1

    if not args.json:
        print(
            "Phase 5.3.3 Windows/Sysmon inventory reconciliation PASSED: "
            f"Windows provider={report['windows']['provider_identity_count']} "
            f"Windows docs={report['windows']['documented_identity_count_in_declared_scope']} "
            f"Sysmon schema={report['sysmon']['current_schema_identity_count']} "
            f"Sysmon docs={report['sysmon']['documented_identity_count']}."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
