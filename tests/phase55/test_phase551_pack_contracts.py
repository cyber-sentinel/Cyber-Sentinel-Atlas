from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tools.pack.contract import (
    PackContractError,
    PACK_SCHEMA,
    LICENSE_SCHEMA,
    load_json,
    validate_contract_pair,
    validate_manifest,
    validate_safe_target_path,
    validate_source_license_inventory,
)
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "phase55"


def valid_manifest() -> dict:
    return load_json(FIXTURES / "valid-pack-manifest.json")


def valid_inventory() -> dict:
    return load_json(FIXTURES / "valid-source-license-inventory.json")


def test_pack_schemas_are_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(load_json(PACK_SCHEMA))
    Draft202012Validator.check_schema(load_json(LICENSE_SCHEMA))


def test_valid_fixture_pair_passes_publication_gate() -> None:
    validate_contract_pair(valid_manifest(), valid_inventory(), publication=True)


@pytest.mark.parametrize(
    "path",
    [
        "../content/data.json",
        "content/../evil.json",
        "/content/data.json",
        "C:/content/data.json",
        "content\\evil.json",
        "content/CON.json",
        "content/aux.txt",
        "content/name. ",
        "content/run.exe",
        "content/run.ps1",
        "content/module.dll",
    ],
)
def test_unsafe_or_active_target_paths_fail_closed(path: str) -> None:
    with pytest.raises(PackContractError):
        validate_safe_target_path(path, expected_prefixes=("content/", "search/"))


def test_path_outside_pack_payload_namespace_fails_closed() -> None:
    with pytest.raises(PackContractError):
        validate_safe_target_path("atlas/control.json", expected_prefixes=("content/", "search/"))


def test_duplicate_case_colliding_artifacts_fail_closed() -> None:
    manifest = valid_manifest()
    duplicate = copy.deepcopy(manifest["artifacts"][0])
    duplicate["path"] = "CONTENT/canonical-records.jsonl"
    manifest["artifacts"].append(duplicate)
    with pytest.raises(PackContractError, match="duplicate/case-colliding"):
        validate_manifest(manifest)


def test_spc_and_search_index_must_be_derived() -> None:
    manifest = valid_manifest()
    manifest["artifacts"][1]["derived"] = False
    with pytest.raises(PackContractError, match="derived search artifact"):
        validate_manifest(manifest)


def test_canonical_records_cannot_be_declared_derived() -> None:
    manifest = valid_manifest()
    manifest["artifacts"][0]["derived"] = True
    with pytest.raises(PackContractError, match="canonical records"):
        validate_manifest(manifest)


def test_included_source_with_unknown_license_fails_closed() -> None:
    inventory = valid_inventory()
    inventory["entries"][0]["license_status"] = "unknown"
    with pytest.raises(PackContractError, match="not verified redistributable"):
        validate_source_license_inventory(inventory, publication=True)


def test_reference_only_unknown_source_is_still_blocked_for_publication() -> None:
    inventory = valid_inventory()
    inventory["entries"][0]["redistribution_scope"] = "reference-only"
    inventory["entries"][0]["license_status"] = "unknown"
    with pytest.raises(PackContractError, match="blocked license state"):
        validate_source_license_inventory(inventory, publication=True)


def test_reference_only_unknown_source_can_be_inspected_non_publication() -> None:
    inventory = valid_inventory()
    inventory["entries"][0]["redistribution_scope"] = "reference-only"
    inventory["entries"][0]["license_status"] = "unknown"
    validate_source_license_inventory(inventory, publication=False)


def test_manifest_inventory_identity_mismatch_fails_closed() -> None:
    inventory = valid_inventory()
    inventory["pack_version"] = "1.0.1-test.1"
    with pytest.raises(PackContractError, match="pack_version mismatch"):
        validate_contract_pair(valid_manifest(), inventory, publication=True)


def test_schema_rejects_unexpected_manifest_properties() -> None:
    manifest = valid_manifest()
    manifest["execute_after_install"] = "content/run.ps1"
    with pytest.raises(PackContractError, match="schema validation failed"):
        validate_manifest(manifest)


def test_fixtures_are_canonical_json_objects() -> None:
    for name in ("valid-pack-manifest.json", "valid-source-license-inventory.json"):
        value = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        assert isinstance(value, dict)
