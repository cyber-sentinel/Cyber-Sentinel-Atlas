from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from tools.pack.contract import (
    LICENSE_SCHEMA,
    PACK_SCHEMA,
    PackContractError,
    load_json,
    validate_contract_pair,
    validate_manifest,
    validate_safe_target_path,
    validate_source_license_inventory,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "phase55"


def valid_manifest() -> dict:
    return load_json(FIXTURES / "valid-pack-manifest.json")


def valid_inventory() -> dict:
    return load_json(FIXTURES / "valid-source-license-inventory.json")


def valid_inventory_bytes() -> bytes:
    return (FIXTURES / "valid-source-license-inventory.json").read_bytes()


def test_pack_schemas_are_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(load_json(PACK_SCHEMA))
    Draft202012Validator.check_schema(load_json(LICENSE_SCHEMA))


def test_byte_bound_fixture_is_lf_stable_on_all_platforms() -> None:
    raw = valid_inventory_bytes()
    assert b"\r\n" not in raw
    assert raw.endswith(b"\n")


def test_valid_fixture_pair_passes_publication_gate() -> None:
    validate_contract_pair(
        valid_manifest(),
        valid_inventory(),
        inventory_bytes=valid_inventory_bytes(),
        publication=True,
    )


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
    duplicate["path"] = "content/Canonical-records.jsonl"
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


def test_manifest_timestamp_requires_canonical_utc_form() -> None:
    manifest = valid_manifest()
    manifest["created_at"] = "2026-09-06 09:30:00"
    with pytest.raises(PackContractError):
        validate_manifest(manifest)


def test_invalid_calendar_timestamp_fails_closed() -> None:
    inventory = valid_inventory()
    inventory["entries"][0]["reviewed_at"] = "2026-02-31T09:30:00Z"
    with pytest.raises(PackContractError):
        validate_source_license_inventory(inventory, publication=True)


def test_non_https_license_evidence_fails_closed() -> None:
    inventory = valid_inventory()
    inventory["entries"][0]["evidence_url"] = "http://example.invalid/license"
    with pytest.raises(PackContractError, match="HTTPS"):
        validate_source_license_inventory(inventory, publication=True)


def test_url_credentials_and_fragments_fail_closed() -> None:
    inventory = valid_inventory()
    inventory["entries"][0]["upstream_url"] = "https://user:secret@example.invalid/source"
    with pytest.raises(PackContractError, match="credentials"):
        validate_source_license_inventory(inventory, publication=True)

    inventory = valid_inventory()
    inventory["entries"][0]["evidence_url"] = "https://example.invalid/license#fragment"
    with pytest.raises(PackContractError, match="fragment"):
        validate_source_license_inventory(inventory, publication=True)


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
        validate_contract_pair(
            valid_manifest(),
            inventory,
            inventory_bytes=valid_inventory_bytes(),
            publication=True,
        )


def test_inventory_exact_byte_digest_mismatch_fails_closed() -> None:
    tampered_bytes = valid_inventory_bytes() + b" "
    with pytest.raises(PackContractError, match="byte digest mismatch"):
        validate_contract_pair(
            valid_manifest(),
            valid_inventory(),
            inventory_bytes=tampered_bytes,
            publication=True,
        )


def test_schema_rejects_unexpected_manifest_properties() -> None:
    manifest = valid_manifest()
    manifest["execute_after_install"] = "content/run.ps1"
    with pytest.raises(PackContractError, match="schema validation failed"):
        validate_manifest(manifest)


def test_fixtures_are_canonical_json_objects() -> None:
    for name in ("valid-pack-manifest.json", "valid-source-license-inventory.json"):
        value = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        assert isinstance(value, dict)
