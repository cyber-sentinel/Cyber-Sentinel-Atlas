"""Phase 5.5.1 Atlas pack-contract validation helpers.

This module validates declarative pack metadata only. It does not implement TUF
signature verification, archive extraction, installation, activation, or rollback.
Those runtime responsibilities are Phase 5.5.2.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker

REPO_ROOT = Path(__file__).resolve().parents[2]
PACK_SCHEMA = REPO_ROOT / "schemas" / "pack" / "v1" / "pack-manifest.schema.json"
LICENSE_SCHEMA = REPO_ROOT / "schemas" / "pack" / "v1" / "source-license-inventory.schema.json"

WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
ACTIVE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".msi", ".msp", ".com", ".scr",
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".lnk", ".reg", ".sh", ".py", ".pl",
    ".rb", ".jar", ".class", ".so", ".dylib", ".appx", ".msix",
    ".deb", ".rpm", ".apk",
}
DRIVE_QUALIFIED = re.compile(r"^[A-Za-z]:")
UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class PackContractError(ValueError):
    """Raised when Atlas pack metadata violates a Phase 5.5.1 invariant."""


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise PackContractError(f"{path}: top-level JSON value must be an object")
    return value


def sha256_prefixed(data: bytes) -> str:
    return "sha256-" + hashlib.sha256(data).hexdigest()


def _validator(schema_path: Path) -> Draft202012Validator:
    schema = load_json(schema_path)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _validate_utc_timestamp(value: str, *, field: str) -> None:
    if not UTC_TIMESTAMP.fullmatch(value):
        raise PackContractError(f"{field} must use canonical UTC YYYY-MM-DDTHH:MM:SSZ form")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise PackContractError(f"{field} is not a valid UTC timestamp") from exc


def _validate_https_url(value: str, *, field: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme.casefold() != "https" or not parsed.netloc:
        raise PackContractError(f"{field} must be an absolute HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise PackContractError(f"{field} must not contain URL credentials")
    if parsed.fragment:
        raise PackContractError(f"{field} must not contain a fragment")


def validate_safe_target_path(path: str, *, expected_prefixes: tuple[str, ...]) -> None:
    if not path or len(path) > 512:
        raise PackContractError("target path is empty or exceeds 512 characters")
    if "\\" in path or "\x00" in path:
        raise PackContractError(f"unsafe target path: {path!r}")
    if path.startswith("/") or DRIVE_QUALIFIED.match(path):
        raise PackContractError(f"absolute/drive-qualified target path: {path!r}")

    pure = PurePosixPath(path)
    parts = pure.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise PackContractError(f"non-canonical target path: {path!r}")
    if pure.as_posix() != path:
        raise PackContractError(f"non-canonical target path: {path!r}")
    if not any(path.startswith(prefix) for prefix in expected_prefixes):
        raise PackContractError(f"target path outside permitted namespace: {path!r}")

    for part in parts:
        stripped = part.rstrip(" .")
        if stripped != part or not stripped:
            raise PackContractError(f"Windows-ambiguous target component: {part!r}")
        stem = stripped.split(".", 1)[0].upper()
        if stem in WINDOWS_RESERVED:
            raise PackContractError(f"Windows-reserved target component: {part!r}")

    if pure.suffix.casefold() in ACTIVE_EXTENSIONS:
        raise PackContractError(f"active-code extension is forbidden in content packs: {path!r}")


def validate_manifest(manifest: dict[str, Any]) -> None:
    errors = sorted(_validator(PACK_SCHEMA).iter_errors(manifest), key=lambda e: list(e.path))
    if errors:
        raise PackContractError("pack manifest schema validation failed: " + "; ".join(e.message for e in errors))

    _validate_utc_timestamp(manifest["created_at"], field="created_at")

    seen: set[str] = set()
    for artifact in manifest["artifacts"]:
        path = artifact["path"]
        validate_safe_target_path(path, expected_prefixes=("content/", "search/"))
        folded = path.casefold()
        if folded in seen:
            raise PackContractError(f"duplicate/case-colliding artifact path: {path!r}")
        seen.add(folded)
        if artifact["kind"] in {"spc", "search-index"} and artifact["derived"] is not True:
            raise PackContractError(f"derived search artifact must declare derived=true: {path!r}")
        if artifact["kind"] == "canonical-records" and artifact["derived"] is not False:
            raise PackContractError(f"canonical records must declare derived=false: {path!r}")


def validate_source_license_inventory(inventory: dict[str, Any], *, publication: bool) -> None:
    errors = sorted(_validator(LICENSE_SCHEMA).iter_errors(inventory), key=lambda e: list(e.path))
    if errors:
        raise PackContractError("source/license inventory schema validation failed: " + "; ".join(e.message for e in errors))

    seen: set[str] = set()
    for entry in inventory["entries"]:
        source_id = entry["source_id"]
        if source_id in seen:
            raise PackContractError(f"duplicate source_id: {source_id!r}")
        seen.add(source_id)

        _validate_https_url(entry["upstream_url"], field=f"{source_id}.upstream_url")
        _validate_https_url(entry["evidence_url"], field=f"{source_id}.evidence_url")
        _validate_utc_timestamp(entry["reviewed_at"], field=f"{source_id}.reviewed_at")

        if entry["redistribution_scope"] == "included":
            if entry["license_status"] != "verified-redistributable":
                raise PackContractError(
                    f"included source is not verified redistributable: {source_id!r}"
                )

        if publication and entry["license_status"] in {"unknown", "incompatible"}:
            raise PackContractError(f"publication inventory contains blocked license state: {source_id!r}")


def validate_contract_pair(
    manifest: dict[str, Any],
    inventory: dict[str, Any],
    *,
    inventory_bytes: bytes,
    publication: bool,
) -> None:
    validate_manifest(manifest)
    validate_source_license_inventory(inventory, publication=publication)
    if manifest["pack_id"] != inventory["pack_id"]:
        raise PackContractError("manifest/inventory pack_id mismatch")
    if manifest["pack_version"] != inventory["pack_version"]:
        raise PackContractError("manifest/inventory pack_version mismatch")

    declared = manifest["source_license_inventory"]["digest"]
    actual = sha256_prefixed(inventory_bytes)
    if declared != actual:
        raise PackContractError(
            f"source/license inventory byte digest mismatch: declared={declared}, actual={actual}"
        )
