"""Offline TUF + Atlas verification for extracted Phase 5.5.2 content packs."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterator
from urllib.parse import unquote, urlsplit

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from tuf.api.exceptions import DownloadHTTPError
from tuf.api.metadata import Metadata
from tuf.ngclient import Updater
from tuf.ngclient.config import UpdaterConfig
from tuf.ngclient.fetcher import FetcherInterface

from tools.pack.contract import (
    PackContractError,
    load_json,
    validate_contract_pair,
)
from tools.pack.versioning import VersionError, require_runtime_compatible
from tools.search.sqlite_search import (
    SQLiteSearchCore,
    SearchIndexValidationError,
    build_index,
    validate_projection_bundle,
)

ROOT = Path(__file__).resolve().parents[2]
CURRENT_RUNTIME_VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
CANONICAL_SCHEMA_ROOT = ROOT / "schemas" / "v1"
CONTROL_TARGETS = {
    "atlas/pack-manifest.json",
    "atlas/source-license-inventory.json",
}
REQUIRED_METADATA = {"root.json", "timestamp.json", "snapshot.json", "targets.json"}
VERSIONED_ROOT_RE = re.compile(r"^[1-9][0-9]*\.root\.json$")
VERSIONED_METADATA_RE = re.compile(r"^([1-9][0-9]*)\.(root|snapshot|targets)\.json$")
HASH_PREFIXED_TARGET_RE = re.compile(r"^([0-9a-f]{64})\.(.+)$")
FETCH_CHUNK = 1024 * 1024


class PackVerificationError(RuntimeError):
    """Raised when TUF or Atlas verification fails closed."""


@dataclass(frozen=True)
class TufClientLimits:
    profile_version: str = "1.0.0"
    root_max_length: int = 1024 * 1024
    timestamp_max_length: int = 2 * 1024 * 1024
    snapshot_max_length: int = 8 * 1024 * 1024
    targets_max_length: int = 32 * 1024 * 1024
    max_root_rotations: int = 32
    max_delegations: int = 1


@dataclass(frozen=True)
class VerifiedPack:
    pack_id: str
    pack_version: str
    manifest: dict[str, Any]
    manifest_bytes: bytes
    manifest_digest: str
    inventory: dict[str, Any]
    inventory_bytes: bytes
    verified_targets_dir: Path
    runtime_search_index: Path
    used_rebuilt_search_index: bool


def sha256_prefixed(data: bytes) -> str:
    return "sha256-" + hashlib.sha256(data).hexdigest()


def _safe_relative_path(value: str) -> PurePosixPath:
    if not value or "\\" in value or "\x00" in value or value.startswith("/"):
        raise DownloadHTTPError(f"invalid local pack URL path: {value!r}", 404)
    pure = PurePosixPath(value)
    if pure.as_posix() != value or any(part in {"", ".", ".."} for part in pure.parts):
        raise DownloadHTTPError(f"invalid local pack URL path: {value!r}", 404)
    return pure


def _metadata_version(path: Path) -> int | None:
    try:
        return int(Metadata.from_bytes(path.read_bytes()).signed.version)
    except Exception:
        return None


class PackDirectoryFetcher(FetcherInterface):
    """python-tuf fetcher that can only read from one extracted local pack directory."""

    def __init__(self, pack_root: Path):
        self.pack_root = Path(pack_root).resolve()
        self.metadata_root = self.pack_root / "metadata"
        self.targets_root = self.pack_root / "targets"

    def _resolve_metadata(self, relative: str) -> Path:
        pure = _safe_relative_path(relative)
        if len(pure.parts) != 1:
            raise DownloadHTTPError("nested metadata paths are not supported by Atlas POUF v1", 404)
        direct = self.metadata_root / pure.parts[0]
        if direct.is_file():
            return direct

        match = VERSIONED_METADATA_RE.fullmatch(pure.parts[0])
        if not match:
            raise DownloadHTTPError(f"metadata not found: {relative}", 404)
        requested_version = int(match.group(1))
        role = match.group(2)
        fallback = self.metadata_root / f"{role}.json"
        if fallback.is_file() and _metadata_version(fallback) == requested_version:
            return fallback
        raise DownloadHTTPError(f"metadata version not found: {relative}", 404)

    def _resolve_target(self, relative: str) -> Path:
        pure = _safe_relative_path(relative)
        direct = self.targets_root.joinpath(*pure.parts)
        if direct.is_file():
            return direct

        filename = pure.parts[-1]
        match = HASH_PREFIXED_TARGET_RE.fullmatch(filename)
        if not match:
            raise DownloadHTTPError(f"target not found: {relative}", 404)
        fallback_parts = (*pure.parts[:-1], match.group(2))
        fallback = self.targets_root.joinpath(*fallback_parts)
        if fallback.is_file():
            return fallback
        raise DownloadHTTPError(f"target not found: {relative}", 404)

    def _fetch(self, url: str) -> Iterator[bytes]:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != "atlas.invalid":
            raise DownloadHTTPError("Atlas offline TUF fetcher refuses non-local synthetic origin", 403)
        if parsed.query or parsed.fragment:
            raise DownloadHTTPError("Atlas offline TUF fetcher refuses query/fragment URLs", 403)

        path = unquote(parsed.path)
        if path.startswith("/metadata/"):
            source = self._resolve_metadata(path[len("/metadata/") :])
        elif path.startswith("/targets/"):
            source = self._resolve_target(path[len("/targets/") :])
        else:
            raise DownloadHTTPError(f"unsupported Atlas offline TUF URL: {url}", 404)

        with source.open("rb") as handle:
            while True:
                chunk = handle.read(FETCH_CHUNK)
                if not chunk:
                    break
                yield chunk


def _tuf_config(limits: TufClientLimits) -> UpdaterConfig:
    config = UpdaterConfig()
    config.root_max_length = limits.root_max_length
    config.timestamp_max_length = limits.timestamp_max_length
    config.snapshot_max_length = limits.snapshot_max_length
    config.targets_max_length = limits.targets_max_length
    config.max_root_rotations = limits.max_root_rotations
    config.max_delegations = limits.max_delegations
    return config


def _regular_files(root: Path) -> set[str]:
    files: set[str] = set()
    if not root.is_dir() or root.is_symlink():
        raise PackVerificationError(f"required pack directory missing/unsafe: {root}")
    for path in root.rglob("*"):
        if path.is_symlink():
            raise PackVerificationError(f"symlink is forbidden in pack directory: {path}")
        if path.is_file():
            files.add(path.relative_to(root).as_posix())
        elif not path.is_dir():
            raise PackVerificationError(f"special file is forbidden in pack directory: {path}")
    return files


def _validate_metadata_topology(pack_root: Path) -> None:
    metadata_files = _regular_files(pack_root / "metadata")
    missing = REQUIRED_METADATA - metadata_files
    if missing:
        raise PackVerificationError(f"pack is missing required TUF metadata: {sorted(missing)}")
    for name in metadata_files:
        if name not in REQUIRED_METADATA and not VERSIONED_ROOT_RE.fullmatch(name):
            raise PackVerificationError(f"unsupported Atlas POUF v1 metadata file: {name}")


def _download_verified_target(
    updater: Updater,
    target_path: str,
    output_root: Path,
) -> tuple[bytes, Path]:
    info = updater.get_targetinfo(target_path)
    if info is None:
        raise PackVerificationError(f"TUF targets metadata does not authorize required target: {target_path}")
    relative = _safe_relative_path(target_path)
    destination = output_root.joinpath(*relative.parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    updater.download_target(info, filepath=str(destination))
    data = destination.read_bytes()
    return data, destination


def _canonical_schema_validator() -> Draft202012Validator:
    registry = Registry()
    for path in sorted(CANONICAL_SCHEMA_ROOT.rglob("*.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        uri = schema.get("$id")
        if isinstance(uri, str):
            registry = registry.with_resource(uri, Resource.from_contents(schema))
    root_schema = json.loads(
        (CANONICAL_SCHEMA_ROOT / "atlas-record.schema.json").read_text(encoding="utf-8")
    )
    return Draft202012Validator(root_schema, registry=registry, format_checker=FormatChecker())


def _validate_canonical_jsonl(path: Path) -> int:
    validator = _canonical_schema_validator()
    count = 0
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    raise PackVerificationError(
                        f"canonical JSONL contains a blank record at line {line_number}"
                    )
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise PackVerificationError(
                        f"canonical JSONL parse failure at line {line_number}: {exc}"
                    ) from exc
                errors = sorted(validator.iter_errors(record), key=lambda error: list(error.path))
                if errors:
                    detail = "; ".join(error.message for error in errors[:5])
                    raise PackVerificationError(
                        f"canonical AtlasRecord schema failure at line {line_number}: {detail}"
                    )
                count += 1
    except UnicodeDecodeError as exc:
        raise PackVerificationError("canonical JSONL is not valid UTF-8") from exc
    if count == 0:
        raise PackVerificationError("canonical JSONL contains no records")
    return count


def _validate_artifact_bindings(
    manifest: dict[str, Any],
    target_paths: dict[str, Path],
) -> tuple[Path, Path, Path | None]:
    canonical = [item for item in manifest["artifacts"] if item["kind"] == "canonical-records"]
    spc = [item for item in manifest["artifacts"] if item["kind"] == "spc"]
    indexes = [item for item in manifest["artifacts"] if item["kind"] == "search-index"]
    if len(canonical) != 1:
        raise PackVerificationError("pack must declare exactly one canonical-records artifact")
    if len(spc) != 1:
        raise PackVerificationError("pack must declare exactly one SPC artifact")
    if len(indexes) > 1:
        raise PackVerificationError("Pack Manifest v1 permits at most one active search-index artifact")
    if canonical[0]["digest"] != manifest["canonical_records_digest"]:
        raise PackVerificationError("canonical_records_digest does not bind the canonical artifact")
    if spc[0]["digest"] != manifest["spc_digest"]:
        raise PackVerificationError("spc_digest does not bind the SPC artifact")
    return (
        target_paths[canonical[0]["path"]],
        target_paths[spc[0]["path"]],
        target_paths[indexes[0]["path"]] if indexes else None,
    )


def _validate_or_rebuild_search(
    spc_path: Path,
    signed_index_path: Path | None,
    verified_root: Path,
) -> tuple[Path, bool]:
    try:
        spc_bundle = json.loads(spc_path.read_text(encoding="utf-8"))
        validate_projection_bundle(spc_bundle)
    except Exception as exc:
        raise PackVerificationError(f"verified SPC is invalid: {exc}") from exc

    if signed_index_path is not None:
        try:
            with SQLiteSearchCore.open(signed_index_path, expected_bundle=spc_bundle):
                return signed_index_path, False
        except SearchIndexValidationError:
            pass

    derived_dir = verified_root / "_runtime-derived" / "search"
    derived_dir.mkdir(parents=True, exist_ok=True)
    rebuilt = derived_dir / "atlas-search.sqlite3"
    try:
        build_index(spc_bundle, rebuilt)
        with SQLiteSearchCore.open(rebuilt, expected_bundle=spc_bundle):
            pass
    except Exception as exc:
        raise PackVerificationError(f"failed to rebuild/validate derived search index: {exc}") from exc
    return rebuilt, True


def verify_pack_directory(
    pack_root: Path,
    *,
    bootstrap_root: bytes,
    metadata_cache_dir: Path,
    verified_targets_dir: Path,
    publication: bool = True,
    current_runtime_version: str = CURRENT_RUNTIME_VERSION,
    tuf_limits: TufClientLimits | None = None,
) -> VerifiedPack:
    """Verify one already safely extracted pack using persistent TUF trust state."""
    pack_root = Path(pack_root)
    metadata_cache_dir = Path(metadata_cache_dir)
    verified_targets_dir = Path(verified_targets_dir)
    if not isinstance(bootstrap_root, (bytes, bytearray)) or not bootstrap_root:
        raise PackVerificationError("a non-empty trusted bootstrap root is mandatory")
    _validate_metadata_topology(pack_root)
    _regular_files(pack_root / "targets")

    if verified_targets_dir.exists():
        if verified_targets_dir.is_symlink() or any(verified_targets_dir.iterdir()):
            raise PackVerificationError("verified target output directory must be empty")
    else:
        verified_targets_dir.mkdir(parents=True)
    metadata_cache_dir.mkdir(parents=True, exist_ok=True)

    updater = Updater(
        str(metadata_cache_dir),
        "https://atlas.invalid/metadata/",
        str(verified_targets_dir),
        "https://atlas.invalid/targets/",
        fetcher=PackDirectoryFetcher(pack_root),
        config=_tuf_config(tuf_limits or TufClientLimits()),
        bootstrap=bytes(bootstrap_root),
    )
    try:
        updater.refresh()
        manifest_bytes, manifest_path = _download_verified_target(
            updater, "atlas/pack-manifest.json", verified_targets_dir
        )
        inventory_bytes, inventory_path = _download_verified_target(
            updater, "atlas/source-license-inventory.json", verified_targets_dir
        )
    except Exception as exc:
        raise PackVerificationError(f"TUF verification failed: {exc}") from exc

    try:
        manifest = load_json(manifest_path)
        inventory = load_json(inventory_path)
        validate_contract_pair(
            manifest,
            inventory,
            inventory_bytes=inventory_bytes,
            publication=publication,
        )
        require_runtime_compatible(manifest["minimum_runtime_version"], current_runtime_version)
    except (PackContractError, VersionError, OSError, ValueError) as exc:
        raise PackVerificationError(f"Atlas pack control contract failed: {exc}") from exc

    declared_paths = {item["path"] for item in manifest["artifacts"]}
    expected_targets = CONTROL_TARGETS | declared_paths
    actual_targets = _regular_files(pack_root / "targets")
    if actual_targets != expected_targets:
        missing = sorted(expected_targets - actual_targets)
        extra = sorted(actual_targets - expected_targets)
        raise PackVerificationError(
            f"pack target topology mismatch; missing={missing}, undeclared={extra}"
        )

    target_paths: dict[str, Path] = {}
    for artifact in manifest["artifacts"]:
        target_path = artifact["path"]
        try:
            data, verified_path = _download_verified_target(updater, target_path, verified_targets_dir)
        except Exception as exc:
            raise PackVerificationError(f"TUF artifact verification failed for {target_path}: {exc}") from exc
        if len(data) != artifact["length"]:
            raise PackVerificationError(
                f"artifact length mismatch for {target_path}: {len(data)} != {artifact['length']}"
            )
        actual_digest = sha256_prefixed(data)
        if actual_digest != artifact["digest"]:
            raise PackVerificationError(
                f"artifact digest mismatch for {target_path}: {actual_digest} != {artifact['digest']}"
            )
        target_paths[target_path] = verified_path

    canonical_path, spc_path, signed_index_path = _validate_artifact_bindings(
        manifest, target_paths
    )
    _validate_canonical_jsonl(canonical_path)
    runtime_search_index, rebuilt = _validate_or_rebuild_search(
        spc_path, signed_index_path, verified_targets_dir
    )

    return VerifiedPack(
        pack_id=manifest["pack_id"],
        pack_version=manifest["pack_version"],
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        manifest_digest=sha256_prefixed(manifest_bytes),
        inventory=inventory,
        inventory_bytes=inventory_bytes,
        verified_targets_dir=verified_targets_dir,
        runtime_search_index=runtime_search_index,
        used_rebuilt_search_index=rebuilt,
    )
