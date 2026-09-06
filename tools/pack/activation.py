"""Atomic installation, activation, LKG and rollback for verified Atlas packs."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import uuid
from contextlib import AbstractContextManager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from tools.pack.archive import PackSafetyLimits, safe_extract_atlaspack
from tools.pack.contract import load_json, validate_contract_pair
from tools.pack.tuf_runtime import (
    CURRENT_RUNTIME_VERSION,
    VerifiedPack,
    sha256_prefixed,
    verify_pack_directory,
)
from tools.pack.versioning import VersionError, compare_versions
from tools.search.sqlite_search import SQLiteSearchCore, validate_projection_bundle

STATE_VERSION = 1
GENERATION_METADATA_VERSION = 1
TRUSTED_TIME_VERSION = 1
LOCK_NAME = "install.lock"
STATE_NAME = "runtime-state.json"
TRUSTED_TIME_NAME = "trusted-time.json"
SHA256_DIGEST_RE = re.compile(r"^sha256-[0-9a-f]{64}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
TRUSTED_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
HealthCheck = Callable[[Path], None]


class ActivationError(RuntimeError):
    """Raised when installation/activation cannot complete safely."""


class RuntimeLock(AbstractContextManager["RuntimeLock"]):
    """Process lock with fail-closed stale-lock semantics.

    The lock is never automatically broken: an abandoned lock requires an explicit
    administrative recovery decision instead of guessing whether another process lives.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.fd: int | None = None

    def __enter__(self) -> "RuntimeLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        try:
            self.fd = os.open(self.path, flags, 0o600)
        except FileExistsError as exc:
            raise ActivationError(
                f"runtime install lock already exists; administrative recovery is required: {self.path}"
            ) from exc
        payload = {
            "pid": os.getpid(),
            "created_at": _format_trusted_time(datetime.now(timezone.utc)),
        }
        os.write(self.fd, _canonical_json_bytes(payload))
        os.fsync(self.fd)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def _fsync_directory(path: Path) -> None:
    """Best-effort directory fsync where the host supports opening directories."""
    flags = getattr(os, "O_DIRECTORY", 0) | os.O_RDONLY
    try:
        fd = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    data = _canonical_json_bytes(value)
    try:
        with temp.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        _fsync_directory(path.parent)
    finally:
        temp.unlink(missing_ok=True)


def _format_trusted_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ActivationError("trusted wall-clock observation must be timezone-aware")
    return value.astimezone(timezone.utc).strftime(TRUSTED_TIME_FORMAT)


def _parse_trusted_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ActivationError("trusted-time value must be a string")
    try:
        parsed = datetime.strptime(value, TRUSTED_TIME_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ActivationError("trusted-time state is not canonical UTC") from exc
    if _format_trusted_time(parsed) != value:
        raise ActivationError("trusted-time state is not canonical UTC")
    return parsed


def _durable_trust_state_exists(runtime_root: Path) -> bool:
    runtime_root = Path(runtime_root)
    if (runtime_root / "state" / STATE_NAME).is_file():
        return True
    metadata_cache = runtime_root / "tuf" / "metadata"
    if metadata_cache.is_dir() and any(path.is_file() for path in metadata_cache.rglob("*")):
        return True
    generations = runtime_root / "generations"
    if generations.is_dir() and any(path.is_dir() for path in generations.iterdir()):
        return True
    return False


def _guard_trusted_time(runtime_root: Path, observed_time: datetime | None = None) -> datetime:
    """Persist a monotonic wall-clock floor and fail closed on local clock rollback.

    The reference profile intentionally uses zero rollback tolerance: any observed UTC
    time below the durable highest observation is an administrative recovery condition.
    A missing trusted-time file while other durable trust state exists is treated as
    state loss and also fails closed.
    """
    runtime_root = Path(runtime_root)
    observed = observed_time or datetime.now(timezone.utc)
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ActivationError("trusted wall-clock observation must be timezone-aware")
    observed = observed.astimezone(timezone.utc)
    path = runtime_root / "state" / TRUSTED_TIME_NAME

    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise ActivationError("trusted-time state path is not a normal file")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ActivationError(f"trusted-time state is corrupt/unreadable: {exc}") from exc
        if not isinstance(value, dict) or set(value) != {
            "trusted_time_version",
            "highest_observed_utc",
        }:
            raise ActivationError("trusted-time state has an unexpected structure")
        if value["trusted_time_version"] != TRUSTED_TIME_VERSION:
            raise ActivationError("unsupported trusted-time state version")
        highest = _parse_trusted_time(value["highest_observed_utc"])
        if observed < highest:
            raise ActivationError(
                "local clock rollback detected; administrative trusted-time recovery is required"
            )
        if observed == highest:
            return observed
    else:
        if _durable_trust_state_exists(runtime_root):
            raise ActivationError(
                "trusted-time state is missing while durable trust state exists; administrative recovery is required"
            )

    _atomic_write_json(
        path,
        {
            "trusted_time_version": TRUSTED_TIME_VERSION,
            "highest_observed_utc": _format_trusted_time(observed),
        },
    )
    return observed


def _default_state() -> dict[str, Any]:
    return {
        "state_version": STATE_VERSION,
        "active_generation": None,
        "lkg_generation": None,
        "highest_seen_packs": {},
    }


def _validate_state(state: Any) -> dict[str, Any]:
    if not isinstance(state, dict) or set(state) != {
        "state_version",
        "active_generation",
        "lkg_generation",
        "highest_seen_packs",
    }:
        raise ActivationError("runtime state has an unexpected structure")
    if state["state_version"] != STATE_VERSION:
        raise ActivationError("unsupported runtime state version")
    for key in ("active_generation", "lkg_generation"):
        value = state[key]
        if value is not None and (not isinstance(value, str) or HEX64_RE.fullmatch(value) is None):
            raise ActivationError(f"invalid runtime generation pointer: {key}")
    highest = state["highest_seen_packs"]
    if not isinstance(highest, dict):
        raise ActivationError("highest_seen_packs must be an object")
    for pack_id, entry in highest.items():
        if not isinstance(pack_id, str) or not pack_id or not isinstance(entry, dict) or set(entry) != {
            "version",
            "manifest_digest",
        }:
            raise ActivationError("invalid highest-seen pack record")
        if not isinstance(entry["version"], str):
            raise ActivationError("invalid highest-seen pack version")
        digest = entry["manifest_digest"]
        if not isinstance(digest, str) or SHA256_DIGEST_RE.fullmatch(digest) is None:
            raise ActivationError("invalid highest-seen manifest digest")
        try:
            compare_versions(entry["version"], entry["version"])
        except VersionError as exc:
            raise ActivationError("invalid highest-seen SemVer") from exc
    return state


def load_runtime_state(runtime_root: Path) -> dict[str, Any]:
    path = Path(runtime_root) / "state" / STATE_NAME
    if not path.exists():
        return _default_state()
    if path.is_symlink() or not path.is_file():
        raise ActivationError("runtime state path is not a normal file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActivationError(f"runtime state is corrupt/unreadable: {exc}") from exc
    return _validate_state(value)


def _write_runtime_state(runtime_root: Path, state: Mapping[str, Any]) -> None:
    validated = _validate_state(dict(state))
    _atomic_write_json(Path(runtime_root) / "state" / STATE_NAME, validated)


def _validate_generation_metadata(value: Any) -> dict[str, Any]:
    expected = {
        "generation_metadata_version",
        "generation_id",
        "pack_id",
        "pack_version",
        "manifest_digest",
        "runtime_search_index",
        "search_index_rebuilt",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ActivationError("generation metadata has an unexpected structure")
    if value["generation_metadata_version"] != GENERATION_METADATA_VERSION:
        raise ActivationError("unsupported generation metadata version")
    if not isinstance(value["generation_id"], str) or HEX64_RE.fullmatch(value["generation_id"]) is None:
        raise ActivationError("invalid generation metadata id")
    if not isinstance(value["pack_id"], str) or not value["pack_id"]:
        raise ActivationError("invalid generation pack_id")
    try:
        compare_versions(value["pack_version"], value["pack_version"])
    except (TypeError, VersionError) as exc:
        raise ActivationError("invalid generation pack_version") from exc
    if not isinstance(value["manifest_digest"], str) or SHA256_DIGEST_RE.fullmatch(value["manifest_digest"]) is None:
        raise ActivationError("invalid generation manifest digest")
    if value["runtime_search_index"] != "derived/search/atlas-search.sqlite3":
        raise ActivationError("unexpected generation search-index location")
    if not isinstance(value["search_index_rebuilt"], bool):
        raise ActivationError("invalid generation search rebuild marker")
    return value


def _load_generation_metadata(generation: Path) -> dict[str, Any]:
    path = Path(generation) / "generation.json"
    if path.is_symlink() or not path.is_file():
        raise ActivationError("generation metadata path is missing/unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActivationError(f"generation metadata is corrupt/unreadable: {exc}") from exc
    return _validate_generation_metadata(value)


def _generation_id(verified: VerifiedPack) -> str:
    return hashlib.sha256(verified.manifest_bytes).hexdigest()


def _copy_file_exact(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise ActivationError(f"refusing to overwrite generation path: {destination}")
    with source.open("rb") as src, destination.open("xb") as dst:
        shutil.copyfileobj(src, dst, 1024 * 1024)
        dst.flush()
        os.fsync(dst.fileno())
    try:
        destination.chmod(0o444)
    except OSError:
        pass


def _make_tree_read_only(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        try:
            if path.is_file():
                path.chmod(0o444)
            elif path.is_dir():
                path.chmod(0o555)
        except OSError:
            pass
    try:
        root.chmod(0o555)
    except OSError:
        pass


def _stage_generation(verified: VerifiedPack, runtime_root: Path) -> Path:
    runtime_root = Path(runtime_root)
    generations = runtime_root / "generations"
    generations.mkdir(parents=True, exist_ok=True)
    generation_id = _generation_id(verified)
    final = generations / generation_id
    if final.exists():
        if final.is_symlink() or not final.is_dir():
            raise ActivationError("existing generation path is unsafe")
        metadata = _load_generation_metadata(final)
        if metadata["generation_id"] != generation_id:
            raise ActivationError("existing generation id conflicts with directory identity")
        if metadata["manifest_digest"] != verified.manifest_digest:
            raise ActivationError("existing generation identity conflicts with manifest digest")
        return final

    staging = generations / f".{generation_id}.{uuid.uuid4().hex}.staging"
    try:
        staging.mkdir(mode=0o700)
        signed_targets = staging / "targets"
        signed_targets.mkdir(mode=0o700)

        required_paths = {
            "atlas/pack-manifest.json",
            "atlas/source-license-inventory.json",
            *(item["path"] for item in verified.manifest["artifacts"]),
        }
        for relative in sorted(required_paths):
            source = verified.verified_targets_dir.joinpath(*relative.split("/"))
            if not source.is_file() or source.is_symlink():
                raise ActivationError(f"verified signed target is missing/unsafe: {relative}")
            _copy_file_exact(source, signed_targets.joinpath(*relative.split("/")))

        derived = staging / "derived" / "search" / "atlas-search.sqlite3"
        _copy_file_exact(verified.runtime_search_index, derived)

        generation_metadata = {
            "generation_metadata_version": GENERATION_METADATA_VERSION,
            "generation_id": generation_id,
            "pack_id": verified.pack_id,
            "pack_version": verified.pack_version,
            "manifest_digest": verified.manifest_digest,
            "runtime_search_index": "derived/search/atlas-search.sqlite3",
            "search_index_rebuilt": verified.used_rebuilt_search_index,
        }
        _validate_generation_metadata(generation_metadata)
        _atomic_write_json(staging / "generation.json", generation_metadata)
        _make_tree_read_only(staging)
        os.replace(staging, final)
        _fsync_directory(generations)
    except Exception:
        try:
            shutil.rmtree(staging, ignore_errors=True)
        finally:
            raise
    return final


def _health_generation(generation: Path) -> None:
    generation = Path(generation)
    metadata = _load_generation_metadata(generation)
    if metadata["generation_id"] != generation.name:
        raise ActivationError("installed generation directory/id mismatch")
    manifest_path = generation / "targets" / "atlas" / "pack-manifest.json"
    inventory_path = generation / "targets" / "atlas" / "source-license-inventory.json"
    manifest_bytes = manifest_path.read_bytes()
    inventory_bytes = inventory_path.read_bytes()
    manifest = load_json(manifest_path)
    inventory = load_json(inventory_path)
    validate_contract_pair(manifest, inventory, inventory_bytes=inventory_bytes, publication=True)
    if sha256_prefixed(manifest_bytes) != metadata["manifest_digest"]:
        raise ActivationError("installed generation manifest digest mismatch")
    if manifest["pack_id"] != metadata["pack_id"] or manifest["pack_version"] != metadata["pack_version"]:
        raise ActivationError("installed generation identity does not match manifest")

    spc_path: Path | None = None
    for artifact in manifest["artifacts"]:
        path = generation / "targets" / Path(*artifact["path"].split("/"))
        if not path.is_file() or path.is_symlink():
            raise ActivationError(f"installed generation artifact missing: {artifact['path']}")
        data = path.read_bytes()
        if len(data) != artifact["length"] or sha256_prefixed(data) != artifact["digest"]:
            raise ActivationError(f"installed generation artifact binding failed: {artifact['path']}")
        if artifact["kind"] == "spc":
            spc_path = path
    if spc_path is None:
        raise ActivationError("installed generation has no SPC")
    bundle = json.loads(spc_path.read_text(encoding="utf-8"))
    validate_projection_bundle(bundle)
    search_path = generation.joinpath(*metadata["runtime_search_index"].split("/"))
    if search_path.is_symlink() or not search_path.is_file():
        raise ActivationError("installed runtime search index is missing/unsafe")
    with SQLiteSearchCore.open(search_path, expected_bundle=bundle):
        pass


def _check_pack_rollback(state: dict[str, Any], verified: VerifiedPack) -> dict[str, Any]:
    highest = state["highest_seen_packs"].get(verified.pack_id)
    if highest is None:
        return {
            "version": verified.pack_version,
            "manifest_digest": verified.manifest_digest,
        }
    try:
        order = compare_versions(verified.pack_version, highest["version"])
    except VersionError as exc:
        raise ActivationError(f"pack rollback version comparison failed: {exc}") from exc
    if order < 0:
        raise ActivationError(
            f"pack rollback rejected: {verified.pack_version} < highest-seen {highest['version']}"
        )
    if order == 0 and verified.manifest_digest != highest["manifest_digest"]:
        raise ActivationError("same pack version was previously trusted with different manifest bytes")
    return {
        "version": verified.pack_version if order > 0 else highest["version"],
        "manifest_digest": verified.manifest_digest if order > 0 else highest["manifest_digest"],
    }


def _record_rollback(runtime_root: Path, payload: Mapping[str, Any]) -> None:
    reports = Path(runtime_root) / "reports" / "rollback"
    reports.mkdir(parents=True, exist_ok=True)
    report_id = uuid.uuid4().hex
    report = dict(payload)
    report["report_version"] = 1
    report["recorded_at"] = _format_trusted_time(datetime.now(timezone.utc))
    _atomic_write_json(reports / f"{report_id}.json", report)


def _install_verified_generation_locked(
    verified: VerifiedPack,
    runtime_root: Path,
    *,
    pre_health: HealthCheck | None = None,
    post_health: HealthCheck | None = None,
) -> str:
    runtime_root = Path(runtime_root)
    state = load_runtime_state(runtime_root)
    previous_active = state["active_generation"]
    previous_lkg = state["lkg_generation"]
    highest_record = _check_pack_rollback(state, verified)
    generation = _stage_generation(verified, runtime_root)
    generation_id = generation.name

    _health_generation(generation)
    if pre_health is not None:
        pre_health(generation)

    trust_advanced = json.loads(json.dumps(state))
    trust_advanced["highest_seen_packs"][verified.pack_id] = highest_record
    _write_runtime_state(runtime_root, trust_advanced)

    activating = json.loads(json.dumps(trust_advanced))
    activating["active_generation"] = generation_id
    _write_runtime_state(runtime_root, activating)

    try:
        active_path = resolve_active_generation(runtime_root)
        _health_generation(active_path)
        if post_health is not None:
            post_health(active_path)
    except Exception as exc:
        rollback_target = previous_lkg or previous_active
        rolled_back = json.loads(json.dumps(trust_advanced))
        rolled_back["active_generation"] = rollback_target
        rolled_back["lkg_generation"] = previous_lkg
        _write_runtime_state(runtime_root, rolled_back)
        _record_rollback(
            runtime_root,
            {
                "pack_id": verified.pack_id,
                "pack_version": verified.pack_version,
                "failed_generation": generation_id,
                "restored_generation": rollback_target,
                "reason": f"{type(exc).__name__}: {exc}",
            },
        )
        raise ActivationError(f"post-activation health failed; LKG restored: {exc}") from exc

    committed = json.loads(json.dumps(activating))
    committed["lkg_generation"] = generation_id
    _write_runtime_state(runtime_root, committed)
    return generation_id


def install_verified_generation(
    verified: VerifiedPack,
    runtime_root: Path,
    *,
    pre_health: HealthCheck | None = None,
    post_health: HealthCheck | None = None,
) -> str:
    """Install an already verified object; primarily used by the reference/test boundary.

    Full production-like activation from untrusted transport must use `install_atlaspack`
    so trusted-time and TUF verification occur under the same runtime lock.
    """
    runtime_root = _prepare_runtime_root(runtime_root)
    with RuntimeLock(runtime_root / "state" / LOCK_NAME):
        return _install_verified_generation_locked(
            verified,
            runtime_root,
            pre_health=pre_health,
            post_health=post_health,
        )


def _prepare_runtime_root(runtime_root: Path) -> Path:
    runtime_root = Path(runtime_root)
    if runtime_root.exists():
        if runtime_root.is_symlink() or not runtime_root.is_dir():
            raise ActivationError("runtime root must be a normal directory")
    else:
        runtime_root.mkdir(parents=True, mode=0o700)
    for name in ("state", "staging", "tuf", "generations", "reports"):
        path = runtime_root / name
        if path.exists() and (path.is_symlink() or not path.is_dir()):
            raise ActivationError(f"runtime subdirectory is unsafe: {path}")
        path.mkdir(exist_ok=True)
    return runtime_root


def resolve_active_generation(runtime_root: Path) -> Path:
    runtime_root = Path(runtime_root)
    state = load_runtime_state(runtime_root)
    generation_id = state["active_generation"]
    if generation_id is None:
        raise ActivationError("no active Atlas pack generation")
    path = runtime_root / "generations" / generation_id
    if path.is_symlink() or not path.is_dir():
        raise ActivationError("active generation pointer is missing/unsafe")
    metadata = _load_generation_metadata(path)
    if metadata["generation_id"] != generation_id:
        raise ActivationError("active generation identity mismatch")
    return path


def install_atlaspack(
    archive_path: Path,
    *,
    bootstrap_root: bytes,
    runtime_root: Path,
    current_runtime_version: str = CURRENT_RUNTIME_VERSION,
    safety_limits: PackSafetyLimits | None = None,
    pre_health: HealthCheck | None = None,
    post_health: HealthCheck | None = None,
) -> str:
    """Safely extract, publication-verify, stage and atomically activate `.atlaspack`."""
    runtime_root = _prepare_runtime_root(runtime_root)
    lock_path = runtime_root / "state" / LOCK_NAME
    with RuntimeLock(lock_path):
        # Activation never has an inspection/non-publication mode: public licensing and
        # trusted-time checks are mandatory. Inspection belongs to verify_pack_directory.
        _guard_trusted_time(runtime_root)
        staging_parent = runtime_root / "staging"
        work = Path(tempfile.mkdtemp(prefix="atlaspack-", dir=staging_parent))
        try:
            extracted = work / "extracted"
            verified_targets = work / "verified-targets"
            safe_extract_atlaspack(
                archive_path,
                extracted,
                limits=safety_limits or PackSafetyLimits(),
            )
            verified = verify_pack_directory(
                extracted,
                bootstrap_root=bootstrap_root,
                metadata_cache_dir=runtime_root / "tuf" / "metadata",
                verified_targets_dir=verified_targets,
                publication=True,
                current_runtime_version=current_runtime_version,
            )
            return _install_verified_generation_locked(
                verified,
                runtime_root,
                pre_health=pre_health,
                post_health=post_health,
            )
        finally:
            shutil.rmtree(work, ignore_errors=True)
