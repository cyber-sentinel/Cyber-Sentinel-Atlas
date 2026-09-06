"""Verified deterministic `.atlaspack` transport builder.

This builder never signs metadata and never accepts private signing keys. Its input is
an already signed TUF repository-layout directory plus an out-of-band trusted root.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path

from tools.pack.archive import PackSafetyLimits, safe_extract_atlaspack, validate_archive_member_name
from tools.pack.tuf_runtime import CURRENT_RUNTIME_VERSION, verify_pack_directory


class PackBuildError(RuntimeError):
    """Raised when a verified `.atlaspack` cannot be safely produced."""


@dataclass(frozen=True)
class PackBuildReport:
    output_path: Path
    sha256: str
    length: int
    file_count: int


def _fsync_directory(path: Path) -> None:
    flags = getattr(os, "O_DIRECTORY", 0) | os.O_RDONLY
    try:
        fd = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _source_files(source_root: Path, limits: PackSafetyLimits) -> list[tuple[str, Path]]:
    source_root = source_root.resolve()
    files: list[tuple[str, Path]] = []
    for namespace in ("metadata", "targets"):
        base = source_root / namespace
        if not base.is_dir() or base.is_symlink():
            raise PackBuildError(f"signed source lacks safe {namespace}/ directory")
        for path in base.rglob("*"):
            if path.is_symlink():
                raise PackBuildError(f"builder refuses symlink source: {path}")
            if path.is_dir():
                continue
            if not path.is_file():
                raise PackBuildError(f"builder refuses special source file: {path}")
            try:
                mode = path.stat(follow_symlinks=False).st_mode
            except OSError as exc:
                raise PackBuildError(f"cannot stat builder source: {path}") from exc
            if not stat.S_ISREG(mode):
                raise PackBuildError(f"builder source is not a regular file: {path}")
            relative = path.relative_to(source_root).as_posix()
            validate_archive_member_name(relative, is_directory=False, limits=limits)
            files.append((relative, path))
    files.sort(key=lambda item: item[0])
    if len(files) > limits.max_entries:
        raise PackBuildError("signed source exceeds archive entry bound")
    return files


def _write_deterministic_zip(
    files: list[tuple[str, Path]], output_path: Path, limits: PackSafetyLimits
) -> None:
    total = 0
    with zipfile.ZipFile(output_path, mode="x", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        for relative, source in files:
            data = source.read_bytes()
            if len(data) > limits.max_file_uncompressed_bytes:
                raise PackBuildError(f"source file exceeds per-file bound: {relative}")
            total += len(data)
            if total > limits.max_total_uncompressed_bytes:
                raise PackBuildError("signed source exceeds aggregate uncompressed-size bound")
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.flag_bits = 0
            archive.writestr(info, data)
    if output_path.stat().st_size > limits.max_archive_bytes:
        raise PackBuildError("built atlaspack exceeds compressed-size bound")
    with output_path.open("r+b") as handle:
        os.fsync(handle.fileno())


def build_verified_atlaspack(
    signed_source_root: Path,
    output_path: Path,
    *,
    bootstrap_root: bytes,
    current_runtime_version: str = CURRENT_RUNTIME_VERSION,
    safety_limits: PackSafetyLimits | None = None,
) -> PackBuildReport:
    """Verify signed source, build deterministic transport, extract and verify it again."""
    limits = safety_limits or PackSafetyLimits()
    signed_source_root = Path(signed_source_root)
    output_path = Path(output_path)
    if output_path.suffix != ".atlaspack":
        raise PackBuildError("output must use the .atlaspack extension")
    if not isinstance(bootstrap_root, (bytes, bytearray)) or not bootstrap_root:
        raise PackBuildError("trusted bootstrap root is mandatory")
    if not signed_source_root.is_dir() or signed_source_root.is_symlink():
        raise PackBuildError("signed source root must be a normal directory")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    source_resolved = signed_source_root.resolve()
    try:
        output_resolved = output_path.resolve(strict=False)
        if output_resolved == source_resolved or source_resolved in output_resolved.parents:
            raise PackBuildError("output path must not be inside signed source tree")
    except OSError as exc:
        raise PackBuildError(f"cannot resolve output path: {exc}") from exc

    files = _source_files(signed_source_root, limits)
    work = Path(tempfile.mkdtemp(prefix="atlas-builder-", dir=output_path.parent))
    temp_pack = output_path.parent / f".{output_path.name}.{uuid.uuid4().hex}.tmp"
    try:
        # Verify the source layout before packaging. Keys stay entirely outside this builder.
        verify_pack_directory(
            signed_source_root,
            bootstrap_root=bytes(bootstrap_root),
            metadata_cache_dir=work / "source-tuf-cache",
            verified_targets_dir=work / "source-verified",
            publication=True,
            current_runtime_version=current_runtime_version,
        )

        _write_deterministic_zip(files, temp_pack, limits)

        extracted = work / "roundtrip-extracted"
        safe_extract_atlaspack(temp_pack, extracted, limits=limits)
        verify_pack_directory(
            extracted,
            bootstrap_root=bytes(bootstrap_root),
            metadata_cache_dir=work / "roundtrip-tuf-cache",
            verified_targets_dir=work / "roundtrip-verified",
            publication=True,
            current_runtime_version=current_runtime_version,
        )

        digest = hashlib.sha256(temp_pack.read_bytes()).hexdigest()
        length = temp_pack.stat().st_size
        os.replace(temp_pack, output_path)
        _fsync_directory(output_path.parent)
        return PackBuildReport(
            output_path=output_path,
            sha256="sha256-" + digest,
            length=length,
            file_count=len(files),
        )
    except PackBuildError:
        raise
    except Exception as exc:
        raise PackBuildError(f"verified atlaspack build failed: {exc}") from exc
    finally:
        temp_pack.unlink(missing_ok=True)
        shutil.rmtree(work, ignore_errors=True)
