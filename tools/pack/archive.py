"""Fail-closed `.atlaspack` ZIP preflight and extraction.

Archive bytes are untrusted. This module never executes archive content and never
uses ZipFile.extract()/extractall(): all paths and entry types are validated before
manual streaming into a private staging directory.
"""
from __future__ import annotations

import os
import re
import stat
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from tools.pack.contract import ACTIVE_EXTENSIONS, DRIVE_QUALIFIED, WINDOWS_RESERVED

ROOT_NAMESPACES = {"metadata", "targets"}
TARGET_NAMESPACES = {"atlas", "content", "search"}
TOP_LEVEL_METADATA = {"root.json", "timestamp.json", "snapshot.json", "targets.json"}
VERSIONED_ROOT_RE = re.compile(r"^[1-9][0-9]*\.root\.json$")
ALLOWED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
WINDOWS_REPARSE_POINT = 0x0400
COPY_CHUNK = 1024 * 1024


class PackArchiveError(ValueError):
    """Raised when an `.atlaspack` violates the strict archive safety profile."""


@dataclass(frozen=True)
class PackSafetyLimits:
    """Reference v1 extraction envelope; configurable without changing canonical schemas."""

    profile_version: str = "1.0.0"
    max_archive_bytes: int = 2 * 1024 * 1024 * 1024
    max_entries: int = 8192
    max_path_chars: int = 512
    max_file_uncompressed_bytes: int = 2 * 1024 * 1024 * 1024
    max_total_uncompressed_bytes: int = 4 * 1024 * 1024 * 1024
    max_compression_ratio: float = 200.0


@dataclass(frozen=True)
class ExtractionReport:
    profile_version: str
    file_count: int
    directory_count: int
    total_uncompressed_bytes: int


def _component_safe(part: str) -> None:
    if not part or part in {".", ".."}:
        raise PackArchiveError(f"non-canonical path component: {part!r}")
    stripped = part.rstrip(" .")
    if stripped != part or not stripped:
        raise PackArchiveError(f"Windows-ambiguous path component: {part!r}")
    stem = stripped.split(".", 1)[0].upper()
    if stem in WINDOWS_RESERVED:
        raise PackArchiveError(f"Windows-reserved path component: {part!r}")


def validate_archive_member_name(
    name: str,
    *,
    is_directory: bool,
    limits: PackSafetyLimits,
) -> tuple[str, tuple[str, ...]]:
    """Validate and canonicalize one ZIP member name without touching disk."""
    if not isinstance(name, str) or not name or "\x00" in name or "\\" in name:
        raise PackArchiveError(f"unsafe archive member name: {name!r}")
    if len(name) > limits.max_path_chars + 1:
        raise PackArchiveError("archive member path exceeds configured bound")
    if name.startswith("/") or DRIVE_QUALIFIED.match(name):
        raise PackArchiveError(f"absolute/drive-qualified archive member: {name!r}")

    if is_directory:
        if not name.endswith("/"):
            raise PackArchiveError(f"directory entry lacks canonical trailing slash: {name!r}")
        raw = name[:-1]
    else:
        if name.endswith("/"):
            raise PackArchiveError(f"file entry has directory-style path: {name!r}")
        raw = name

    if not raw or len(raw) > limits.max_path_chars:
        raise PackArchiveError("archive member path is empty or exceeds configured bound")
    if unicodedata.normalize("NFC", raw) != raw:
        raise PackArchiveError(f"archive member path is not NFC canonical: {name!r}")

    pure = PurePosixPath(raw)
    if pure.as_posix() != raw:
        raise PackArchiveError(f"non-canonical archive member path: {name!r}")
    parts = pure.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise PackArchiveError(f"unsafe archive traversal path: {name!r}")
    for part in parts:
        _component_safe(part)

    if parts[0] not in ROOT_NAMESPACES:
        raise PackArchiveError(f"archive member outside metadata/targets namespaces: {name!r}")

    if parts[0] == "metadata" and not is_directory:
        if len(parts) != 2:
            raise PackArchiveError("Phase 5.5.2 v1 metadata files must be direct children of metadata/")
        metadata_name = parts[1]
        if metadata_name not in TOP_LEVEL_METADATA and not VERSIONED_ROOT_RE.fullmatch(metadata_name):
            raise PackArchiveError(f"unsupported v1 TUF metadata member: {metadata_name!r}")

    if parts[0] == "targets":
        if len(parts) < 2:
            if not is_directory:
                raise PackArchiveError("targets/ cannot itself be a file")
        elif parts[1] not in TARGET_NAMESPACES:
            raise PackArchiveError(f"target outside Atlas target namespaces: {name!r}")
        elif not is_directory and PurePosixPath(raw).suffix.casefold() in ACTIVE_EXTENSIONS:
            raise PackArchiveError(f"active-code extension is forbidden in content packs: {name!r}")

    return raw, parts


def _validate_entry_type(info: zipfile.ZipInfo) -> None:
    if info.flag_bits & 0x1:
        raise PackArchiveError(f"encrypted ZIP member is forbidden: {info.filename!r}")
    if info.compress_type not in ALLOWED_COMPRESSION:
        raise PackArchiveError(
            f"unsupported ZIP compression method {info.compress_type}: {info.filename!r}"
        )

    dos_attrs = info.external_attr & 0xFFFF
    if dos_attrs & WINDOWS_REPARSE_POINT:
        raise PackArchiveError(f"Windows reparse-point archive member is forbidden: {info.filename!r}")

    unix_mode = (info.external_attr >> 16) & 0xFFFF
    if unix_mode:
        file_type = stat.S_IFMT(unix_mode)
        allowed = {0, stat.S_IFREG, stat.S_IFDIR}
        if file_type not in allowed:
            raise PackArchiveError(f"non-regular archive member is forbidden: {info.filename!r}")
        if info.is_dir() and file_type not in {0, stat.S_IFDIR}:
            raise PackArchiveError(f"directory entry has non-directory mode: {info.filename!r}")
        if not info.is_dir() and file_type == stat.S_IFDIR:
            raise PackArchiveError(f"file entry has directory mode: {info.filename!r}")


def _preflight(
    archive: zipfile.ZipFile,
    limits: PackSafetyLimits,
) -> tuple[list[tuple[zipfile.ZipInfo, str, tuple[str, ...]]], int, int, int]:
    infos = archive.infolist()
    if len(infos) > limits.max_entries:
        raise PackArchiveError(f"archive has {len(infos)} entries; limit is {limits.max_entries}")

    seen: set[str] = set()
    validated: list[tuple[zipfile.ZipInfo, str, tuple[str, ...]]] = []
    total = 0
    files = 0
    directories = 0

    for info in infos:
        # CPython's ZIP parser may sanitize the raw member name (for example,
        # backslashes are converted to forward slashes on Windows and NUL can
        # truncate a name). Atlas validates the wire-level name, not a parser-
        # repaired representation. Any parser mutation is therefore fail-closed.
        original_name = getattr(info, "orig_filename", info.filename)
        if original_name != info.filename:
            raise PackArchiveError(
                f"ZIP parser sanitized a non-canonical archive member name: {original_name!r}"
            )

        _validate_entry_type(info)
        raw, parts = validate_archive_member_name(
            original_name, is_directory=info.is_dir(), limits=limits
        )
        collision_key = unicodedata.normalize("NFC", raw).casefold()
        if collision_key in seen:
            raise PackArchiveError(f"duplicate/case-colliding archive path: {info.filename!r}")
        seen.add(collision_key)

        if info.is_dir():
            if info.file_size != 0:
                raise PackArchiveError(f"directory entry has non-zero size: {info.filename!r}")
            directories += 1
        else:
            files += 1
            if info.file_size < 0 or info.file_size > limits.max_file_uncompressed_bytes:
                raise PackArchiveError(f"archive member exceeds per-file bound: {info.filename!r}")
            total += info.file_size
            if total > limits.max_total_uncompressed_bytes:
                raise PackArchiveError("archive exceeds aggregate uncompressed-size bound")
            if info.file_size:
                ratio = info.file_size / max(info.compress_size, 1)
                if ratio > limits.max_compression_ratio:
                    raise PackArchiveError(
                        f"archive member exceeds compression-ratio bound: {info.filename!r}"
                    )
        validated.append((info, raw, parts))

    return validated, files, directories, total


def _ensure_private_empty_directory(destination: Path) -> None:
    if destination.exists():
        if destination.is_symlink() or not destination.is_dir():
            raise PackArchiveError("staging destination is not a normal directory")
        if any(destination.iterdir()):
            raise PackArchiveError("staging destination must be empty")
    else:
        destination.mkdir(parents=True, mode=0o700)
    try:
        destination.chmod(0o700)
    except OSError:
        pass


def _mkdir_chain_without_links(root: Path, parts: tuple[str, ...]) -> Path:
    current = root
    for part in parts:
        current = current / part
        if current.exists() or current.is_symlink():
            if current.is_symlink() or not current.is_dir():
                raise PackArchiveError(f"staging path component is not a normal directory: {current}")
        else:
            current.mkdir(mode=0o700)
    return current


def safe_extract_atlaspack(
    archive_path: Path,
    destination: Path,
    *,
    limits: PackSafetyLimits | None = None,
) -> ExtractionReport:
    """Preflight every member, then manually stream a pack into private staging."""
    limits = limits or PackSafetyLimits()
    archive_path = Path(archive_path)
    destination = Path(destination)
    if not archive_path.is_file():
        raise PackArchiveError(f"atlaspack does not exist: {archive_path}")
    if archive_path.stat().st_size > limits.max_archive_bytes:
        raise PackArchiveError("atlaspack exceeds configured compressed-size bound")
    _ensure_private_empty_directory(destination)

    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            validated, files, directories, total = _preflight(archive, limits)
            for info, _raw, parts in validated:
                if info.is_dir():
                    _mkdir_chain_without_links(destination, parts)
                    continue

                parent = _mkdir_chain_without_links(destination, parts[:-1])
                target = parent / parts[-1]
                if target.exists() or target.is_symlink():
                    raise PackArchiveError(f"refusing to overwrite staging path: {target}")

                written = 0
                with archive.open(info, "r") as source, target.open("xb") as output:
                    while True:
                        chunk = source.read(COPY_CHUNK)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > info.file_size or written > limits.max_file_uncompressed_bytes:
                            raise PackArchiveError(
                                f"decompressed member exceeded declared/safety size: {info.filename!r}"
                            )
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
                if written != info.file_size:
                    raise PackArchiveError(
                        f"decompressed member size mismatch: {info.filename!r}: {written} != {info.file_size}"
                    )
                try:
                    target.chmod(0o600)
                except OSError:
                    pass
    except PackArchiveError:
        raise
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        raise PackArchiveError(f"atlaspack extraction failed: {exc}") from exc

    return ExtractionReport(
        profile_version=limits.profile_version,
        file_count=files,
        directory_count=directories,
        total_uncompressed_bytes=total,
    )
