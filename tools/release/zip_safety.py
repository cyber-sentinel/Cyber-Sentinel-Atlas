#!/usr/bin/env python3
"""Fail-closed ZIP member safety checks for the Windows portable release model."""

from __future__ import annotations

import re
import stat
import zipfile
from pathlib import PurePosixPath

DRIVE_PREFIX_RE = re.compile(r"^[A-Za-z]:")
RESERVED_DEVICE_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def _device_basename(part: str) -> str:
    cleaned = part.rstrip(" .")
    return cleaned.split(".", 1)[0].upper()


def validate_zip_members(infos: list[zipfile.ZipInfo]) -> tuple[list[str], int]:
    errors: list[str] = []
    file_count = 0
    seen_exact: set[str] = set()
    seen_windows: dict[str, str] = {}

    for info in infos:
        original = info.filename
        normalized = original.replace("\\", "/")

        if not normalized:
            errors.append("ZIP entry has an empty name")
            continue
        if normalized.startswith("/") or normalized.startswith("//"):
            errors.append(f"absolute/UNC ZIP entry path: {original}")
        if DRIVE_PREFIX_RE.match(normalized):
            errors.append(f"drive-qualified ZIP entry path: {original}")
        if "//" in normalized:
            errors.append(f"ambiguous repeated-separator ZIP entry path: {original}")

        pure = PurePosixPath(normalized)
        if pure.is_absolute() or ".." in pure.parts:
            errors.append(f"unsafe ZIP entry path: {original}")

        raw_parts = normalized.rstrip("/").split("/")
        for part in raw_parts:
            if not part or part == ".":
                errors.append(f"ambiguous ZIP entry path component: {original}")
                continue
            if ":" in part:
                errors.append(f"Windows ADS/colon ZIP entry component: {original}")
            if part.endswith((" ", ".")):
                errors.append(f"Windows trailing-dot/space ZIP entry component: {original}")
            if _device_basename(part) in RESERVED_DEVICE_NAMES:
                errors.append(f"Windows reserved-device ZIP entry component: {original}")

        canonical_exact = normalized.rstrip("/")
        if canonical_exact in seen_exact:
            errors.append(f"duplicate ZIP entry: {original}")
        seen_exact.add(canonical_exact)

        canonical_windows = canonical_exact.casefold()
        prior = seen_windows.get(canonical_windows)
        if prior is not None and prior != original:
            errors.append(f"Windows case-insensitive ZIP collision: {prior} vs {original}")
        else:
            seen_windows[canonical_windows] = original

        if info.flag_bits & 0x1:
            errors.append(f"encrypted ZIP entry is not allowed: {original}")

        if info.create_system == 3:
            mode = (info.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(mode)
            if stat.S_ISLNK(mode):
                errors.append(f"symlink ZIP entry is not allowed: {original}")
            elif file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                errors.append(f"special-file ZIP entry is not allowed: {original}")

        if not info.is_dir():
            file_count += 1

    if file_count == 0:
        errors.append("package ZIP must contain at least one file entry")

    return errors, file_count
