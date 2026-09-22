#!/usr/bin/env python3
"""Validate preserved Go linked-module/toolchain license material for PPR-04."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath

HEX64 = re.compile(r"^[0-9a-f]{64}$")
GO_SUM_RE = re.compile(r"^h1:[A-Za-z0-9+/=]+$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_bound_file(
    root: Path,
    item: dict,
    expected_paths: set[str],
    errors: list[str],
    label: str,
) -> None:
    path_value = item.get("bundle_path")
    if not isinstance(path_value, str) or not path_value or "\\" in path_value:
        errors.append(f"{label}: bundle_path must be a normalized POSIX relative path")
        return
    pure = PurePosixPath(path_value)
    if pure.is_absolute() or ".." in pure.parts:
        errors.append(f"{label}: unsafe bundle_path: {path_value!r}")
        return
    if path_value in expected_paths:
        errors.append(f"{label}: duplicate bundle_path: {path_value}")
        return
    expected_paths.add(path_value)

    expected_hash = item.get("sha256")
    expected_size = item.get("size_bytes")
    if not isinstance(expected_hash, str) or not HEX64.fullmatch(expected_hash):
        errors.append(f"{label}: invalid SHA-256")
    if (
        not isinstance(expected_size, int)
        or isinstance(expected_size, bool)
        or expected_size <= 0
    ):
        errors.append(f"{label}: invalid size_bytes")

    path = root.joinpath(*pure.parts)
    if not path.is_file() or path.is_symlink():
        errors.append(
            f"{label}: bound material is missing or not a regular non-symlink file"
        )
        return
    if isinstance(expected_size, int) and not isinstance(expected_size, bool):
        if path.stat().st_size != expected_size:
            errors.append(f"{label}: size mismatch")
    if isinstance(expected_hash, str) and HEX64.fullmatch(expected_hash):
        if sha256_file(path) != expected_hash:
            errors.append(f"{label}: SHA-256 mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--material-dir", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--sbom-license-inventory", type=Path, required=True)
    args = parser.parse_args()

    errors: list[str] = []
    try:
        data = json.loads(args.evidence.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Go license-material validation FAILED: {exc}")
        return 1

    if data.get("schema_version") != "1.0.0":
        errors.append("unexpected schema_version")
    if data.get("gate") != "PPR-04":
        errors.append("evidence must identify PPR-04")
    if data.get("evidence_class") != "GO_LINKED_MODULE_LICENSE_MATERIAL":
        errors.append("unexpected evidence_class")
    if data.get("release_authority") is not False:
        errors.append("evidence must not claim release authority")
    if data.get("license_classification_authority") is not False:
        errors.append("scanner labels must remain non-authoritative")
    if data.get("error_count") != 0:
        errors.append("evidence contains generation errors")

    root = args.material_dir.resolve()
    if not root.is_dir():
        errors.append("material-dir is missing")
    binary = args.binary.resolve()
    sbom = args.sbom_license_inventory.resolve()
    if not binary.is_file():
        errors.append("bound binary is missing")
    if not sbom.is_file():
        errors.append("bound SBOM license inventory is missing")

    binary_binding = data.get("binary")
    if not isinstance(binary_binding, dict):
        errors.append("binary binding is missing")
        binary_binding = {}
    if binary.is_file():
        if binary_binding.get("file") != binary.name:
            errors.append("binary filename binding mismatch")
        if binary_binding.get("sha256") != sha256_file(binary):
            errors.append("binary SHA-256 binding mismatch")
        if binary_binding.get("size_bytes") != binary.stat().st_size:
            errors.append("binary size binding mismatch")

    sbom_binding = data.get("sbom_license_inventory")
    if not isinstance(sbom_binding, dict):
        errors.append("SBOM license-inventory binding is missing")
        sbom_binding = {}
    if sbom.is_file():
        if sbom_binding.get("file") != sbom.name:
            errors.append("SBOM license-inventory filename binding mismatch")
        if sbom_binding.get("sha256") != sha256_file(sbom):
            errors.append("SBOM license-inventory SHA-256 binding mismatch")

    modules = data.get("modules")
    if not isinstance(modules, list) or not modules:
        errors.append("modules must be a non-empty list")
        modules = []
    if data.get("linked_module_count") != len(modules):
        errors.append("linked_module_count must exactly match modules")
    if data.get("modules_with_material_count") != len(modules):
        errors.append("every linked module must have preserved material")

    seen_modules: set[str] = set()
    expected_paths: set[str] = set()
    material_count = 0
    total_bytes = 0
    for module in modules:
        if not isinstance(module, dict):
            errors.append("module entry must be an object")
            continue
        path = module.get("path")
        version = module.get("version")
        module_sum = module.get("module_sum")
        if not isinstance(path, str) or not path:
            errors.append("module path is required")
            continue
        if path in seen_modules:
            errors.append(f"duplicate module path: {path}")
        seen_modules.add(path)
        if not isinstance(version, str) or not version:
            errors.append(f"{path}: version is required")
        if not isinstance(module_sum, str) or not GO_SUM_RE.fullmatch(module_sum):
            errors.append(f"{path}: cryptographic module Sum is required")
        material = module.get("material")
        if not isinstance(material, list) or not material:
            errors.append(f"{path}: preserved license/notice material is required")
            continue
        for item in material:
            if not isinstance(item, dict):
                errors.append(f"{path}: material item must be an object")
                continue
            validate_bound_file(root, item, expected_paths, errors, path)
            material_count += 1
            size = item.get("size_bytes")
            if isinstance(size, int) and not isinstance(size, bool) and size > 0:
                total_bytes += size

    toolchain = data.get("go_toolchain")
    if not isinstance(toolchain, dict):
        errors.append("Go toolchain evidence is missing")
        toolchain = {}
    if (
        not isinstance(toolchain.get("version"), str)
        or not toolchain.get("version", "").strip()
    ):
        errors.append("Go toolchain version is required")
    toolchain_material = toolchain.get("material")
    if not isinstance(toolchain_material, list) or not toolchain_material:
        errors.append("Go toolchain license/notice material is required")
        toolchain_material = []
    for item in toolchain_material:
        if not isinstance(item, dict):
            errors.append("Go toolchain material item must be an object")
            continue
        validate_bound_file(root, item, expected_paths, errors, "Go toolchain")
        material_count += 1
        size = item.get("size_bytes")
        if isinstance(size, int) and not isinstance(size, bool) and size > 0:
            total_bytes += size

    actual_paths: set[str] = set()
    if root.is_dir():
        for path in root.rglob("*"):
            if path.is_symlink():
                errors.append(
                    f"material-dir contains symlink: {path.relative_to(root).as_posix()}"
                )
            elif path.is_file():
                actual_paths.add(path.relative_to(root).as_posix())
    if actual_paths != expected_paths:
        missing = sorted(expected_paths - actual_paths)
        extra = sorted(actual_paths - expected_paths)
        if missing:
            errors.append("material-dir missing bound files: " + ", ".join(missing))
        if extra:
            errors.append("material-dir contains unbound files: " + ", ".join(extra))

    if data.get("material_file_count") != material_count:
        errors.append("material_file_count mismatch")
    if data.get("total_material_bytes") != total_bytes:
        errors.append("total_material_bytes mismatch")

    if errors:
        print("Go linked-module license-material validation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 1

    print(
        "Go linked-module license-material validation passed: "
        f"{len(modules)} linked modules, {material_count} exact material files."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
