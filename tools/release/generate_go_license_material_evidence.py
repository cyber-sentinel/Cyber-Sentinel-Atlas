#!/usr/bin/env python3
"""Preserve exact Go linked-module/toolchain license material for PPR-04 evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

LICENSE_NAME_RE = re.compile(
    r"^(?:licen[cs]e|copying|notice|copyrights?|patents?|unlicense)(?:$|[._-].*)",
    re.IGNORECASE,
)
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_json_stream(text: str) -> list[dict]:
    decoder = json.JSONDecoder()
    position = 0
    output: list[dict] = []
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position >= len(text):
            break
        value, position = decoder.raw_decode(text, position)
        if not isinstance(value, dict):
            raise ValueError("go list JSON stream contained a non-object")
        output.append(value)
    return output


def binary_modules(binary: Path) -> dict[str, str]:
    raw = subprocess.check_output(
        ["go", "version", "-m", str(binary)],
        text=True,
        encoding="utf-8",
    )
    modules: dict[str, str] = {}
    for line in raw.splitlines():
        fields = line.strip().split("\t")
        if len(fields) < 3 or fields[0] != "dep":
            continue
        module, version = fields[1], fields[2]
        previous = modules.get(module)
        if previous is not None and previous != version:
            raise ValueError(
                f"binary contains conflicting versions for {module}: "
                f"{previous!r} and {version!r}"
            )
        modules[module] = version
    if not modules:
        raise ValueError("binary exposes no linked third-party Go modules")
    return modules


def material_candidates(root: Path, label: str, errors: list[str]) -> list[Path]:
    if not root.is_dir():
        errors.append(f"{label}: source directory is missing")
        return []
    candidates: list[Path] = []
    seen_casefold: set[str] = set()
    for path in sorted(root.iterdir(), key=lambda p: p.name.casefold()):
        if not LICENSE_NAME_RE.fullmatch(path.name):
            continue
        if path.is_symlink():
            errors.append(f"{label}: license material must not be a symlink: {path.name}")
            continue
        if not path.is_file():
            continue
        folded = path.name.casefold()
        if folded in seen_casefold:
            errors.append(f"{label}: case-insensitive duplicate material filename: {path.name}")
            continue
        seen_casefold.add(folded)
        size = path.stat().st_size
        if size <= 0:
            errors.append(f"{label}: empty license material: {path.name}")
            continue
        if size > MAX_FILE_BYTES:
            errors.append(f"{label}: oversized license material: {path.name} ({size} bytes)")
            continue
        candidates.append(path)
    return candidates


def load_sbom_inventory(path: Path) -> tuple[dict[str, dict], str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    components = data.get("components")
    if not isinstance(components, list):
        raise ValueError("SBOM license inventory components must be a list")
    result: dict[str, dict] = {}
    for component in components:
        if not isinstance(component, dict) or component.get("linked_module") is not True:
            continue
        name = component.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("linked SBOM component is missing name")
        if name in result:
            raise ValueError(f"duplicate linked SBOM component: {name}")
        result[name] = component
    return result, sha256_file(path)


def copy_material(
    source_files: list[Path],
    destination_root: Path,
    prefix: str,
    errors: list[str],
) -> tuple[list[dict], int]:
    output: list[dict] = []
    total = 0
    target_root = destination_root / prefix
    target_root.mkdir(parents=True, exist_ok=True)
    for source in source_files:
        destination = target_root / source.name
        if destination.exists():
            errors.append(
                "duplicate output material path: "
                + destination.relative_to(destination_root).as_posix()
            )
            continue
        shutil.copyfile(source, destination)
        source_hash = sha256_file(source)
        copied_hash = sha256_file(destination)
        if copied_hash != source_hash:
            errors.append(f"copied material hash mismatch: {source.name}")
            continue
        size = destination.stat().st_size
        total += size
        output.append(
            {
                "file": source.name,
                "bundle_path": destination.relative_to(destination_root).as_posix(),
                "sha256": copied_hash,
                "size_bytes": size,
            }
        )
    return output, total


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--module-root", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--sbom-license-inventory", type=Path, required=True)
    parser.add_argument("--material-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runner-os", required=True)
    args = parser.parse_args()

    errors: list[str] = []
    binary = args.binary.resolve()
    sbom_inventory = args.sbom_license_inventory.resolve()

    if not binary.is_file():
        errors.append(f"binary is missing: {args.binary}")
    if not sbom_inventory.is_file():
        errors.append(f"SBOM license inventory is missing: {args.sbom_license_inventory}")

    material_root = args.material_dir.resolve()
    if material_root.exists() and any(material_root.iterdir()):
        errors.append("material-dir must be absent or empty to prevent stale evidence reuse")
    material_root.mkdir(parents=True, exist_ok=True)

    linked: dict[str, str] = {}
    module_rows: dict[str, dict] = {}
    sbom_by_module: dict[str, dict] = {}
    sbom_sha: str | None = None

    if binary.is_file():
        try:
            linked = binary_modules(binary)
        except Exception as exc:
            errors.append(f"cannot resolve binary linked modules: {exc}")

    try:
        raw = subprocess.check_output(
            ["go", "list", "-m", "-json", "all"],
            cwd=args.module_root,
            text=True,
            encoding="utf-8",
        )
        rows = decode_json_stream(raw)
        module_rows = {
            str(row.get("Path")): row
            for row in rows
            if isinstance(row.get("Path"), str) and row.get("Path")
        }
    except Exception as exc:
        errors.append(f"cannot resolve exact Go module graph: {exc}")

    if sbom_inventory.is_file():
        try:
            sbom_by_module, sbom_sha = load_sbom_inventory(sbom_inventory)
        except Exception as exc:
            errors.append(f"cannot load SBOM license inventory: {exc}")

    module_evidence: list[dict] = []
    total_material_bytes = 0
    for module in sorted(linked):
        version = linked[module]
        row = module_rows.get(module)
        if not isinstance(row, dict):
            errors.append(f"{module}: linked module missing from go list graph")
            continue
        if row.get("Version") != version:
            errors.append(
                f"{module}: module graph version mismatch "
                f"({row.get('Version')!r} != {version!r})"
            )
        module_sum = row.get("Sum")
        if not isinstance(module_sum, str) or not module_sum.strip():
            errors.append(f"{module}: linked module has no cryptographic module Sum")
            module_sum = None
        directory = row.get("Dir")
        if not isinstance(directory, str) or not directory.strip():
            errors.append(f"{module}: linked module has no local source directory")
            continue
        root = Path(directory)
        source_files = material_candidates(root, f"{module}@{version}", errors)
        if not source_files:
            errors.append(f"{module}@{version}: no root license/notice material found")
            continue

        key = hashlib.sha256(f"{module}@{version}".encode("utf-8")).hexdigest()[:20]
        materials, copied_bytes = copy_material(
            source_files,
            material_root,
            f"modules/{key}",
            errors,
        )
        total_material_bytes += copied_bytes

        sbom_component = sbom_by_module.get(module)
        if not isinstance(sbom_component, dict):
            errors.append(f"{module}: missing linked-module entry in SBOM license inventory")
            sbom_component = {}
        elif sbom_component.get("version") != version:
            errors.append(
                f"{module}: SBOM license inventory version mismatch "
                f"({sbom_component.get('version')!r} != {version!r})"
            )

        module_evidence.append(
            {
                "path": module,
                "version": version,
                "module_sum": module_sum,
                "material": materials,
                "sbom_component_licenses": sbom_component.get("licenses", []),
                "sbom_license_evidence": sbom_component.get("license_evidence", []),
            }
        )

    goroot_material: list[dict] = []
    go_version: str | None = None
    try:
        goroot = Path(
            subprocess.check_output(
                ["go", "env", "GOROOT"], text=True, encoding="utf-8"
            ).strip()
        )
        go_version = subprocess.check_output(
            ["go", "version"], text=True, encoding="utf-8"
        ).strip()
        source_files = material_candidates(goroot, "Go toolchain", errors)
        if not source_files:
            errors.append("Go toolchain: no root license/notice material found")
        else:
            goroot_material, copied_bytes = copy_material(
                source_files,
                material_root,
                "toolchain",
                errors,
            )
            total_material_bytes += copied_bytes
    except Exception as exc:
        errors.append(f"cannot preserve Go toolchain license material: {exc}")

    if total_material_bytes > MAX_TOTAL_BYTES:
        errors.append(
            f"total preserved license material exceeds {MAX_TOTAL_BYTES} bytes: "
            f"{total_material_bytes}"
        )

    material_file_count = (
        sum(len(item["material"]) for item in module_evidence) + len(goroot_material)
    )
    evidence = {
        "schema_version": "1.0.0",
        "gate": "PPR-04",
        "evidence_class": "GO_LINKED_MODULE_LICENSE_MATERIAL",
        "release_authority": False,
        "license_classification_authority": False,
        "runner_os": args.runner_os,
        "binary": {
            "file": binary.name,
            "sha256": sha256_file(binary) if binary.is_file() else None,
            "size_bytes": binary.stat().st_size if binary.is_file() else None,
        },
        "sbom_license_inventory": {
            "file": sbom_inventory.name,
            "sha256": sbom_sha,
        },
        "go_toolchain": {
            "version": go_version,
            "material": goroot_material,
        },
        "linked_module_count": len(linked),
        "modules_with_material_count": len(module_evidence),
        "material_file_count": material_file_count,
        "total_material_bytes": total_material_bytes,
        "modules": module_evidence,
        "notes": [
            "Preserved license/notice bytes are cryptographic review evidence, not an automated legal classification.",
            "SBOM-reported license labels are retained for comparison but are explicitly non-authoritative.",
        ],
        "error_count": len(errors),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    if errors:
        print("Go linked-module license-material generation FAILED:")
        for error in errors:
            print(f"- {error}")
        print(f"Evidence written to {args.output}")
        return 1

    print(
        "Go linked-module license-material generation passed: "
        f"{len(module_evidence)} linked modules, {material_file_count} material files."
    )
    print(f"Evidence written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
