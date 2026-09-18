#!/usr/bin/env python3
"""Generate fail-closed Tauri/Rust redistribution preflight evidence for PPR-04."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TAURI_ROOT = ROOT / "benchmarks" / "desktop" / "phase56" / "candidates" / "tauri"
WWW_ROOT = TAURI_ROOT / "www"
REMOTE_REF_RE = re.compile(r"(?i)(?:https?:)?//[a-z0-9]")
EXPECTED_FRONTEND = "www"
EXPECTED_TARGET = "x86_64-pc-windows-msvc"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def load_json(path: Path, errors: list[str]) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(errors, f"cannot load JSON {rel(path)}: {exc}")
        return {}


def inventory_assets(errors: list[str]) -> list[dict]:
    if not WWW_ROOT.is_dir():
        fail(errors, f"missing Tauri frontend directory: {rel(WWW_ROOT)}")
        return []

    assets: list[dict] = []
    for path in sorted(p for p in WWW_ROOT.rglob("*") if p.is_file()):
        raw = path.read_bytes()
        entry = {
            "path": rel(path),
            "size_bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        if path.suffix.lower() in {".html", ".htm", ".css", ".js", ".mjs", ".json", ".svg"}:
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                fail(errors, f"text-like asset is not valid UTF-8: {rel(path)}")
                text = ""
            remote_refs = sorted(set(match.group(0) for match in REMOTE_REF_RE.finditer(text)))
            if remote_refs:
                entry["remote_references"] = remote_refs
                fail(errors, f"remote reference detected in packaged frontend asset: {rel(path)}")
        assets.append(entry)

    if not assets:
        fail(errors, "Tauri frontend asset inventory is empty")
    return assets


def inventory_packages(metadata: dict, errors: list[str]) -> tuple[list[dict], list[dict]]:
    packages = metadata.get("packages")
    resolve = metadata.get("resolve")
    if not isinstance(packages, list) or not isinstance(resolve, dict):
        fail(errors, "cargo metadata must contain packages and resolve")
        return [], []

    nodes = resolve.get("nodes")
    if not isinstance(nodes, list):
        fail(errors, "cargo metadata resolve.nodes must be a list")
        return [], []

    reachable_ids = {node.get("id") for node in nodes if isinstance(node, dict)}
    reachable_ids.discard(None)
    package_by_id = {
        package.get("id"): package
        for package in packages
        if isinstance(package, dict) and package.get("id") in reachable_ids
    }
    missing = sorted(str(package_id) for package_id in reachable_ids if package_id not in package_by_id)
    if missing:
        fail(errors, "cargo metadata is missing reachable packages: " + ", ".join(missing))

    third_party: list[dict] = []
    first_party: list[dict] = []
    for package_id in sorted(package_by_id, key=str):
        package = package_by_id[package_id]
        source = package.get("source")
        item = {
            "id": str(package_id),
            "name": package.get("name"),
            "version": package.get("version"),
            "source": source,
            "license_expression": package.get("license"),
            "license_file": package.get("license_file"),
            "repository": package.get("repository"),
        }

        if source is None:
            first_party.append(item)
            continue

        license_expr = package.get("license")
        license_file = package.get("license_file")
        if not isinstance(license_expr, str) or not license_expr.strip():
            license_expr = None
        if not isinstance(license_file, str) or not license_file.strip():
            license_file = None

        if license_file:
            license_path = Path(license_file)
            if not license_path.is_file():
                fail(errors, f"{package.get('name')} {package.get('version')}: license_file is missing: {license_file}")
            else:
                item["license_file_sha256"] = sha256_file(license_path)
                item["license_file_size_bytes"] = license_path.stat().st_size

        if not license_expr and not license_file:
            fail(
                errors,
                f"{package.get('name')} {package.get('version')}: no license expression or license file in exact cargo metadata",
            )

        third_party.append(item)

    if not third_party:
        fail(errors, "exact Tauri dependency graph contains no third-party packages")
    return third_party, first_party


def validate_tauri_configuration(errors: list[str]) -> dict:
    config_path = TAURI_ROOT / "tauri.conf.json"
    cargo_toml = TAURI_ROOT / "Cargo.toml"
    cargo_lock = TAURI_ROOT / "Cargo.lock"
    build_rs = TAURI_ROOT / "build.rs"

    for path in (config_path, cargo_toml, cargo_lock, build_rs):
        if not path.is_file():
            fail(errors, f"missing Tauri release-control input: {rel(path)}")

    config = load_json(config_path, errors) if config_path.is_file() else {}
    build = config.get("build") if isinstance(config, dict) else {}
    app = config.get("app") if isinstance(config, dict) else {}
    security = app.get("security") if isinstance(app, dict) else {}
    bundle = config.get("bundle") if isinstance(config, dict) else {}

    if not isinstance(build, dict) or build.get("frontendDist") != EXPECTED_FRONTEND:
        fail(errors, f"Tauri frontendDist must remain {EXPECTED_FRONTEND!r}")
    if not isinstance(bundle, dict) or bundle.get("active") is not False:
        fail(errors, "current PPR-04 portable model requires Tauri bundle.active=false")
    csp = security.get("csp") if isinstance(security, dict) else None
    if not isinstance(csp, str) or "connect-src 'none'" not in csp:
        fail(errors, "Tauri CSP must preserve connect-src 'none'")

    files = {}
    for path in (config_path, cargo_toml, cargo_lock, build_rs):
        if path.is_file():
            files[rel(path)] = {
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }

    return {
        "product_name": config.get("productName") if isinstance(config, dict) else None,
        "version": config.get("version") if isinstance(config, dict) else None,
        "identifier": config.get("identifier") if isinstance(config, dict) else None,
        "frontend_dist": build.get("frontendDist") if isinstance(build, dict) else None,
        "bundle_active": bundle.get("active") if isinstance(bundle, dict) else None,
        "csp": csp,
        "control_files": files,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo-metadata", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", default=EXPECTED_TARGET)
    parser.add_argument("--commit", default="")
    args = parser.parse_args()

    errors: list[str] = []
    if args.target != EXPECTED_TARGET:
        fail(errors, f"redistribution preflight target must be {EXPECTED_TARGET}")

    metadata = load_json(args.cargo_metadata, errors)
    third_party, first_party = inventory_packages(metadata, errors) if metadata else ([], [])
    assets = inventory_assets(errors)
    tauri = validate_tauri_configuration(errors)

    metadata_sha = sha256_file(args.cargo_metadata) if args.cargo_metadata.is_file() else None
    evidence = {
        "schema_version": "1.0.0",
        "gate": "PPR-04",
        "evidence_class": "TAURI_RUST_REDISTRIBUTION_PREFLIGHT",
        "release_authority": False,
        "target": args.target,
        "commit": args.commit or None,
        "cargo_metadata_sha256": metadata_sha,
        "tauri": tauri,
        "first_party_packages": first_party,
        "third_party_packages": third_party,
        "frontend_assets": assets,
        "summary": {
            "third_party_package_count": len(third_party),
            "first_party_package_count": len(first_party),
            "frontend_asset_count": len(assets),
            "error_count": len(errors),
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if errors:
        print("PPR-04 Tauri/Rust redistribution preflight FAILED:")
        for error in errors:
            print(f"- {error}")
        print(f"Evidence written to {args.output}")
        return 1

    print(
        "PPR-04 Tauri/Rust redistribution preflight passed: "
        f"{len(third_party)} third-party packages, {len(assets)} frontend assets."
    )
    print(f"Evidence written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
