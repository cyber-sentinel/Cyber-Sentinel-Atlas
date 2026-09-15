#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

CANDIDATES = {
    "tauri-v2": ("tauri.json", "tauri", "atlas-tauri-candidate.exe"),
    "electron": ("electron.json", "electron", "electron.exe"),
    "dotnet-wpf": ("dotnet.json", "dotnet", "Atlas.DotNetCandidate.exe"),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def directory_size(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def verify_package(stage: Path, subdir: str, host_name: str, evidence: dict) -> dict:
    package = stage / subdir
    host = package / host_name
    core = package / "atlas-core.exe"
    manifest = package / "atlas-core.exe.sha256"
    for path in (package, host, core, manifest):
        require(path.exists(), f"missing packaged candidate artifact: {path}")

    expected = manifest.read_text(encoding="utf-8").strip().split()[0].lower()
    require(len(expected) == 64 and all(ch in "0123456789abcdef" for ch in expected), f"invalid sidecar manifest: {manifest}")
    core_hash = sha256_file(core)
    host_hash = sha256_file(host)
    require(core_hash == expected, f"packaged sidecar hash mismatch for {subdir}")
    require(evidence["sidecar_sha256"] == core_hash, f"runtime sidecar hash mismatch for {subdir}")
    require(evidence["host_sha256"] == host_hash, f"runtime host hash mismatch for {subdir}")
    require(evidence["sidecar_size_bytes"] == core.stat().st_size, f"sidecar size mismatch for {subdir}")
    require(evidence["host_size_bytes"] == host.stat().st_size, f"host size mismatch for {subdir}")
    return {
        "package_size_bytes": directory_size(package),
        "host_size_bytes": host.stat().st_size,
        "host_sha256": host_hash,
        "sidecar_size_bytes": core.stat().st_size,
        "sidecar_sha256": core_hash,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--stage-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    evidence_dir = Path(args.evidence_dir)
    stage = Path(args.stage_dir)
    rows: dict[str, dict] = {}
    common_hashes: set[str] = set()
    core_commits: set[str] = set()

    for expected_id, (filename, package_dir, host_name) in CANDIDATES.items():
        path = evidence_dir / filename
        require(path.is_file(), f"missing candidate evidence: {path}")
        item = json.loads(path.read_text(encoding="utf-8"))
        require(item.get("candidate") == expected_id, f"candidate identity mismatch in {filename}")
        require(item.get("protocol") == "atlas-core", f"protocol mismatch in {filename}")
        require(item.get("protocol_version") == "1.0.0", f"protocol version mismatch in {filename}")
        require(item.get("session_nonce_echoed") is True, f"nonce was not echoed in {filename}")
        require(item.get("stderr_bytes") == 0, f"atlas-core emitted stderr in {filename}")
        status = item.get("status_result")
        require(isinstance(status, dict), f"missing core.status object in {filename}")
        require(status.get("protocol") == "atlas-core", f"core.status protocol mismatch in {filename}")
        require(status.get("version") == "1.0.0", f"core.status version mismatch in {filename}")
        require(status.get("network_listener") is False, f"network listener unexpectedly enabled in {filename}")
        require(status.get("offline_capable") is True, f"offline capability false in {filename}")
        require(isinstance(item.get("round_trip_ms"), (int, float)) and item["round_trip_ms"] > 0, f"invalid IPC measurement in {filename}")

        package = verify_package(stage, package_dir, host_name, item)
        common_hashes.add(package["sidecar_sha256"])
        if isinstance(status.get("core_commit"), str):
            core_commits.add(status["core_commit"])
        rows[expected_id] = {
            "host_runtime": item.get("host_runtime"),
            "round_trip_ms": item["round_trip_ms"],
            "status_result": status,
            **package,
        }

    require(len(common_hashes) == 1, "candidate packages do not contain the identical atlas-core binary")
    require(len(core_commits) == 1, "candidate probes do not report one identical core commit")
    expected_sha = os.environ.get("GITHUB_SHA")
    if expected_sha:
        require(next(iter(core_commits)) == expected_sha, f"atlas-core commit does not match exact workflow SHA: {core_commits}")

    summary = {
        "phase": "5.6",
        "slice": "5.6.1",
        "exact_head": expected_sha,
        "common_atlas_core_sha256": next(iter(common_hashes)),
        "common_core_commit": next(iter(core_commits)),
        "candidates": rows,
        "observed_hard_gates": {
            "G-D1-windows-clean-build": "PASS",
            "G-D2-atlas-core-stdio-handshake-and-status": "PASS",
            "G-D3-offline-no-default-network-listener": "CORE_BOUNDARY_PASS_HOST_REVIEW_PENDING",
            "G-D4-sidecar-location-and-integrity-control": "PASS",
            "G-D5-search-record-graph-provenance-capability": "PENDING_5.6.2",
            "G-D6-pack-status-update-and-rollback-capability": "PENDING_5.6.2",
            "G-D7-desktop-security-surface": "PENDING_5.6.2",
            "G-D8-installer-and-portable-mode-feasibility": "PENDING_5.6.2",
            "G-D9-footprint-startup-and-ipc-measurements": "PARTIAL_MEASUREMENTS_CAPTURED"
        },
        "selection_authorized": False,
        "selection_reason": "ADR-0026 is intentionally blocked until 5.6.2 completes every hard gate and weighted review."
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
