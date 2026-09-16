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

COMMON_MEASUREMENTS = "phase562-common-measurements.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def positive_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


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


def verify_network_probe(item: dict, context: str) -> None:
    require(item.get("network_listener_seen") is False, f"network listener/endpoint observed {context}")
    require(item.get("tcp_listener_seen") is False, f"TCP listener observed {context}")
    require(item.get("udp_endpoint_seen") is False, f"UDP endpoint observed {context}")


def verify_common_measurements(evidence_dir: Path, packages: dict[str, dict], common_hash: str) -> dict[str, dict]:
    path = evidence_dir / COMMON_MEASUREMENTS
    require(path.is_file(), f"missing common measurement evidence: {path}")
    document = json.loads(path.read_text(encoding="utf-8-sig"))

    require(document.get("evidence_version") == 1, "unsupported common measurement evidence version")
    require(document.get("phase") == "5.6.2", "common measurement phase mismatch")
    require(document.get("measurement_scope") == "common-external-windows-host-probe", "common measurement scope mismatch")
    require(document.get("common_sidecar_sha256") == common_hash, "common measurement sidecar hash mismatch")
    require(isinstance(document.get("network_probe_note"), str) and "TCP" in document["network_probe_note"] and "UDP" in document["network_probe_note"], "common measurement network probe note is incomplete")
    require(isinstance(document.get("warmup_count"), int) and document["warmup_count"] >= 1, "common measurement warmup count is insufficient")
    require(isinstance(document.get("measured_count"), int) and document["measured_count"] >= 5, "common measurement sample count is insufficient")

    items = document.get("candidates")
    require(isinstance(items, list), "common measurement candidates must be an array")
    by_id: dict[str, dict] = {}
    for item in items:
        require(isinstance(item, dict), "common measurement candidate entry must be an object")
        candidate = item.get("candidate")
        require(candidate in CANDIDATES, f"unexpected common measurement candidate: {candidate!r}")
        require(candidate not in by_id, f"duplicate common measurement candidate: {candidate}")
        package = packages[candidate]
        require(item.get("sidecar_sha256") == common_hash, f"common measurement sidecar mismatch for {candidate}")
        require(item.get("package_size_bytes") == package["package_size_bytes"], f"common measurement package size mismatch for {candidate}")
        require(item.get("host_size_bytes") == package["host_size_bytes"], f"common measurement host size mismatch for {candidate}")
        require(item.get("sidecar_size_bytes") == package["sidecar_size_bytes"], f"common measurement sidecar size mismatch for {candidate}")
        verify_network_probe(item, f"for {candidate}")
        require(item.get("warmup_count") == document["warmup_count"], f"warmup count mismatch for {candidate}")
        require(item.get("measured_count") == document["measured_count"], f"measured count mismatch for {candidate}")

        first = item.get("first_launch")
        require(isinstance(first, dict), f"first-launch evidence missing for {candidate}")
        require(first.get("candidate") == candidate and first.get("sample_kind") == "first-launch", f"invalid first-launch identity for {candidate}")
        verify_network_probe(first, f"during first launch for {candidate}")
        require(first.get("sidecar_sha256") == common_hash, f"first-launch sidecar mismatch for {candidate}")
        require(first.get("host_sha256") == package["host_sha256"], f"first-launch host hash mismatch for {candidate}")
        require(positive_number(first.get("external_process_total_ms")), f"invalid first-launch timing for {candidate}")
        require(positive_number(first.get("peak_tree_working_set_bytes")), f"invalid first-launch working set for {candidate}")
        require(isinstance(first.get("max_process_count"), int) and first["max_process_count"] >= 1, f"invalid first-launch process count for {candidate}")

        samples = item.get("measured_samples")
        require(isinstance(samples, list) and len(samples) == document["measured_count"], f"measured sample cardinality mismatch for {candidate}")
        for index, sample in enumerate(samples, start=1):
            require(isinstance(sample, dict), f"invalid measured sample for {candidate}")
            require(sample.get("candidate") == candidate and sample.get("sample_kind") == "measured", f"invalid measured sample identity for {candidate}")
            require(sample.get("sample_index") == index, f"measured sample index mismatch for {candidate}")
            verify_network_probe(sample, f"in measured sample {index} for {candidate}")
            require(sample.get("sidecar_sha256") == common_hash, f"measured sidecar mismatch for {candidate}")
            require(sample.get("host_sha256") == package["host_sha256"], f"measured host hash mismatch for {candidate}")
            require(positive_number(sample.get("external_process_total_ms")), f"invalid measured timing for {candidate}")
            require(positive_number(sample.get("peak_tree_working_set_bytes")), f"invalid measured working set for {candidate}")
            require(isinstance(sample.get("max_process_count"), int) and sample["max_process_count"] >= 1, f"invalid measured process count for {candidate}")

        for field in (
            "external_process_total_ms_median",
            "external_process_total_ms_p95",
            "peak_tree_working_set_bytes_median",
            "peak_tree_working_set_bytes_p95",
        ):
            require(positive_number(item.get(field)), f"invalid {field} for {candidate}")
        require(isinstance(item.get("max_process_count_p95"), int) and item["max_process_count_p95"] >= 1, f"invalid process-count p95 for {candidate}")

        by_id[candidate] = {
            "package_size_bytes": item["package_size_bytes"],
            "first_launch_external_ms": first["external_process_total_ms"],
            "external_process_total_ms_median": item["external_process_total_ms_median"],
            "external_process_total_ms_p95": item["external_process_total_ms_p95"],
            "peak_tree_working_set_bytes_median": item["peak_tree_working_set_bytes_median"],
            "peak_tree_working_set_bytes_p95": item["peak_tree_working_set_bytes_p95"],
            "max_process_count_p95": item["max_process_count_p95"],
            "network_listener_seen": False,
            "tcp_listener_seen": False,
            "udp_endpoint_seen": False,
        }

    require(set(by_id) == set(CANDIDATES), "common measurement candidate set is incomplete")
    return by_id


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--stage-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    evidence_dir = Path(args.evidence_dir)
    stage = Path(args.stage_dir)
    rows: dict[str, dict] = {}
    packages: dict[str, dict] = {}
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
        require(positive_number(item.get("round_trip_ms")), f"invalid IPC measurement in {filename}")

        package = verify_package(stage, package_dir, host_name, item)
        packages[expected_id] = package
        common_hashes.add(package["sidecar_sha256"])
        if isinstance(status.get("core_commit"), str):
            core_commits.add(status["core_commit"])
        rows[expected_id] = {
            "host_runtime": item.get("host_runtime"),
            "round_trip_ms_reference_only": item["round_trip_ms"],
            "status_result": status,
            **package,
        }

    require(len(common_hashes) == 1, "candidate packages do not contain the identical atlas-core binary")
    require(len(core_commits) == 1, "candidate probes do not report one identical core commit")
    common_hash = next(iter(common_hashes))
    expected_sha = os.environ.get("GITHUB_SHA")
    if expected_sha:
        require(next(iter(core_commits)) == expected_sha, f"atlas-core commit does not match exact workflow SHA: {core_commits}")

    common_measurements = verify_common_measurements(evidence_dir, packages, common_hash)

    summary = {
        "phase": "5.6",
        "slice": "5.6.2-evidence-review",
        "exact_head": expected_sha,
        "common_atlas_core_sha256": common_hash,
        "common_core_commit": next(iter(core_commits)),
        "candidates": rows,
        "common_external_measurements": common_measurements,
        "measurement_interpretation": {
            "candidate_internal_round_trip_ms": "REFERENCE_ONLY_NOT_CROSS_CANDIDATE_COMPARABLE",
            "external_process_total_ms": "COMMON_HARNESS_COMPARABLE_ON_THIS_RUNNER",
            "first_launch": "FIRST_POST_BUILD_LAUNCH_NOT_LABORATORY_OS_COLD_CACHE",
            "true_cold_cache": "PENDING",
            "build_duration": "PENDING",
        },
        "observed_hard_gates": {
            "G-D1-windows-clean-build": "PASS",
            "G-D2-atlas-core-stdio-handshake-and-status": "PASS",
            "G-D3-offline-no-default-network-listener": "PASS",
            "G-D4-sidecar-location-and-integrity-control": "PASS",
            "G-D5-search-record-graph-provenance-capability": "PASS_VERIFIED_SEPARATELY",
            "G-D6-pack-status-update-and-rollback-capability": "PASS_VERIFIED_SEPARATELY",
            "G-D7-desktop-security-surface": "PENDING_5.6.2",
            "G-D8-installer-and-portable-mode-feasibility": "PENDING_5.6.2",
            "G-D9-footprint-startup-and-ipc-measurements": "PARTIAL_COMMON_HARNESS_CAPTURED",
        },
        "selection_authorized": False,
        "selection_reason": "ADR-0026 remains blocked until 5.6.2 completes every hard gate, closes supply-chain requirements, and completes the weighted review.",
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
