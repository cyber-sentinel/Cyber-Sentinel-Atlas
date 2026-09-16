#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

EXPECTED_CANDIDATES = {"tauri-v2", "electron", "dotnet-wpf"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def positive_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def verify_host_measurements(document: dict, common_hash: str) -> dict[str, dict]:
    require(document.get("evidence_version") == 1, "unsupported host measurement evidence version")
    require(document.get("phase") == "5.6.2", "host measurement phase mismatch")
    require(document.get("measurement_scope") == "common-external-windows-host-probe", "host measurement scope mismatch")
    require(document.get("common_sidecar_sha256") == common_hash, "host measurement sidecar hash mismatch")
    require(isinstance(document.get("warmup_count"), int) and document["warmup_count"] >= 1, "host warmup count is insufficient")
    require(isinstance(document.get("measured_count"), int) and document["measured_count"] >= 5, "host measured sample count is insufficient")

    rows = document.get("candidates")
    require(isinstance(rows, list), "host measurement candidates must be an array")
    by_id: dict[str, dict] = {}
    for row in rows:
        require(isinstance(row, dict), "invalid host measurement row")
        candidate = row.get("candidate")
        require(candidate in EXPECTED_CANDIDATES, f"unexpected host measurement candidate: {candidate!r}")
        require(candidate not in by_id, f"duplicate host measurement candidate: {candidate}")
        require(row.get("sidecar_sha256") == common_hash, f"host measurement sidecar mismatch for {candidate}")
        require(isinstance(row.get("package_size_bytes"), int) and row["package_size_bytes"] > 0, f"invalid package footprint for {candidate}")
        require(isinstance(row.get("host_size_bytes"), int) and row["host_size_bytes"] > 0, f"invalid host footprint for {candidate}")
        require(isinstance(row.get("sidecar_size_bytes"), int) and row["sidecar_size_bytes"] > 0, f"invalid sidecar footprint for {candidate}")
        require(row.get("network_listener_seen") is False, f"network listener observed for {candidate}")
        require(row.get("tcp_listener_seen") is False, f"TCP listener observed for {candidate}")
        require(row.get("udp_endpoint_seen") is False, f"UDP endpoint observed for {candidate}")

        cold = row.get("first_launch")
        require(isinstance(cold, dict) and cold.get("sample_kind") == "first-launch", f"cold/first launch evidence missing for {candidate}")
        require(positive_number(cold.get("external_process_total_ms")), f"invalid cold/first launch timing for {candidate}")
        require(positive_number(cold.get("peak_tree_working_set_bytes")), f"invalid cold/first launch memory for {candidate}")
        require(isinstance(cold.get("max_process_count"), int) and cold["max_process_count"] >= 1, f"invalid cold/first process count for {candidate}")
        require(cold.get("network_listener_seen") is False, f"network listener observed on cold/first launch for {candidate}")
        require(cold.get("tcp_listener_seen") is False, f"TCP listener observed on cold/first launch for {candidate}")
        require(cold.get("udp_endpoint_seen") is False, f"UDP endpoint observed on cold/first launch for {candidate}")

        samples = row.get("measured_samples")
        require(isinstance(samples, list) and len(samples) == document["measured_count"], f"warm measurement sample count mismatch for {candidate}")
        for index, sample in enumerate(samples, start=1):
            require(isinstance(sample, dict), f"invalid warm sample for {candidate}")
            require(sample.get("sample_kind") == "measured" and sample.get("sample_index") == index, f"warm sample identity mismatch for {candidate}")
            require(positive_number(sample.get("external_process_total_ms")), f"invalid warm timing for {candidate} sample {index}")
            require(positive_number(sample.get("peak_tree_working_set_bytes")), f"invalid warm memory for {candidate} sample {index}")
            require(isinstance(sample.get("max_process_count"), int) and sample["max_process_count"] >= 1, f"invalid warm process count for {candidate} sample {index}")
            require(sample.get("network_listener_seen") is False, f"network listener observed for {candidate} sample {index}")
            require(sample.get("tcp_listener_seen") is False, f"TCP listener observed for {candidate} sample {index}")
            require(sample.get("udp_endpoint_seen") is False, f"UDP endpoint observed for {candidate} sample {index}")

        for field in (
            "external_process_total_ms_median",
            "external_process_total_ms_p95",
            "peak_tree_working_set_bytes_median",
            "peak_tree_working_set_bytes_p95",
        ):
            require(positive_number(row.get(field)), f"invalid {field} for {candidate}")
        require(isinstance(row.get("max_process_count_p95"), int) and row["max_process_count_p95"] >= 1, f"invalid max_process_count_p95 for {candidate}")
        by_id[candidate] = row

    require(set(by_id) == EXPECTED_CANDIDATES, "host measurement candidate set is incomplete")
    return by_id


def verify_core_ipc(document: dict, common_hash: str, common_commit: str) -> None:
    require(document.get("evidence_version") == 1, "unsupported core IPC evidence version")
    require(document.get("phase") == "5.6.2", "core IPC phase mismatch")
    require(document.get("gate") == "G-D9-footprint-startup-and-ipc-measurements", "core IPC gate mismatch")
    require(document.get("measurement_scope") == "common-identical-sidecar-stdio-ipc", "core IPC measurement scope mismatch")
    require(document.get("sidecar_sha256") == common_hash, "core IPC sidecar hash mismatch")
    require(document.get("core_commit") == common_commit, "core IPC commit mismatch")
    expected_sha = os.environ.get("GITHUB_SHA")
    if expected_sha:
        require(document.get("core_commit") == expected_sha, "core IPC evidence does not match exact workflow SHA")
    require(isinstance(document.get("cold_start_definition"), str) and "OS page cache is not forcibly purged" in document["cold_start_definition"], "cold-start definition missing cache qualification")
    require(isinstance(document.get("warm_start_definition"), str) and document["warm_start_definition"], "warm-start definition missing")
    require(isinstance(document.get("warmup_count"), int) and document["warmup_count"] >= 1, "core IPC warmup count is insufficient")
    require(isinstance(document.get("measured_count"), int) and document["measured_count"] >= 5, "core IPC measured sample count is insufficient")
    require(document.get("selection_authorized") is False, "core IPC evidence must not authorize selection")

    cold = document.get("cold_first_post_build")
    require(isinstance(cold, dict), "core IPC cold sample missing")
    for field in ("handshake_ms", "status_ms", "handshake_plus_status_ms", "process_total_ms"):
        require(positive_number(cold.get(field)), f"invalid cold core IPC {field}")
    require(cold.get("network_listener") is False and cold.get("offline_capable") is True, "cold core IPC posture mismatch")

    samples = document.get("measured_samples")
    require(isinstance(samples, list) and len(samples) == document["measured_count"], "core IPC measured sample count mismatch")
    for index, sample in enumerate(samples, start=1):
        require(isinstance(sample, dict), "invalid core IPC measured sample")
        require(sample.get("sample_kind") == "measured-warm" and sample.get("sample_index") == index, "core IPC measured sample identity mismatch")
        require(sample.get("sidecar_sha256") == common_hash, "core IPC measured sample hash mismatch")
        require(sample.get("core_commit") == common_commit, "core IPC measured sample commit mismatch")
        require(sample.get("network_listener") is False and sample.get("offline_capable") is True, "core IPC measured sample posture mismatch")
        for field in ("handshake_ms", "status_ms", "handshake_plus_status_ms", "process_total_ms"):
            require(positive_number(sample.get(field)), f"invalid core IPC {field} in sample {index}")

    for field in (
        "handshake_ms_median",
        "handshake_ms_p95",
        "status_ms_median",
        "status_ms_p95",
        "handshake_plus_status_ms_median",
        "handshake_plus_status_ms_p95",
        "process_total_ms_median",
        "process_total_ms_p95",
    ):
        require(positive_number(document.get(field)), f"invalid aggregate core IPC metric: {field}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--summary", required=True)
    args = parser.parse_args()

    evidence_dir = Path(args.evidence_dir)
    summary_path = Path(args.summary)
    host_path = evidence_dir / "phase562-common-measurements.json"
    ipc_path = evidence_dir / "phase562-core-ipc.json"

    require(summary_path.is_file(), f"missing candidate summary: {summary_path}")
    require(host_path.is_file(), f"missing common host measurements: {host_path}")
    require(ipc_path.is_file(), f"missing common core IPC measurements: {ipc_path}")

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    common_hash = summary.get("common_atlas_core_sha256")
    common_commit = summary.get("common_core_commit")
    require(isinstance(common_hash, str) and len(common_hash) == 64, "candidate summary common core hash missing")
    require(isinstance(common_commit, str) and common_commit, "candidate summary common core commit missing")

    host = json.loads(host_path.read_text(encoding="utf-8-sig"))
    host_rows = verify_host_measurements(host, common_hash)
    ipc = json.loads(ipc_path.read_text(encoding="utf-8-sig"))
    verify_core_ipc(ipc, common_hash, common_commit)

    gates = summary.get("observed_hard_gates")
    require(isinstance(gates, dict), "candidate summary hard-gate object missing")
    require(gates.get("G-D3-offline-no-default-network-listener") == "PASS", "G-D9 requires verified G-D3 evidence")
    require(gates.get("G-D7-desktop-security-surface") == "PASS", "G-D9 requires G-D7 to pass in the same candidate run")
    require(gates.get("G-D8-installer-and-portable-mode-feasibility") == "PASS_FEASIBILITY", "G-D9 closure must run after G-D8 feasibility validation")

    summary["measurement_closure"] = {
        "gate": "G-D9-footprint-startup-and-ipc-measurements",
        "state": "PASS",
        "cold_start_semantics": "first post-build/staged process launch; OS page cache is not forcibly purged",
        "warm_start_semantics": "measured process launches after warmup on the same runner/job",
        "candidate_metrics": {
            candidate: {
                "package_size_bytes": row["package_size_bytes"],
                "cold_first_launch_external_ms": row["first_launch"]["external_process_total_ms"],
                "warm_external_ms_median": row["external_process_total_ms_median"],
                "warm_external_ms_p95": row["external_process_total_ms_p95"],
                "peak_tree_working_set_bytes_median": row["peak_tree_working_set_bytes_median"],
                "peak_tree_working_set_bytes_p95": row["peak_tree_working_set_bytes_p95"],
                "max_process_count_p95": row["max_process_count_p95"],
            }
            for candidate, row in sorted(host_rows.items())
        },
        "common_core_ipc": {
            "sidecar_sha256": ipc["sidecar_sha256"],
            "cold_handshake_ms": ipc["cold_first_post_build"]["handshake_ms"],
            "cold_status_ms": ipc["cold_first_post_build"]["status_ms"],
            "warm_handshake_ms_median": ipc["handshake_ms_median"],
            "warm_handshake_ms_p95": ipc["handshake_ms_p95"],
            "warm_status_ms_median": ipc["status_ms_median"],
            "warm_status_ms_p95": ipc["status_ms_p95"],
        },
        "build_duration": "NOT_A_G_D9_HARD_GATE",
        "selection_authorized": False,
    }
    gates["G-D9-footprint-startup-and-ipc-measurements"] = "PASS"
    summary["selection_authorized"] = False
    summary["selection_reason"] = "All executable hard-gate evidence in this candidate workflow is closed; ADR-0026 remains blocked until the weighted review is generated, reviewed, and accepted."

    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary["measurement_closure"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
