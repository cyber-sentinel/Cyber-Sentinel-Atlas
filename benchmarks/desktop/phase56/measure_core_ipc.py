#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import struct
import subprocess
import time
from typing import BinaryIO

MAX_FRAME = 8 * 1024 * 1024
ENV_ALLOWLIST = (
    "PATH",
    "SystemRoot",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def frame(payload: dict) -> bytes:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    require(0 < len(body) <= MAX_FRAME, "request frame length is invalid")
    return struct.pack(">I", len(body)) + body


def read_exact(stream: BinaryIO, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise RuntimeError(f"truncated atlas-core response: wanted {length} bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(stream: BinaryIO) -> dict:
    prefix = read_exact(stream, 4)
    length = struct.unpack(">I", prefix)[0]
    require(0 < length <= MAX_FRAME, f"invalid response frame length: {length}")
    body = read_exact(stream, length)
    value = json.loads(body.decode("utf-8"))
    require(isinstance(value, dict), "atlas-core response must be an object")
    return value


def percentile_nearest_rank(values: list[float], percentile: float) -> float:
    require(bool(values), "percentile requires values")
    ordered = sorted(values)
    rank = max(1, min(len(ordered), math.ceil(percentile * len(ordered))))
    return ordered[rank - 1]


def minimal_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for key in ENV_ALLOWLIST:
        value = os.environ.get(key)
        if value:
            env[key] = value
    return env


def invoke_sample(core: Path, expected_hash: str, sample_kind: str, sample_index: int) -> dict:
    nonce = f"phase562-core-ipc-{sample_kind}-{sample_index}-{time.time_ns()}"
    handshake = {
        "id": f"handshake-{sample_kind}-{sample_index}",
        "method": "core.handshake",
        "params": {
            "protocol": "atlas-core",
            "version": "1.0.0",
            "client_name": "phase562-common-ipc-harness",
            "client_version": "1.0.0",
            "session_nonce": nonce,
        },
    }
    status = {
        "id": f"status-{sample_kind}-{sample_index}",
        "method": "core.status",
        "params": {},
    }

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    process_started = time.perf_counter_ns()
    process = subprocess.Popen(
        [str(core), "--serve-stdio"],
        cwd=str(core.parent),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=minimal_env(),
        creationflags=creationflags,
    )
    require(process.stdin is not None and process.stdout is not None and process.stderr is not None, "stdio pipe creation failed")

    try:
        handshake_started = time.perf_counter_ns()
        process.stdin.write(frame(handshake))
        process.stdin.flush()
        handshake_response = read_frame(process.stdout)
        handshake_ms = (time.perf_counter_ns() - handshake_started) / 1_000_000.0

        require(handshake_response.get("id") == handshake["id"], "handshake response id mismatch")
        require(handshake_response.get("ok") is True, f"handshake failed: {handshake_response}")
        handshake_result = handshake_response.get("result")
        require(isinstance(handshake_result, dict), "handshake result missing")
        require(handshake_result.get("protocol") == "atlas-core", "handshake protocol mismatch")
        require(handshake_result.get("version") == "1.0.0", "handshake protocol version mismatch")
        require(handshake_result.get("session_nonce") == nonce, "handshake nonce mismatch")

        status_started = time.perf_counter_ns()
        process.stdin.write(frame(status))
        process.stdin.flush()
        status_response = read_frame(process.stdout)
        status_ms = (time.perf_counter_ns() - status_started) / 1_000_000.0

        require(status_response.get("id") == status["id"], "status response id mismatch")
        require(status_response.get("ok") is True, f"core.status failed: {status_response}")
        status_result = status_response.get("result")
        require(isinstance(status_result, dict), "core.status result missing")
        require(status_result.get("protocol") == "atlas-core", "core.status protocol mismatch")
        require(status_result.get("version") == "1.0.0", "core.status version mismatch")
        require(status_result.get("network_listener") is False, "core.status network listener unexpectedly enabled")
        require(status_result.get("offline_capable") is True, "core.status offline capability false")
        expected_commit = os.environ.get("GITHUB_SHA")
        if expected_commit:
            require(status_result.get("core_commit") == expected_commit, "core.status exact-head commit mismatch")

        process.stdin.close()
        process.wait(timeout=15)
        process_total_ms = (time.perf_counter_ns() - process_started) / 1_000_000.0
        stderr = process.stderr.read()
        trailing_stdout = process.stdout.read()
        require(process.returncode == 0, f"atlas-core exited {process.returncode}: {stderr[:2000]!r}")
        require(stderr == b"", f"atlas-core emitted stderr during IPC measurement: {stderr[:2000]!r}")
        require(trailing_stdout == b"", "atlas-core emitted unexpected trailing protocol bytes")

        actual_hash = sha256_file(core)
        require(actual_hash == expected_hash, "atlas-core changed during IPC measurement")

        return {
            "sample_kind": sample_kind,
            "sample_index": sample_index,
            "handshake_ms": round(handshake_ms, 3),
            "status_ms": round(status_ms, 3),
            "handshake_plus_status_ms": round(handshake_ms + status_ms, 3),
            "process_total_ms": round(process_total_ms, 3),
            "sidecar_sha256": actual_hash,
            "network_listener": False,
            "offline_capable": True,
            "core_commit": status_result.get("core_commit"),
        }
    except Exception:
        try:
            process.kill()
        except Exception:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--warmup-count", type=int, default=1)
    parser.add_argument("--measured-count", type=int, default=7)
    args = parser.parse_args()

    require(args.warmup_count >= 1, "warmup-count must be at least 1")
    require(args.measured_count >= 5, "measured-count must be at least 5")

    core = Path(args.core).resolve()
    manifest = Path(args.manifest).resolve()
    require(core.is_file(), f"atlas-core not found: {core}")
    require(manifest.is_file(), f"atlas-core manifest not found: {manifest}")

    expected_hash = manifest.read_text(encoding="ascii").strip().split()[0].lower()
    require(len(expected_hash) == 64 and all(ch in "0123456789abcdef" for ch in expected_hash), "invalid atlas-core SHA-256 manifest")
    require(sha256_file(core) == expected_hash, "atlas-core SHA-256 manifest mismatch")

    cold = invoke_sample(core, expected_hash, "cold-first-post-build", 0)
    for index in range(1, args.warmup_count + 1):
        invoke_sample(core, expected_hash, "warmup", index)
    samples = [
        invoke_sample(core, expected_hash, "measured-warm", index)
        for index in range(1, args.measured_count + 1)
    ]

    handshake_values = [float(item["handshake_ms"]) for item in samples]
    status_values = [float(item["status_ms"]) for item in samples]
    combined_values = [float(item["handshake_plus_status_ms"]) for item in samples]
    process_values = [float(item["process_total_ms"]) for item in samples]

    document = {
        "evidence_version": 1,
        "phase": "5.6.2",
        "gate": "G-D9-footprint-startup-and-ipc-measurements",
        "measurement_scope": "common-identical-sidecar-stdio-ipc",
        "cold_start_definition": "first atlas-core process launch after fresh exact-head build/staging in this CI job; OS page cache is not forcibly purged",
        "warm_start_definition": "new atlas-core process launches measured after one or more warmup launches on the same runner/job",
        "sidecar_sha256": expected_hash,
        "core_commit": cold.get("core_commit"),
        "warmup_count": args.warmup_count,
        "measured_count": args.measured_count,
        "cold_first_post_build": cold,
        "measured_samples": samples,
        "handshake_ms_median": round(statistics.median(handshake_values), 3),
        "handshake_ms_p95": round(percentile_nearest_rank(handshake_values, 0.95), 3),
        "status_ms_median": round(statistics.median(status_values), 3),
        "status_ms_p95": round(percentile_nearest_rank(status_values, 0.95), 3),
        "handshake_plus_status_ms_median": round(statistics.median(combined_values), 3),
        "handshake_plus_status_ms_p95": round(percentile_nearest_rank(combined_values, 0.95), 3),
        "process_total_ms_median": round(statistics.median(process_values), 3),
        "process_total_ms_p95": round(percentile_nearest_rank(process_values, 0.95), 3),
        "selection_authorized": False,
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
