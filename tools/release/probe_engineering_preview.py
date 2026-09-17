#!/usr/bin/env python3
"""Fail-closed stdio acceptance probe for the packaged engineering preview."""
from __future__ import annotations

import argparse
import json
import os
import struct
import subprocess
from pathlib import Path
from typing import Any, BinaryIO

MAX_FRAME = 8 * 1024 * 1024
EXPECTED_EVENT = "atlas:event:microsoft.windows.security:4688"
EXPECTED_SYSMON = "atlas:event:microsoft.sysmon:1"


def write_frame(stream: BinaryIO, value: dict[str, Any]) -> None:
    body = json.dumps(value, separators=(",", ":")).encode("utf-8")
    if not body or len(body) > MAX_FRAME:
        raise RuntimeError("request frame exceeds probe bound")
    stream.write(struct.pack(">I", len(body)))
    stream.write(body)
    stream.flush()


def read_exact(stream: BinaryIO, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = stream.read(length - len(data))
        if not chunk:
            raise RuntimeError("unexpected EOF from atlas-core")
        data.extend(chunk)
    return bytes(data)


def read_frame(stream: BinaryIO) -> dict[str, Any]:
    length = struct.unpack(">I", read_exact(stream, 4))[0]
    if length < 1 or length > MAX_FRAME:
        raise RuntimeError(f"invalid response frame length: {length}")
    return json.loads(read_exact(stream, length))


def request(
    stdin: BinaryIO,
    stdout: BinaryIO,
    request_id: str,
    method: str,
    params: dict[str, Any],
) -> Any:
    write_frame(stdin, {"id": request_id, "method": method, "params": params})
    response = read_frame(stdout)
    if response.get("id") != request_id:
        raise RuntimeError(f"response id mismatch for {method}")
    if response.get("ok") is not True:
        error = response.get("error") or {}
        raise RuntimeError(
            f"{method} failed: {error.get('code', 'UNKNOWN')}: {error.get('message', '')}"
        )
    return response.get("result")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    core = args.core.resolve()
    if not core.is_file():
        raise SystemExit(f"atlas-core executable not found: {core}")

    env_allow = {
        key: os.environ[key]
        for key in (
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
        if key in os.environ
    }
    process = subprocess.Popen(
        [str(core), "--serve-stdio"],
        cwd=str(core.parent),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env_allow,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None

    evidence: dict[str, Any] = {}
    try:
        handshake = request(
            process.stdin,
            process.stdout,
            "h",
            "core.handshake",
            {
                "protocol": "atlas-core",
                "version": "1.0.0",
                "client_name": "phase5105-packaged-data-probe",
                "client_version": "1.0.0",
                "session_nonce": "phase5105-clean-machine",
            },
        )
        status = request(process.stdin, process.stdout, "p", "pack.status", {})
        if status.get("ready") is not True or status.get("state") != "read_model_ready":
            raise RuntimeError(f"engineering preview pack is not active: {status}")

        search_4688 = request(
            process.stdin,
            process.stdout,
            "q1",
            "search.query",
            {"query": "4688", "graph_depth": 1, "limit": 10},
        )
        record_4688 = request(
            process.stdin,
            process.stdout,
            "r1",
            "record.get",
            {"id": EXPECTED_EVENT},
        )
        if record_4688.get("id") != EXPECTED_EVENT:
            raise RuntimeError("Windows Event 4688 record identity mismatch")

        search_sysmon = request(
            process.stdin,
            process.stdout,
            "q2",
            "search.query",
            {"query": "Sysmon 1", "graph_depth": 1, "limit": 10},
        )
        record_sysmon = request(
            process.stdin,
            process.stdout,
            "r2",
            "record.get",
            {"id": EXPECTED_SYSMON},
        )
        if record_sysmon.get("id") != EXPECTED_SYSMON:
            raise RuntimeError("Sysmon Event 1 record identity mismatch")

        graph = request(
            process.stdin,
            process.stdout,
            "g",
            "graph.expand",
            {
                "seed_ids": ["atlas:activity:synthetic.graph:a"],
                "depth": 2,
                "direction": "both",
                "limit": 100,
            },
        )
        if not isinstance(graph.get("pivots"), list):
            raise RuntimeError("graph response lacks bounded pivots")

        evidence = {
            "schema_version": "1.0.0",
            "handshake_protocol": handshake.get("protocol"),
            "core_version": handshake.get("core_version"),
            "core_commit": handshake.get("core_commit"),
            "pack_ready": status.get("ready"),
            "pack_id": status.get("pack_id"),
            "pack_version": status.get("pack_version"),
            "generation_id": status.get("generation_id"),
            "windows_4688_search_ok": search_4688 is not None,
            "windows_4688_record_ok": True,
            "sysmon_1_search_ok": search_sysmon is not None,
            "sysmon_1_record_ok": True,
            "graph_expand_ok": True,
        }
    finally:
        process.stdin.close()
        return_code = process.wait(timeout=15)
        stderr = process.stderr.read().decode("utf-8", errors="replace")
        if return_code != 0:
            raise RuntimeError(f"atlas-core exited {return_code}: {stderr[:2000]}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
