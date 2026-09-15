#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import subprocess
import time
from pathlib import Path

MAX_RESPONSE = 8 * 1024 * 1024


def command_version(argv: list[str]) -> str:
    completed = subprocess.run(argv, check=True, capture_output=True, text=True, timeout=20)
    text = (completed.stdout or completed.stderr).strip()
    if not text:
        raise RuntimeError(f"no version output from {argv!r}")
    return text.splitlines()[0].strip()


def frame(payload: dict) -> bytes:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return struct.pack(">I", len(raw)) + raw


def parse_frames(data: bytes) -> list[dict]:
    frames: list[dict] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise RuntimeError("truncated response frame prefix")
        (length,) = struct.unpack(">I", data[offset : offset + 4])
        offset += 4
        if length <= 0 or length > MAX_RESPONSE:
            raise RuntimeError(f"invalid response frame length: {length}")
        end = offset + length
        if end > len(data):
            raise RuntimeError("truncated response payload")
        frames.append(json.loads(data[offset:end].decode("utf-8")))
        offset = end
    return frames


def minimal_child_env() -> dict[str, str]:
    keep = (
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
    return {key: os.environ[key] for key in keep if key in os.environ}


def run_core_probe(core: Path) -> dict:
    if not core.is_file():
        raise FileNotFoundError(core)

    nonce = "phase56-bootstrap-nonce"
    requests = [
        {
            "id": "phase56-handshake",
            "method": "core.handshake",
            "params": {
                "protocol": "atlas-core",
                "version": "1.0.0",
                "client_name": "atlas-desktop-spike",
                "client_version": "0.1.0-dev",
                "session_nonce": nonce,
            },
        },
        {
            "id": "phase56-status",
            "method": "core.status",
            "params": {},
        },
    ]
    wire = b"".join(frame(item) for item in requests)

    started = time.perf_counter()
    proc = subprocess.Popen(
        [str(core), "--serve-stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=minimal_child_env(),
    )
    try:
        stdout, stderr = proc.communicate(input=wire, timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise RuntimeError("atlas-core stdio probe timed out")
    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)

    if proc.returncode != 0:
        diagnostic = stderr.decode("utf-8", errors="replace")[:2000]
        raise RuntimeError(f"atlas-core exited {proc.returncode}: {diagnostic}")

    responses = parse_frames(stdout)
    if len(responses) != 2:
        raise RuntimeError(f"expected 2 protocol responses, received {len(responses)}")

    by_id = {item.get("id"): item for item in responses}
    handshake = by_id.get("phase56-handshake")
    status = by_id.get("phase56-status")
    if not handshake or handshake.get("ok") is not True:
        raise RuntimeError(f"handshake failed: {handshake!r}")
    if not status or status.get("ok") is not True:
        raise RuntimeError(f"core.status failed: {status!r}")

    handshake_result = handshake.get("result")
    if not isinstance(handshake_result, dict):
        raise RuntimeError("handshake result is not an object")
    if handshake_result.get("protocol") != "atlas-core":
        raise RuntimeError(f"unexpected protocol: {handshake_result.get('protocol')!r}")
    if handshake_result.get("version") != "1.0.0":
        raise RuntimeError(f"unexpected protocol version: {handshake_result.get('version')!r}")
    if handshake_result.get("session_nonce") != nonce:
        raise RuntimeError("session nonce mismatch")

    core_bytes = core.read_bytes()
    return {
        "binary_name": core.name,
        "binary_size_bytes": len(core_bytes),
        "binary_sha256": hashlib.sha256(core_bytes).hexdigest(),
        "process_exit_code": proc.returncode,
        "round_trip_ms": elapsed_ms,
        "response_count": len(responses),
        "handshake": {
            "protocol": handshake_result.get("protocol"),
            "version": handshake_result.get("version"),
            "session_nonce_echoed": True,
            "capabilities": handshake_result.get("capabilities", []),
        },
        "status_result": status.get("result"),
        "stderr_bytes": len(stderr),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--atlas-core", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    evidence = {
        "phase": "5.6",
        "slice": "5.6.0",
        "runner_os": os.environ.get("RUNNER_OS", os.name),
        "toolchains": {
            "python": command_version(["python", "--version"]),
            "go": command_version(["go", "version"]),
            "node": command_version(["node", "--version"]),
            "npm": command_version(["npm", "--version"]),
            "rustc": command_version(["rustc", "--version"]),
            "cargo": command_version(["cargo", "--version"]),
            "dotnet": command_version(["dotnet", "--version"]),
        },
        "core_probe": run_core_probe(Path(args.atlas_core)),
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
