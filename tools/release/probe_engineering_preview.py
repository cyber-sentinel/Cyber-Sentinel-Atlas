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
ROOT = Path(__file__).resolve().parents[2]
APPROVED_EXEMPLARS = ROOT / "content" / "encyclopedia" / "approved-exemplars.json"


def approved_windows_event_ids() -> list[str]:
    data = json.loads(APPROVED_EXEMPLARS.read_text(encoding="utf-8"))
    if data.get("status") != "MAINTAINER_APPROVED_PRODUCTION_EXEMPLARS" or not isinstance(data.get("events"), list):
        raise RuntimeError("Windows Security exemplar blueprint is not approved or is malformed")
    event_ids = [
        item["native_event_id"]
        for item in data["events"]
        if item.get("namespace") == "microsoft.windows.security"
    ]
    # Do not cap the aggregate preview set at the Security-Auditing provider
    # denominator. That frozen 423-ID denominator applies only to the
    # Microsoft-Windows-Security-Auditing family, while approved Windows
    # Security exemplars may include independently governed identities outside
    # that family. The aggregate probe remains fail-closed on type, decimal
    # identity, and uniqueness.
    if (not event_ids
            or any(not isinstance(event_id, str) or not event_id.isdecimal() for event_id in event_ids)
            or len(event_ids) != len(set(event_ids))):
        raise RuntimeError("approved Windows Security exemplar IDs are invalid or duplicated")
    return sorted(event_ids, key=int)


EXPECTED_SYSMON = "atlas:event:microsoft.sysmon:1"
EXPECTED_SYSMON_3 = "atlas:event:microsoft.sysmon:3"
EXPECTED_SEARCH_CONTRACT = "1.0.0"


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


def search_contains_target(result: Any, target_id: str) -> bool:
    if not isinstance(result, dict):
        return False
    if result.get("search_contract_version") != EXPECTED_SEARCH_CONTRACT:
        return False
    matches = result.get("matches")
    if not isinstance(matches, list):
        return False
    return any(
        isinstance(match, dict) and match.get("target_id") == target_id
        for match in matches
    )


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

        windows_security_results: dict[str, dict[str, bool]] = {}
        windows_security_event_ids = approved_windows_event_ids()
        if not windows_security_event_ids:
            raise RuntimeError("approved Windows Security exemplar set is unexpectedly empty")
        for index, event_id in enumerate(windows_security_event_ids):
            target_id = f"atlas:event:microsoft.windows.security:{event_id}"
            search_result = request(
                process.stdin,
                process.stdout,
                f"qw{index}",
                "search.query",
                {"query": event_id, "graph_depth": 1, "limit": 10},
            )
            search_ok = search_contains_target(search_result, target_id)
            if not search_ok:
                raise RuntimeError(
                    f"Windows Event {event_id} was not returned by deterministic search: {search_result}"
                )
            record = request(
                process.stdin,
                process.stdout,
                f"rw{index}",
                "record.get",
                {"id": target_id},
            )
            record_ok = isinstance(record, dict) and record.get("id") == target_id
            if not record_ok:
                raise RuntimeError(f"Windows Event {event_id} record identity mismatch")
            windows_security_results[event_id] = {
                "search_ok": search_ok,
                "record_ok": record_ok,
            }
        windows_security_exemplars_all_ok = all(
            item["search_ok"] and item["record_ok"]
            for item in windows_security_results.values()
        )

        search_sysmon = request(
            process.stdin,
            process.stdout,
            "q2",
            "search.query",
            {"query": "Sysmon 1", "graph_depth": 1, "limit": 10},
        )
        sysmon_1_search_ok = search_contains_target(search_sysmon, EXPECTED_SYSMON)
        if not sysmon_1_search_ok:
            raise RuntimeError(
                f"Sysmon Event 1 was not returned by deterministic search: {search_sysmon}"
            )

        search_processcreate = request(
            process.stdin,
            process.stdout,
            "q2a",
            "search.query",
            {"query": "ProcessCreate", "graph_depth": 1, "limit": 10},
        )
        sysmon_1_processcreate_alias_ok = search_contains_target(
            search_processcreate, EXPECTED_SYSMON
        )
        if not sysmon_1_processcreate_alias_ok:
            raise RuntimeError(
                "Sysmon Event 1 ProcessCreate alias was not returned by "
                f"deterministic search: {search_processcreate}"
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
        sysmon_1_record_aliases = {
            str(item.get("value", "")).casefold()
            for item in record_sysmon.get("aliases", [])
            if isinstance(item, dict)
        }
        sysmon_1_record_processcreate_alias_ok = "processcreate" in sysmon_1_record_aliases
        if not sysmon_1_record_processcreate_alias_ok:
            raise RuntimeError(
                f"Sysmon Event 1 canonical record is missing ProcessCreate alias: {record_sysmon}"
            )

        search_sysmon_3 = request(
            process.stdin,
            process.stdout,
            "q4",
            "search.query",
            {"query": "Sysmon 3", "graph_depth": 1, "limit": 10},
        )
        sysmon_3_search_ok = search_contains_target(search_sysmon_3, EXPECTED_SYSMON_3)
        if not sysmon_3_search_ok:
            raise RuntimeError(
                f"Sysmon Event 3 was not returned by deterministic search: {search_sysmon_3}"
            )
        record_sysmon_3 = request(
            process.stdin,
            process.stdout,
            "r4",
            "record.get",
            {"id": EXPECTED_SYSMON_3},
        )
        if record_sysmon_3.get("id") != EXPECTED_SYSMON_3:
            raise RuntimeError("Sysmon Event 3 record identity mismatch")

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
            "windows_security_exemplar_event_ids": windows_security_event_ids,
            "windows_security_exemplars": windows_security_results,
            "windows_security_exemplars_all_ok": windows_security_exemplars_all_ok,
            "sysmon_1_search_ok": sysmon_1_search_ok,
            "sysmon_1_processcreate_alias_ok": sysmon_1_processcreate_alias_ok,
            "sysmon_1_record_processcreate_alias_ok": sysmon_1_record_processcreate_alias_ok,
            "sysmon_1_record_ok": True,
            "sysmon_3_search_ok": sysmon_3_search_ok,
            "sysmon_3_record_ok": True,
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
