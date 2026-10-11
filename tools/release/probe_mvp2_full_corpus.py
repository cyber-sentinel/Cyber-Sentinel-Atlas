#!/usr/bin/env python3
"""Corpus-wide fail-closed acceptance for the ATLAS MVP-2 packaged runtime.

This probe is deliberately end-to-end: it talks to the packaged atlas-core over
its production stdio protocol and verifies that every approved Windows Security,
Sysmon, and frozen PowerShell Operational knowledge record can be found, opened
with detail=true, and projected with the exact governed field dictionary.
"""
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
APPROVED = ROOT / "content" / "encyclopedia" / "approved-exemplars.json"
POWERSHELL_BATCH_GLOB = "powershell-operational-26100-batch*.json"
SEARCH_CONTRACT = "1.0.0"
DETAIL_CONTRACT = "1.0.0"


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


def request(stdin: BinaryIO, stdout: BinaryIO, request_id: str, method: str, params: dict[str, Any]) -> Any:
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


def _powershell_events() -> list[dict[str, Any]]:
    directory = ROOT / "content" / "encyclopedia"
    paths = sorted(directory.glob(POWERSHELL_BATCH_GLOB), key=lambda p: p.name)
    if len(paths) != 8:
        raise RuntimeError(f"PowerShell batch count drift: expected 8, got {len(paths)}")
    events: list[dict[str, Any]] = []
    for index, path in enumerate(paths, start=1):
        batch = json.loads(path.read_text(encoding="utf-8"))
        if batch.get("status") != "MAINTAINER_APPROVED_POWERSHELL_OPERATIONAL_26100":
            raise RuntimeError(f"unapproved PowerShell batch: {path.name}")
        if batch.get("batch_index") != index:
            raise RuntimeError(f"PowerShell batch ordering drift: {path.name}")
        events.extend(batch.get("events") or [])
    ids = [str(item.get("native_event_id", "")) for item in events]
    if len(events) != 43 or len(set(ids)) != 43:
        raise RuntimeError(f"PowerShell denominator drift: events={len(events)}, unique={len(set(ids))}")
    if sum(len(item.get("fields") or []) for item in events) != 71:
        raise RuntimeError("PowerShell field denominator drift: expected 71")
    return sorted(events, key=lambda item: int(item["native_event_id"]))


def approved_events() -> list[dict[str, Any]]:
    data = json.loads(APPROVED.read_text(encoding="utf-8"))
    if data.get("status") != "MAINTAINER_APPROVED_PRODUCTION_EXEMPLARS":
        raise RuntimeError("approved exemplar corpus is not in the maintainer-approved state")
    events = [
        item for item in data.get("events", [])
        if item.get("namespace") in {"microsoft.windows.security", "microsoft.sysmon"}
    ]
    if not events:
        raise RuntimeError("approved Windows/Sysmon event corpus is empty")
    windows = [item for item in events if item.get("namespace") == "microsoft.windows.security"]
    sysmon = [item for item in events if item.get("namespace") == "microsoft.sysmon"]
    if len(windows) != 429:
        raise RuntimeError(f"approved Windows Security aggregate drift: expected 429, got {len(windows)}")
    if len(sysmon) != 30:
        raise RuntimeError(f"approved Sysmon denominator drift: expected 30, got {len(sysmon)}")
    powershell = _powershell_events()
    combined = [*events, *powershell]
    ids = [item.get("id") for item in combined]
    if len(combined) != 502 or len(set(ids)) != 502:
        raise RuntimeError(f"MVP-2 event aggregate drift: total={len(combined)}, unique={len(set(ids))}")
    return combined


def target_in_search(result: Any, target_id: str) -> bool:
    if not isinstance(result, dict) or result.get("search_contract_version") != SEARCH_CONTRACT:
        return False
    matches = result.get("matches")
    return isinstance(matches, list) and any(
        isinstance(item, dict) and item.get("target_id") == target_id for item in matches
    )


def claim_value(claim: dict[str, Any]) -> Any:
    obj = claim.get("object")
    return obj.get("value") if isinstance(obj, dict) else None


def verify_detail(event: dict[str, Any], detail: Any) -> dict[str, Any]:
    target_id = str(event["id"])
    if not isinstance(detail, dict) or detail.get("detail_version") != DETAIL_CONTRACT:
        raise RuntimeError(f"{target_id}: detail projection contract missing/mismatched")
    record = detail.get("record")
    if not isinstance(record, dict) or record.get("id") != target_id:
        raise RuntimeError(f"{target_id}: canonical record identity mismatch")

    title = event.get("title")
    if not isinstance(title, str) or not title.strip():
        raise RuntimeError(f"{target_id}: approved title missing")
    overview = event.get("overview")
    if not isinstance(overview, dict) or not isinstance(overview.get("summary"), str) or not overview["summary"].strip():
        raise RuntimeError(f"{target_id}: approved analyst overview summary missing")

    expected_fields = event.get("fields")
    if not isinstance(expected_fields, list):
        raise RuntimeError(f"{target_id}: approved field dictionary is not a list")
    projected_fields = detail.get("fields")
    if not isinstance(projected_fields, list):
        raise RuntimeError(f"{target_id}: runtime fields projection missing")
    if len(projected_fields) != len(expected_fields):
        raise RuntimeError(
            f"{target_id}: field projection mismatch; expected {len(expected_fields)}, got {len(projected_fields)}"
        )

    claims = detail.get("claims")
    if not isinstance(claims, list):
        raise RuntimeError(f"{target_id}: runtime claims projection missing")
    overview_claims = [
        item for item in claims
        if isinstance(item, dict)
        and item.get("subject_id") == target_id
        and item.get("predicate") == "telemetry.represents"
    ]
    if len(overview_claims) != 1 or not isinstance(claim_value(overview_claims[0]), dict):
        raise RuntimeError(f"{target_id}: telemetry.represents overview projection missing/ambiguous")

    field_ids = {
        item.get("id") for item in projected_fields
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    field_semantics = [
        item for item in claims
        if isinstance(item, dict)
        and item.get("predicate") == "telemetry.field-semantics"
        and item.get("subject_id") in field_ids
    ]
    if len(field_semantics) != len(expected_fields):
        raise RuntimeError(
            f"{target_id}: field semantics mismatch; expected {len(expected_fields)}, got {len(field_semantics)}"
        )

    sources = detail.get("sources")
    if not isinstance(sources, list):
        raise RuntimeError(f"{target_id}: source projection missing")
    if event.get("source_id") and not any(
        isinstance(item, dict) and item.get("id") == event.get("source_id") for item in sources
    ):
        raise RuntimeError(f"{target_id}: primary source is not projected into record detail")

    return {
        "field_count": len(projected_fields),
        "claim_count": len(claims),
        "source_count": len(sources),
        "overview_ok": True,
        "fields_ok": True,
        "sources_ok": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    core = args.core.resolve()
    if not core.is_file():
        raise SystemExit(f"atlas-core executable not found: {core}")

    env = {
        key: os.environ[key]
        for key in (
            "PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
            "USERPROFILE", "LOCALAPPDATA", "APPDATA", "ATLAS_RUNTIME_CHANNEL",
        )
        if key in os.environ
    }
    process = subprocess.Popen(
        [str(core), "--serve-stdio"],
        cwd=str(core.parent),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None

    events = approved_events()
    evidence: dict[str, Any] = {
        "probe": "mvp2-full-corpus",
        "windows_security": {},
        "sysmon": {},
        "powershell_operational": {},
    }
    try:
        request(
            process.stdin,
            process.stdout,
            "h",
            "core.handshake",
            {
                "protocol": "atlas-core",
                "version": "1.0.0",
                "client_name": "atlas-mvp2-full-corpus-probe",
                "client_version": "1.1.0",
                "session_nonce": "atlas-mvp2-full-corpus",
            },
        )
        status = request(process.stdin, process.stdout, "status", "pack.status", {})
        if not isinstance(status, dict) or status.get("ready") is not True or status.get("state") != "read_model_ready":
            raise RuntimeError(f"active pack is not ready: {status}")

        for index, event in enumerate(events):
            target_id = str(event["id"])
            event_id = str(event["native_event_id"])
            namespace = str(event["namespace"])
            if namespace == "microsoft.sysmon":
                query = f"Sysmon {event_id}"
                bucket = "sysmon"
            elif namespace == "microsoft.windows.powershell":
                query = f"PowerShell {event_id}"
                bucket = "powershell_operational"
            else:
                query = event_id
                bucket = "windows_security"
            search = request(
                process.stdin,
                process.stdout,
                f"q{index}",
                "search.query",
                {"query": query, "graph_depth": 1, "limit": 50},
            )
            if not target_in_search(search, target_id):
                raise RuntimeError(f"{target_id}: not discoverable by analyst query {query!r}")
            detail = request(
                process.stdin,
                process.stdout,
                f"r{index}",
                "record.get",
                {"id": target_id, "detail": True},
            )
            result = verify_detail(event, detail)
            result["query"] = query
            result["search_ok"] = True
            evidence[bucket][event_id] = result

        evidence["summary"] = {
            "windows_security_records": len(evidence["windows_security"]),
            "sysmon_records": len(evidence["sysmon"]),
            "powershell_operational_records": len(evidence["powershell_operational"]),
            "total_records": len(events),
            "all_searchable": True,
            "all_detail_resolvable": True,
            "all_field_projections_exact": True,
            "all_overviews_present": True,
            "all_primary_sources_projected": True,
        }
        expected_summary = (429, 30, 43, 502)
        actual_summary = (
            evidence["summary"]["windows_security_records"],
            evidence["summary"]["sysmon_records"],
            evidence["summary"]["powershell_operational_records"],
            evidence["summary"]["total_records"],
        )
        if actual_summary != expected_summary:
            raise RuntimeError(f"MVP-2 summary drift: expected {expected_summary}, got {actual_summary}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    finally:
        try:
            process.stdin.close()
        except Exception:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    stderr = process.stderr.read().decode("utf-8", errors="replace")
    if process.returncode not in (0, None):
        raise RuntimeError(f"atlas-core exited {process.returncode}: {stderr[:2000]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
