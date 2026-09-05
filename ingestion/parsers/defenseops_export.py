#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

PARSER_ID = "atlas:parser:atlas.ingestion:defenseops-export"
PARSER_VERSION = "1.0.0"
PSR_VERSION = "1.0.0"
MAX_INPUT_BYTES = 8 * 1024 * 1024
EXPECTED_REPOSITORY = "cyber-sentinel/Cyber-Sentinel-DefenseOps"


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_digest(value) -> str:
    if isinstance(value, bytes):
        payload = value
    elif isinstance(value, str):
        payload = value.encode("utf-8")
    else:
        payload = canonical_json(value).encode("utf-8")
    return "sha256-" + hashlib.sha256(payload).hexdigest()


def stable_artifact_id(kind: str, payload) -> str:
    return f"atlas:{kind}:atlas.ingestion:{sha256_digest(payload)}"


def export_digest(document: dict) -> str:
    body = copy.deepcopy(document)
    body.pop("export_digest", None)
    return sha256_digest(body)


def parse_bytes(
    raw: bytes,
    *,
    source_id: str,
    source_snapshot_id: str,
    expected_commit_sha: str | None = None,
) -> list[dict]:
    if not raw:
        raise ValueError("DefenseOps export input is empty")
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(f"DefenseOps export exceeds {MAX_INPUT_BYTES} bytes")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid DefenseOps export JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("DefenseOps export root must be an object")
    if document.get("repository") != EXPECTED_REPOSITORY:
        raise ValueError("DefenseOps export repository mismatch")
    commit_sha = document.get("commit_sha")
    if not isinstance(commit_sha, str) or len(commit_sha) != 40 or any(ch not in "0123456789abcdef" for ch in commit_sha):
        raise ValueError("DefenseOps export commit_sha is malformed")
    if expected_commit_sha is not None and commit_sha != expected_commit_sha:
        raise ValueError("DefenseOps export commit does not match pinned source profile")
    if document.get("export_digest") != export_digest(document):
        raise ValueError("DefenseOps export digest mismatch")
    records = document.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError("DefenseOps export must contain records")

    output: list[dict] = []
    seen_content_ids: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(f"DefenseOps records[{index}] must be an object")
        content_id = record.get("content_id")
        content_type = record.get("content_type")
        if not isinstance(content_id, str) or not content_id:
            raise ValueError(f"DefenseOps records[{index}] missing content_id")
        if content_id in seen_content_ids:
            raise ValueError(f"duplicate DefenseOps content_id: {content_id}")
        seen_content_ids.add(content_id)
        if content_type not in {"detection", "hunt", "engineering", "response"}:
            raise ValueError(f"{content_id}: unsupported content_type")
        validation = record.get("validation")
        if not isinstance(validation, dict) or validation.get("review_status") not in {"unreviewed", "reviewed", "validated", "rejected"}:
            raise ValueError(f"{content_id}: invalid validation metadata")
        license_metadata = record.get("license")
        if not isinstance(license_metadata, dict) or license_metadata.get("status") not in {"verified", "restricted", "unknown"}:
            raise ValueError(f"{content_id}: license metadata missing or invalid")
        if not isinstance(record.get("source_refs"), list) or not record["source_refs"]:
            raise ValueError(f"{content_id}: source_refs are required")
        if not isinstance(record.get("telemetry_requirements"), list) or not record["telemetry_requirements"]:
            raise ValueError(f"{content_id}: telemetry_requirements are required")

        native_key = content_id
        native_identifiers = [{"type": "defenseops_content_id", "value": content_id, "namespace": "cyber-sentinel.defenseops"}]
        native_fields = copy.deepcopy(record)
        native_fields["repository"] = document["repository"]
        native_fields["commit_sha"] = commit_sha
        native_fields["release_version"] = document.get("release_version")
        locator = {"json_pointer": f"/records/{index}", "source_key": content_id}
        record_payload = {
            "native_type": f"defenseops-{content_type}",
            "native_key": native_key,
            "native_identifiers": native_identifiers,
            "native_fields": native_fields,
            "unknown_fields": {},
            "locator": locator,
        }
        record_digest = sha256_digest(record_payload)
        parsed_record_id = stable_artifact_id(
            "parsed-source-record",
            {
                "source_snapshot_id": source_snapshot_id,
                "parser_id": PARSER_ID,
                "parser_version": PARSER_VERSION,
                "psr_version": PSR_VERSION,
                "native_type": f"defenseops-{content_type}",
                "native_key": native_key,
                "record_digest": record_digest,
            },
        )
        diagnostics = []
        if validation.get("review_status") != "validated":
            diagnostics.append("DefenseOps content is not validated and cannot be promotion-eligible")
        if license_metadata.get("status") != "verified":
            diagnostics.append("DefenseOps content license is not verified; G14 publication must fail closed")
        output.append({
            "psr_version": PSR_VERSION,
            "parsed_record_id": parsed_record_id,
            "source_id": source_id,
            "source_snapshot_id": source_snapshot_id,
            "parser_id": PARSER_ID,
            "parser_version": PARSER_VERSION,
            "native_type": f"defenseops-{content_type}",
            "native_key": native_key,
            "native_identifiers": native_identifiers,
            "native_fields": native_fields,
            "unknown_fields": {},
            "locator": locator,
            "record_digest": record_digest,
            "diagnostics": diagnostics,
        })
    return sorted(output, key=lambda item: item["native_key"])


def representation_digest(records: list[dict]) -> str:
    rows = sorted(
        ({"parsed_record_id": r["parsed_record_id"], "record_digest": r["record_digest"]} for r in records),
        key=lambda row: row["parsed_record_id"],
    )
    return sha256_digest(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse an explicit DefenseOps validated export into Atlas PSR.")
    ap.add_argument("input", type=Path)
    ap.add_argument("--source-id", required=True)
    ap.add_argument("--snapshot-id", required=True)
    ap.add_argument("--expected-commit-sha")
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    records = parse_bytes(
        args.input.read_bytes(),
        source_id=args.source_id,
        source_snapshot_id=args.snapshot_id,
        expected_commit_sha=args.expected_commit_sha,
    )
    payload = {"psr_version": PSR_VERSION, "representation_digest": representation_digest(records), "records": records}
    rendered = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
