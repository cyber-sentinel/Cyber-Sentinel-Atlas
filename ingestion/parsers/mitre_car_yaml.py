#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

import yaml

PARSER_ID = "atlas:parser:atlas.ingestion:mitre-car-yaml"
PARSER_VERSION = "1.0.0"
PSR_VERSION = "1.0.0"
MAX_INPUT_BYTES = 2 * 1024 * 1024
CAR_ID_RE = re.compile(r"^CAR-[0-9]{4}-[0-9]{2}-[0-9]{3}$")
KNOWN_FIELDS = {
    "title", "submission_date", "information_domain", "platforms", "subtypes",
    "analytic_types", "contributors", "id", "description", "coverage",
    "implementations", "data_model_references", "true_positives", "d3fend_mappings",
}


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


def json_safe(value):
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError(f"unsupported YAML scalar type: {type(value).__name__}")


def parse_bytes(raw: bytes, *, source_id: str, source_snapshot_id: str) -> list[dict]:
    if not raw:
        raise ValueError("CAR YAML input is empty")
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(f"CAR YAML input exceeds {MAX_INPUT_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("CAR YAML input must be UTF-8") from exc
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid CAR YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("CAR YAML root must be a mapping")
    document = json_safe(document)

    car_id = document.get("id")
    title = document.get("title")
    if not isinstance(car_id, str) or not CAR_ID_RE.fullmatch(car_id):
        raise ValueError("CAR analytic id is missing or malformed")
    if not isinstance(title, str) or not title.strip():
        raise ValueError(f"{car_id}: title is missing")

    known = {key: document[key] for key in document if key in KNOWN_FIELDS}
    unknown = {key: document[key] for key in document if key not in KNOWN_FIELDS}
    native_identifiers = [{"type": "car_id", "value": car_id, "namespace": "mitre.car"}]
    locator = {"source_key": car_id}
    record_payload = {
        "native_type": "mitre-car-analytic",
        "native_key": car_id,
        "native_identifiers": native_identifiers,
        "native_fields": known,
        "unknown_fields": unknown,
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
            "native_type": "mitre-car-analytic",
            "native_key": car_id,
            "record_digest": record_digest,
        },
    )
    diagnostics = []
    if unknown:
        diagnostics.append("unknown structured YAML keys preserved: " + ", ".join(sorted(unknown)))
    return [{
        "psr_version": PSR_VERSION,
        "parsed_record_id": parsed_record_id,
        "source_id": source_id,
        "source_snapshot_id": source_snapshot_id,
        "parser_id": PARSER_ID,
        "parser_version": PARSER_VERSION,
        "native_type": "mitre-car-analytic",
        "native_key": car_id,
        "native_identifiers": native_identifiers,
        "native_fields": known,
        "unknown_fields": unknown,
        "locator": locator,
        "record_digest": record_digest,
        "diagnostics": diagnostics,
    }]


def representation_digest(records: list[dict]) -> str:
    rows = sorted(
        ({"parsed_record_id": r["parsed_record_id"], "record_digest": r["record_digest"]} for r in records),
        key=lambda row: row["parsed_record_id"],
    )
    return sha256_digest(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse a pinned MITRE CAR YAML analytic into Atlas PSR.")
    ap.add_argument("input", type=Path)
    ap.add_argument("--source-id", required=True)
    ap.add_argument("--snapshot-id", required=True)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    records = parse_bytes(args.input.read_bytes(), source_id=args.source_id, source_snapshot_id=args.snapshot_id)
    payload = {"psr_version": PSR_VERSION, "representation_digest": representation_digest(records), "records": records}
    rendered = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
