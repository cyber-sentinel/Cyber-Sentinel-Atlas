#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

PARSER_ID = "atlas:parser:atlas.ingestion:microsoft-sysmon-markdown"
PARSER_VERSION = "1.0.0"
PSR_VERSION = "1.0.0"

RELEASE_RE = re.compile(r"^#\s+Sysmon\s+v(?P<version>[0-9]+(?:\.[0-9]+)*)\s*$", re.I)
EVENT_RE = re.compile(r"^###\s+Event\s+ID\s+(?P<event_id>[0-9]+):\s*(?P<title>.+?)\s*$", re.I)
FRONTMATTER_DATE_RE = re.compile(r"^ms\.date:\s*(?P<date>[^\s]+)\s*$", re.I)


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


def parse_markdown(
    text: str,
    *,
    source_id: str,
    source_snapshot_id: str,
    parser_id: str = PARSER_ID,
    parser_version: str = PARSER_VERSION,
    psr_version: str = PSR_VERSION,
) -> list[dict]:
    lines = text.splitlines()
    release_versions: list[str] = []
    document_dates: list[str] = []
    headings: list[tuple[int, str, str, str]] = []

    for line_no, line in enumerate(lines, 1):
        release = RELEASE_RE.match(line)
        if release:
            release_versions.append(release.group("version"))
        date_match = FRONTMATTER_DATE_RE.match(line)
        if date_match:
            document_dates.append(date_match.group("date"))
        event = EVENT_RE.match(line)
        if event:
            headings.append((line_no, event.group("event_id"), event.group("title").strip(), line.strip()))

    releases = sorted(set(release_versions))
    dates = sorted(set(document_dates))
    if len(releases) != 1:
        raise ValueError(f"expected exactly one Sysmon release heading, found {releases!r}")
    if len(dates) != 1:
        raise ValueError(f"expected exactly one Sysmon ms.date frontmatter value, found {dates!r}")
    if not headings:
        raise ValueError("no Sysmon Event ID headings found")

    seen_ids: set[str] = set()
    records: list[dict] = []
    for line_no, event_id, title, raw_heading in headings:
        if event_id in seen_ids:
            raise ValueError(f"duplicate Sysmon Event ID heading: {event_id}")
        seen_ids.add(event_id)

        native_key = f"event-id:{event_id}"
        native_identifiers = [
            {"type": "event_id", "value": event_id, "namespace": "microsoft.sysmon"}
        ]
        native_fields = {
            "event_id": event_id,
            "title": title,
            "document_release_version": releases[0],
            "document_date": dates[0],
            "heading": raw_heading,
        }
        locator = {
            "line_range": f"L{line_no}-L{line_no}",
            "section": "Events",
            "source_key": f"Event ID {event_id}",
        }
        record_payload = {
            "native_type": "sysmon-event-heading",
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
                "parser_id": parser_id,
                "parser_version": parser_version,
                "psr_version": psr_version,
                "native_type": "sysmon-event-heading",
                "native_key": native_key,
                "record_digest": record_digest,
            },
        )
        records.append(
            {
                "psr_version": psr_version,
                "parsed_record_id": parsed_record_id,
                "source_id": source_id,
                "source_snapshot_id": source_snapshot_id,
                "parser_id": parser_id,
                "parser_version": parser_version,
                "native_type": "sysmon-event-heading",
                "native_key": native_key,
                "native_identifiers": native_identifiers,
                "native_fields": native_fields,
                "unknown_fields": {},
                "locator": locator,
                "record_digest": record_digest,
                "diagnostics": [
                    "Structured heading extraction only; explanatory Markdown prose remains in the immutable RawSnapshot and is not copied into PSR."
                ],
            }
        )

    return sorted(records, key=lambda r: (int(r["native_fields"]["event_id"]), r["parsed_record_id"]))


def parse_bytes(raw: bytes, *, source_id: str, source_snapshot_id: str) -> list[dict]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Sysmon Markdown input must be UTF-8") from exc
    return parse_markdown(text, source_id=source_id, source_snapshot_id=source_snapshot_id)


def representation_digest(records: list[dict]) -> str:
    rows = sorted(
        ({"parsed_record_id": r["parsed_record_id"], "record_digest": r["record_digest"]} for r in records),
        key=lambda r: r["parsed_record_id"],
    )
    return sha256_digest(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse pinned Microsoft Sysmon Markdown into source-native PSR event-heading records.")
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
