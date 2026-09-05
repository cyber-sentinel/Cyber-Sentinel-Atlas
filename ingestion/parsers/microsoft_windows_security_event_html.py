#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import html
from html.parser import HTMLParser
import json
import re
from pathlib import Path

PARSER_ID = "atlas:parser:atlas.ingestion:microsoft-windows-security-event-html"
PARSER_VERSION = "1.0.1"
PSR_VERSION = "1.0.0"

EVENT_HEADING_RE = re.compile(r"\b(?P<event_id>[0-9]+)\(S\):\s*(?P<title>[^\n]+?)(?:\s*\(Windows[^\n)]*\))?\s*$", re.I | re.M)
PROVIDER_RE = re.compile(r"<Provider\s+Name=[\"'](?P<value>[^\"']+)[\"']", re.I)
EVENT_ID_XML_RE = re.compile(r"<EventID>\s*(?P<value>[0-9]+)\s*</EventID>", re.I)
VERSION_XML_RE = re.compile(r"<Version>\s*(?P<value>[0-9]+)\s*</Version>", re.I)
TASK_RE = re.compile(r"<Task>\s*(?P<value>[0-9]+)\s*</Task>", re.I)
OPCODE_RE = re.compile(r"<Opcode>\s*(?P<value>[0-9]+)\s*</Opcode>", re.I)
KEYWORDS_RE = re.compile(r"<Keywords>\s*(?P<value>0x[0-9a-fA-F]+)\s*</Keywords>", re.I)
CHANNEL_RE = re.compile(r"<Channel>\s*(?P<value>[^<]+?)\s*</Channel>", re.I)
DATA_NAME_RE = re.compile(r"<Data\s+Name=[\"'](?P<value>[A-Za-z0-9_.-]+)[\"']", re.I)
SUBCATEGORY_RE = re.compile(r"\bSubcategory:\s*(?P<value>[^\n]+)", re.I)
MIN_OS_RE = re.compile(r"\bMinimum\s+OS\s+Version:\s*(?P<value>[^\n]+)", re.I)
LAST_UPDATED_RE = re.compile(r"\bLast\s+updated\s+on\s+(?P<value>[0-9]{4}-[0-9]{2}-[0-9]{2})", re.I)


class VisibleTextParser(HTMLParser):
    BLOCK_TAGS = {
        "article", "aside", "blockquote", "br", "code", "dd", "div", "dl", "dt",
        "figcaption", "figure", "footer", "h1", "h2", "h3", "h4", "h5", "h6",
        "header", "hr", "li", "main", "nav", "ol", "p", "pre", "section", "table",
        "tbody", "td", "tfoot", "th", "thead", "tr", "ul",
    }

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in {"script", "style", "svg"}:
            self.skip_depth += 1
            return
        if self.skip_depth == 0 and tag in self.BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in {"script", "style", "svg"}:
            if self.skip_depth:
                self.skip_depth -= 1
            return
        if self.skip_depth == 0 and tag in self.BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):
        if self.skip_depth == 0:
            self.parts.append(data)

    def text(self) -> str:
        raw = "".join(self.parts)
        lines = [re.sub(r"[ \t\r\f\v]+", " ", line).strip() for line in raw.splitlines()]
        return "\n".join(line for line in lines if line)


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


def _single(pattern: re.Pattern, text: str, label: str) -> str:
    values = [m.group("value").strip() for m in pattern.finditer(text)]
    unique = sorted(set(values))
    if len(unique) != 1:
        raise ValueError(f"expected one unique {label}, found {unique!r}")
    return unique[0]


def _visible_text(raw_html: str) -> str:
    parser = VisibleTextParser()
    parser.feed(raw_html)
    parser.close()
    return parser.text()


def _event_versions(visible: str) -> list[str]:
    match = re.search(r"\bEvent\s+Versions:\s*(?P<body>.*?)\bField\s+Descriptions:", visible, re.I | re.S)
    if not match:
        raise ValueError("Event Versions section not found")
    versions = re.findall(r"(?:^|\n)\s*([0-9]+)\s*-\s*", match.group("body"), re.M)
    unique = []
    for value in versions:
        if value not in unique:
            unique.append(value)
    if not unique:
        raise ValueError("no documented event versions found")
    return unique


def _event_heading(visible: str) -> tuple[str, str, int]:
    matches = list(EVENT_HEADING_RE.finditer(visible))
    headings: list[tuple[str, str]] = []
    for match in matches:
        value = (match.group("event_id"), match.group("title").strip())
        if value not in headings:
            headings.append(value)
    if len(headings) != 1:
        raise ValueError(f"expected one unique Windows Security event heading, found {headings!r}")
    event_id, title = headings[0]
    return event_id, title.rstrip("."), len(matches)


def parse_html(
    raw_html: str,
    *,
    source_id: str,
    source_snapshot_id: str,
    parser_id: str = PARSER_ID,
    parser_version: str = PARSER_VERSION,
    psr_version: str = PSR_VERSION,
) -> list[dict]:
    visible = _visible_text(raw_html)
    unescaped = html.unescape(raw_html)

    event_id, title, heading_match_count = _event_heading(visible)

    xml_event_id = _single(EVENT_ID_XML_RE, unescaped, "EventID in Event XML")
    if event_id != xml_event_id:
        raise ValueError(f"heading/XML Event ID mismatch: {event_id!r} != {xml_event_id!r}")

    provider = _single(PROVIDER_RE, unescaped, "provider")
    channel = _single(CHANNEL_RE, unescaped, "channel")
    xml_version = _single(VERSION_XML_RE, unescaped, "sample Event XML version")
    task = _single(TASK_RE, unescaped, "task")
    opcode = _single(OPCODE_RE, unescaped, "opcode")
    keywords = _single(KEYWORDS_RE, unescaped, "keywords")
    field_names = []
    for match in DATA_NAME_RE.finditer(unescaped):
        value = match.group("value")
        if value not in field_names:
            field_names.append(value)
    if not field_names:
        raise ValueError("Event XML contains no EventData field names")

    versions = _event_versions(visible)
    subcategory = _single(SUBCATEGORY_RE, visible, "audit subcategory")
    minimum_os = _single(MIN_OS_RE, visible, "minimum OS version")
    last_updated = _single(LAST_UPDATED_RE, visible, "page last-updated date")

    native_key = f"event-id:{event_id}"
    native_identifiers = [
        {
            "type": "event_id",
            "value": event_id,
            "namespace": "microsoft.windows.security",
        }
    ]
    native_fields = {
        "event_id": event_id,
        "title": title,
        "provider": provider,
        "channel": channel,
        "sample_event_xml_version": xml_version,
        "documented_event_versions": versions,
        "task": task,
        "opcode": opcode,
        "keywords": keywords,
        "event_data_fields": field_names,
        "audit_subcategory": subcategory,
        "minimum_os_version": minimum_os.rstrip("."),
        "page_last_updated": last_updated,
    }
    locator = {
        "section": "Event documentation",
        "source_key": f"Event ID {event_id}",
    }
    record_payload = {
        "native_type": "windows-security-event-documentation",
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
            "native_type": "windows-security-event-documentation",
            "native_key": native_key,
            "record_digest": record_digest,
        },
    )
    diagnostics = [
        "Parser extracts source-native structural facts only; explanatory Microsoft Learn prose remains in the immutable RawSnapshot and is not copied into PSR."
    ]
    if heading_match_count > 1:
        diagnostics.append(
            f"Microsoft Learn rendered {heading_match_count} identical Event {event_id} headings; parser deduplicated identical headings after verifying a single unique identity/title."
        )
    return [
        {
            "psr_version": psr_version,
            "parsed_record_id": parsed_record_id,
            "source_id": source_id,
            "source_snapshot_id": source_snapshot_id,
            "parser_id": parser_id,
            "parser_version": parser_version,
            "native_type": "windows-security-event-documentation",
            "native_key": native_key,
            "native_identifiers": native_identifiers,
            "native_fields": native_fields,
            "unknown_fields": {},
            "locator": locator,
            "record_digest": record_digest,
            "diagnostics": diagnostics,
        }
    ]


def parse_bytes(raw: bytes, *, source_id: str, source_snapshot_id: str) -> list[dict]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Windows Security event HTML input must be UTF-8") from exc
    return parse_html(text, source_id=source_id, source_snapshot_id=source_snapshot_id)


def representation_digest(records: list[dict]) -> str:
    rows = sorted(
        ({"parsed_record_id": r["parsed_record_id"], "record_digest": r["record_digest"]} for r in records),
        key=lambda r: r["parsed_record_id"],
    )
    return sha256_digest(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse Microsoft Learn Windows Security event HTML into source-native PSR.")
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
