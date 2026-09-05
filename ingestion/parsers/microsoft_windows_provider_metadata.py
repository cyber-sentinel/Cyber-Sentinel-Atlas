#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

PARSER_ID = "atlas:parser:atlas.ingestion:microsoft-windows-provider-metadata"
PARSER_VERSION = "1.0.0"
PSR_VERSION = "1.0.0"
EXPORT_FORMAT_VERSION = "1.0.0"
EVENT_ID_RE = re.compile(r"^[0-9]+$")
VERSION_RE = re.compile(r"^[0-9]+$")

TOP_LEVEL_FIELDS = {
    "export_format_version",
    "provider",
    "provider_guid",
    "log_links",
    "events",
    "structural_only",
    "descriptions_included",
}
EVENT_FIELDS = {
    "event_id",
    "version",
    "log_name",
    "level",
    "opcode",
    "task",
    "keywords",
    "template",
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


def _template_fields(template: str | None) -> list[str]:
    if template is None or not template.strip():
        return []
    try:
        root = ET.fromstring(template)
    except ET.ParseError as exc:
        raise ValueError(f"event template XML is malformed: {exc}") from exc
    fields: list[str] = []
    for element in root.iter():
        local = element.tag.rsplit("}", 1)[-1].lower()
        if local != "data":
            continue
        name = element.attrib.get("name")
        if isinstance(name, str) and name and name not in fields:
            fields.append(name)
    return fields


def _named_value(value, label: str):
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object or null")
    allowed = {"value", "name", "displayName", "display_name"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"{label} contains unsupported structural fields: {unknown!r}")
    normalized = {}
    if value.get("value") is not None:
        normalized["value"] = str(value["value"])
    if value.get("name") is not None:
        normalized["name"] = str(value["name"])
    display = value.get("display_name", value.get("displayName"))
    if display is not None:
        normalized["display_name"] = str(display)
    return normalized


def parse_document(
    document: dict,
    *,
    source_id: str,
    source_snapshot_id: str,
    parser_id: str = PARSER_ID,
    parser_version: str = PARSER_VERSION,
    psr_version: str = PSR_VERSION,
) -> list[dict]:
    if not isinstance(document, dict):
        raise ValueError("Windows provider reference export must be a JSON object")
    if document.get("export_format_version") != EXPORT_FORMAT_VERSION:
        raise ValueError("unsupported Windows provider reference-export format version")
    provider = document.get("provider")
    provider_guid = document.get("provider_guid")
    if not isinstance(provider, str) or not provider:
        raise ValueError("Windows provider reference export is missing provider")
    if not isinstance(provider_guid, str) or not provider_guid:
        raise ValueError("Windows provider reference export is missing provider_guid")
    if document.get("structural_only") is not True:
        raise ValueError("Windows provider reference export must declare structural_only=true")
    if document.get("descriptions_included") is not False:
        raise ValueError("Windows provider reference export must not embed localized event descriptions")
    events = document.get("events")
    if not isinstance(events, list) or not events:
        raise ValueError("Windows provider reference export contains no events")

    export_unknown = {key: document[key] for key in sorted(set(document) - TOP_LEVEL_FIELDS)}
    records: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"event[{index}] is not an object")
        event_id = str(event.get("event_id", ""))
        version = str(event.get("version", ""))
        channel = event.get("log_name")
        if not EVENT_ID_RE.fullmatch(event_id):
            raise ValueError(f"event[{index}] has invalid numeric event_id: {event_id!r}")
        if not VERSION_RE.fullmatch(version):
            raise ValueError(f"event[{index}] has invalid numeric version: {version!r}")
        if not isinstance(channel, str) or not channel:
            raise ValueError(f"event[{index}] is missing log_name/channel")

        identity = (event_id, version, channel)
        if identity in seen:
            raise ValueError(f"duplicate provider event/version/channel identity: {identity!r}")
        seen.add(identity)

        template = event.get("template")
        if template is not None and not isinstance(template, str):
            raise ValueError(f"event[{index}].template must be a string or null")
        template_fields = _template_fields(template)
        keywords = event.get("keywords", [])
        if not isinstance(keywords, list):
            raise ValueError(f"event[{index}].keywords must be an array")
        normalized_keywords = [_named_value(item, f"event[{index}].keywords") for item in keywords]
        event_unknown = {key: event[key] for key in sorted(set(event) - EVENT_FIELDS)}
        unknown_fields = {}
        if export_unknown:
            unknown_fields["export"] = export_unknown
        if event_unknown:
            unknown_fields["event"] = event_unknown

        native_key = f"event-id:{event_id}:version:{version}:channel:{channel}"
        native_identifiers = [
            {
                "type": "event_id",
                "value": event_id,
                "namespace": "microsoft.windows.security",
                "context": {
                    "provider": provider,
                    "channel": channel,
                    "event_version": version,
                },
            }
        ]
        native_fields = {
            "provider": provider,
            "provider_guid": provider_guid,
            "event_id": event_id,
            "event_version": version,
            "channel": channel,
            "level": _named_value(event.get("level"), f"event[{index}].level"),
            "opcode": _named_value(event.get("opcode"), f"event[{index}].opcode"),
            "task": _named_value(event.get("task"), f"event[{index}].task"),
            "keywords": normalized_keywords,
            "template": template,
            "template_fields": template_fields,
        }
        locator = {
            "json_pointer": f"/events/{index}",
            "source_key": f"{provider}:{event_id}:v{version}:{channel}",
        }
        record_payload = {
            "native_type": "windows-event-provider-definition",
            "native_key": native_key,
            "native_identifiers": native_identifiers,
            "native_fields": native_fields,
            "unknown_fields": unknown_fields,
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
                "native_type": "windows-event-provider-definition",
                "native_key": native_key,
                "record_digest": record_digest,
            },
        )
        diagnostics = []
        if unknown_fields:
            diagnostics.append("Unknown structured fields were preserved in PSR unknown_fields for source-drift review.")
        records.append(
            {
                "psr_version": psr_version,
                "parsed_record_id": parsed_record_id,
                "source_id": source_id,
                "source_snapshot_id": source_snapshot_id,
                "parser_id": parser_id,
                "parser_version": parser_version,
                "native_type": "windows-event-provider-definition",
                "native_key": native_key,
                "native_identifiers": native_identifiers,
                "native_fields": native_fields,
                "unknown_fields": unknown_fields,
                "locator": locator,
                "record_digest": record_digest,
                "diagnostics": diagnostics,
            }
        )

    records.sort(key=lambda r: (int(r["native_fields"]["event_id"]), int(r["native_fields"]["event_version"]), r["native_fields"]["channel"]))
    return records


def parse_bytes(raw: bytes, *, source_id: str, source_snapshot_id: str) -> list[dict]:
    try:
        document = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("Windows provider reference export must be UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Windows provider reference export is invalid JSON: {exc}") from exc
    return parse_document(document, source_id=source_id, source_snapshot_id=source_snapshot_id)


def representation_digest(records: list[dict]) -> str:
    rows = sorted(
        ({"parsed_record_id": r["parsed_record_id"], "record_digest": r["record_digest"]} for r in records),
        key=lambda r: r["parsed_record_id"],
    )
    return sha256_digest(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse a controlled Windows ProviderMetadata.Events reference export into PSR.")
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
