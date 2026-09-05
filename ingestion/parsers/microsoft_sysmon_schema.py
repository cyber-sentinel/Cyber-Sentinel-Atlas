#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

PARSER_ID = "atlas:parser:atlas.ingestion:microsoft-sysmon-schema"
PARSER_VERSION = "1.0.0"
PSR_VERSION = "1.0.0"

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_MANIFESTS = 128
MAX_EVENTS_PER_MANIFEST = 4096
MAX_FIELDS_PER_EVENT = 4096

MANIFEST_RE = re.compile(r"<manifest\b.*?</manifest>", re.IGNORECASE | re.DOTALL)
SCHEMA_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)+$")
NUMERIC_RE = re.compile(r"^[0-9]+$")
FORBIDDEN_XML_RE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)

MANIFEST_ATTRS = {"schemaversion", "binaryversion"}
EVENT_ATTRS = {"name", "value", "level", "template", "rulename", "ruledefault", "version"}
DATA_ATTRS = {"name", "inType", "outType"}


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


def _version_key(value: str) -> tuple[int, ...]:
    if not SCHEMA_VERSION_RE.fullmatch(value):
        raise ValueError(f"invalid Sysmon schema version: {value!r}")
    return tuple(int(part) for part in value.split("."))


def _unknown_attributes(attributes: dict[str, str], known: set[str]) -> dict[str, str]:
    return {key: attributes[key] for key in sorted(set(attributes) - known)}


def _required_attr(attributes: dict[str, str], name: str, context: str) -> str:
    value = attributes.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} is missing required attribute {name!r}")
    return value


def parse_text(
    text: str,
    *,
    source_id: str,
    source_snapshot_id: str,
    parser_id: str = PARSER_ID,
    parser_version: str = PARSER_VERSION,
    psr_version: str = PSR_VERSION,
) -> list[dict]:
    if FORBIDDEN_XML_RE.search(text):
        raise ValueError("Sysmon schema export contains forbidden DTD/entity declarations")

    matches = list(MANIFEST_RE.finditer(text))
    if not matches:
        raise ValueError("Sysmon schema export contains no manifest documents")
    if len(matches) > MAX_MANIFESTS:
        raise ValueError(f"Sysmon schema export exceeds manifest limit: {len(matches)} > {MAX_MANIFESTS}")

    seen_schema_versions: set[str] = set()
    records: list[dict] = []

    for manifest_index, match in enumerate(matches):
        fragment = match.group(0)
        try:
            root = ET.fromstring(fragment)
        except ET.ParseError as exc:
            raise ValueError(f"Sysmon manifest[{manifest_index}] is malformed XML: {exc}") from exc

        if root.tag.rsplit("}", 1)[-1].lower() != "manifest":
            raise ValueError(f"Sysmon manifest[{manifest_index}] has unexpected root element {root.tag!r}")

        schema_version = _required_attr(root.attrib, "schemaversion", f"manifest[{manifest_index}]")
        _version_key(schema_version)
        if schema_version in seen_schema_versions:
            raise ValueError(f"duplicate Sysmon schema version: {schema_version}")
        seen_schema_versions.add(schema_version)

        binary_version = _required_attr(root.attrib, "binaryversion", f"manifest[{manifest_index}]")
        if not NUMERIC_RE.fullmatch(binary_version):
            raise ValueError(f"manifest[{manifest_index}] has nonnumeric binaryversion: {binary_version!r}")
        manifest_unknown = _unknown_attributes(root.attrib, MANIFEST_ATTRS)

        events_parent = root.find("./events")
        if events_parent is None:
            raise ValueError(f"Sysmon schema {schema_version} contains no events element")
        event_elements = list(events_parent.findall("./event"))
        if not event_elements:
            raise ValueError(f"Sysmon schema {schema_version} contains no event definitions")
        if len(event_elements) > MAX_EVENTS_PER_MANIFEST:
            raise ValueError(
                f"Sysmon schema {schema_version} exceeds event limit: {len(event_elements)} > {MAX_EVENTS_PER_MANIFEST}"
            )

        seen_event_ids: set[str] = set()
        for event_index, event in enumerate(event_elements):
            context = f"schema {schema_version} event[{event_index}]"
            event_id = _required_attr(event.attrib, "value", context)
            event_version = _required_attr(event.attrib, "version", context)
            event_name = _required_attr(event.attrib, "name", context)
            level = _required_attr(event.attrib, "level", context)
            template = _required_attr(event.attrib, "template", context)

            if not NUMERIC_RE.fullmatch(event_id):
                raise ValueError(f"{context} has nonnumeric event ID: {event_id!r}")
            if not NUMERIC_RE.fullmatch(event_version):
                raise ValueError(f"{context} has nonnumeric event version: {event_version!r}")
            if event_id in seen_event_ids:
                raise ValueError(f"duplicate Sysmon Event ID {event_id} within schema {schema_version}")
            seen_event_ids.add(event_id)

            data_elements = list(event.findall("./data"))
            if len(data_elements) > MAX_FIELDS_PER_EVENT:
                raise ValueError(
                    f"Sysmon schema {schema_version} Event ID {event_id} exceeds field limit: "
                    f"{len(data_elements)} > {MAX_FIELDS_PER_EVENT}"
                )

            fields: list[dict] = []
            seen_field_names: set[str] = set()
            field_unknown: dict[str, dict[str, str]] = {}
            for field_index, field in enumerate(data_elements):
                field_context = f"schema {schema_version} Event ID {event_id} field[{field_index}]"
                field_name = _required_attr(field.attrib, "name", field_context)
                if field_name in seen_field_names:
                    raise ValueError(f"duplicate field {field_name!r} in Sysmon schema {schema_version} Event ID {event_id}")
                seen_field_names.add(field_name)
                fields.append(
                    {
                        "name": field_name,
                        "in_type": field.attrib.get("inType"),
                        "out_type": field.attrib.get("outType"),
                    }
                )
                unknown = _unknown_attributes(field.attrib, DATA_ATTRS)
                if unknown:
                    field_unknown[str(field_index)] = unknown

            event_unknown = _unknown_attributes(event.attrib, EVENT_ATTRS)
            unknown_fields: dict[str, object] = {}
            if manifest_unknown:
                unknown_fields["manifest_attributes"] = manifest_unknown
            if event_unknown:
                unknown_fields["event_attributes"] = event_unknown
            if field_unknown:
                unknown_fields["field_attributes"] = field_unknown

            native_key = f"schema-version:{schema_version}:event-id:{event_id}"
            native_identifiers = [
                {
                    "type": "event_id",
                    "value": event_id,
                    "namespace": "microsoft.sysmon",
                    "context": {
                        "provider": "Microsoft-Windows-Sysmon",
                        "channel": "Microsoft-Windows-Sysmon/Operational",
                        "schema_version": schema_version,
                        "event_version": event_version,
                    },
                },
                {
                    "type": "schema_version",
                    "value": schema_version,
                    "namespace": "microsoft.sysmon",
                    "context": {"binary_version": binary_version},
                },
            ]
            native_fields = {
                "provider": "Microsoft-Windows-Sysmon",
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "schema_version": schema_version,
                "binary_version": binary_version,
                "event_id": event_id,
                "event_version": event_version,
                "event_name": event_name,
                "level": level,
                "template": template,
                "rule_name": event.attrib.get("rulename"),
                "rule_default": event.attrib.get("ruledefault"),
                "fields": fields,
            }
            locator = {
                "section": f"Sysmon schema {schema_version}",
                "source_key": f"schema-version:{schema_version}:event-id:{event_id}",
            }
            record_payload = {
                "native_type": "sysmon-schema-event",
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
                    "native_type": "sysmon-schema-event",
                    "native_key": native_key,
                    "record_digest": record_digest,
                },
            )
            diagnostics: list[str] = []
            if unknown_fields:
                diagnostics.append("Unknown structured schema attributes were preserved in PSR unknown_fields for drift review.")
            records.append(
                {
                    "psr_version": psr_version,
                    "parsed_record_id": parsed_record_id,
                    "source_id": source_id,
                    "source_snapshot_id": source_snapshot_id,
                    "parser_id": parser_id,
                    "parser_version": parser_version,
                    "native_type": "sysmon-schema-event",
                    "native_key": native_key,
                    "native_identifiers": native_identifiers,
                    "native_fields": native_fields,
                    "unknown_fields": unknown_fields,
                    "locator": locator,
                    "record_digest": record_digest,
                    "diagnostics": diagnostics,
                }
            )

    records.sort(
        key=lambda record: (
            _version_key(record["native_fields"]["schema_version"]),
            int(record["native_fields"]["event_id"]),
            int(record["native_fields"]["event_version"]),
            record["parsed_record_id"],
        )
    )
    return records


def parse_bytes(raw: bytes, *, source_id: str, source_snapshot_id: str) -> list[dict]:
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(f"Sysmon schema export exceeds input limit: {len(raw)} > {MAX_INPUT_BYTES}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Sysmon schema reference export must be normalized UTF-8") from exc
    return parse_text(text, source_id=source_id, source_snapshot_id=source_snapshot_id)


def representation_digest(records: list[dict]) -> str:
    rows = sorted(
        ({"parsed_record_id": record["parsed_record_id"], "record_digest": record["record_digest"]} for record in records),
        key=lambda row: row["parsed_record_id"],
    )
    return sha256_digest(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse a controlled Sysmon -s all reference export into source-native PSR records.")
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
