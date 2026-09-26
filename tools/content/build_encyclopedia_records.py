#!/usr/bin/env python3
"""Build deterministic canonical records for maintainer-approved encyclopedia exemplars.

This module is intentionally small and auditable. It converts the reviewed
content blueprint into canonical v1 Entity/Claim/Relationship/Source records.
It does not scrape external websites and it does not create unsupported
relationships or claims.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
BLUEPRINT = ROOT / "content" / "encyclopedia" / "approved-exemplars.json"
FIXED_TIME = "2026-09-18T18:20:00Z"

SOURCE_PATHS = [
    ROOT / "ingestion" / "source-profiles" / "microsoft-sysmon-docs.source.json",
    ROOT / "ingestion" / "source-profiles" / "microsoft-sysmon-schema-export.source.json",
    ROOT / "ingestion" / "source-profiles" / "microsoft-windows-provider-metadata.source.json",
    ROOT / "ingestion" / "source-profiles" / "microsoft-windows-security-auditing-4688-doc.source.json",
    ROOT / "content" / "encyclopedia" / "sources" / "microsoft-windows-security-event-4624.json",
    ROOT / "content" / "encyclopedia" / "sources" / "microsoft-windows-security-event-4625.json",
    ROOT / "content" / "encyclopedia" / "sources" / "microsoft-windows-security-event-4672.json",
    ROOT / "content" / "encyclopedia" / "sources" / "ultimate-windows-security-event-4624.json",
    ROOT / "content" / "encyclopedia" / "sources" / "ultimate-windows-security-event-4625.json",
    ROOT / "content" / "encyclopedia" / "sources" / "ultimate-windows-security-event-4672.json",
    ROOT / "content" / "encyclopedia" / "sources" / "ultimate-windows-security-event-4688.json",
]

SYSMON_SCHEMA_SOURCE = "atlas:source:atlas.source:microsoft-sysmon-schema-export"
SYSMON_SCHEMA_SOURCE_VERSION = "sysmon-15.22-schema-4.91"
WINDOWS_PROVIDER_SOURCE = "atlas:source:atlas.source:microsoft-windows-provider-metadata"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha_key(payload: Any) -> str:
    return "sha256-" + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def envelope(kind: str, rid: str, namespace: str, canonical_key: str, *, status: str = "validated") -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "record_kind": kind,
        "id": rid,
        "record_revision": 1,
        "created_at": FIXED_TIME,
        "updated_at": FIXED_TIME,
        "curation_status": status,
        "namespace": namespace,
        "canonical_key": canonical_key,
    }


def evidence(source_id: str, source_version: str, locator: str, *, transformation: str = "human-authored-synthesis") -> dict[str, Any]:
    return {
        "source_id": source_id,
        "source_version": source_version,
        "retrieved_at": FIXED_TIME,
        "locator": {"other": locator},
        "transformation_type": transformation,
        "reviewer_status": "approved",
    }


def claim(subject_id: str, predicate: str, value: Any, claim_evidence: list[dict[str, Any]], *, confidence: str = "high") -> dict[str, Any]:
    obj = {"kind": "json", "value": value} if isinstance(value, (dict, list)) else {
        "kind": "literal", "datatype": "string", "value": str(value)
    }
    semantic = {"subject_id": subject_id, "predicate": predicate, "object": obj}
    key = sha_key(semantic)
    result = envelope("claim", f"atlas:claim:atlas.claim:{key}", "atlas.claim", key)
    result.update({
        "subject_id": subject_id,
        "predicate": predicate,
        "object": obj,
        "confidence": confidence,
        "evidence": copy.deepcopy(claim_evidence),
    })
    return result


def relationship(from_id: str, to_id: str, relationship_type: str, *, confidence: str = "high", supporting: list[str] | None = None) -> dict[str, Any]:
    semantic = {"from": from_id, "relationship_type": relationship_type, "to": to_id}
    key = sha_key(semantic)
    result = envelope("relationship", f"atlas:relationship:atlas.graph:{key}", "atlas.graph", key)
    result.update({
        "from": from_id,
        "to": to_id,
        "relationship_type": relationship_type,
        "confidence": confidence,
    })
    if supporting:
        result["supporting_claim_ids"] = sorted(set(supporting))
    return result


def source_records() -> list[dict[str, Any]]:
    out = []
    for path in SOURCE_PATHS:
        value = json.loads(path.read_text(encoding="utf-8"))
        # Source identity/rights data are authoritative control records. Do not
        # mutate them here: deterministic dedupe relies on exact bytes/semantics.
        out.append(value)
    return out


def event_entity(item: dict[str, Any]) -> dict[str, Any]:
    result = envelope("entity", item["id"], item["namespace"], item["canonical_key"])
    result.update({
        "entity_type": "event",
        "title": item["title"],
        "lifecycle": {"state": item["lifecycle"]},
        "native_identifiers": [{
            "type": "event_id",
            "value": item["native_event_id"],
            "namespace": item["namespace"],
            "context": {
                "provider": item["provider"],
                "channel": item["channel"],
                "product": item["product"],
                "platform": item["platform"],
            },
            "components": {
                "content_contract": "ENCYCLOPEDIA_GRADE_EXEMPLAR",
                "semantic_source_version": item["source_version"],
            },
            "case_sensitive": False,
            "primary": True,
        }],
        "aliases": [
            {
                "value": alias,
                "kind": "provider-qualified" if alias != item["native_event_id"] else "native",
                "case_sensitive": False,
                "scope": {"namespace": item["namespace"]},
            }
            for alias in item.get("aliases", [])
        ],
    })
    return result


def field_entity(event: dict[str, Any], field: dict[str, Any]) -> dict[str, Any]:
    key = f"{event['canonical_key']}.{field['key']}"
    rid = f"atlas:field:{event['namespace']}:{key}"
    result = envelope("entity", rid, event["namespace"], key)
    result.update({
        "entity_type": "field",
        "title": f"{event['native_event_id']} — {field['section']} — {field['native_name']}",
        "lifecycle": {"state": "current"},
        "native_identifiers": [{
            "type": "field_name",
            "value": field["native_name"],
            "namespace": event["namespace"],
            "context": {
                "event_id": event["native_event_id"],
                "section": field["section"],
            },
            "components": {
                "field_key": field["key"],
                "field_type": field["type"],
            },
            "case_sensitive": True,
            "primary": True,
        }],
    })
    return result


def field_semantics(event: dict[str, Any], field: dict[str, Any], field_id: str) -> dict[str, Any]:
    value = {
        "section": field["section"],
        "native_name": field["native_name"],
        "type": field["type"],
        "meaning": field["meaning"],
    }
    for optional in ("versions", "values_ref", "values", "correlation", "notes", "provider_scope"):
        if optional in field:
            value[optional] = copy.deepcopy(field[optional])

    if event["namespace"] == "microsoft.sysmon":
        schema_locator = event.get("schema_locator")
        if not schema_locator:
            raise ValueError(f"Sysmon encyclopedia event {event['native_event_id']} is missing schema_locator")
        ev = [
            evidence(event["source_id"], event["source_version"], event["source_locator"]),
            evidence(
                SYSMON_SCHEMA_SOURCE,
                SYSMON_SCHEMA_SOURCE_VERSION,
                f"{schema_locator} / {field['native_name']}",
                transformation="normalized-fact",
            ),
        ]
        value["structural_refresh_state"] = "VALIDATED_CONTROLLED_SYSMON_15_22_SCHEMA_EXPORT"
    else:
        ev = [evidence(event["source_id"], event["source_version"], f"{event['source_locator']} / {field['section']} / {field['native_name']}")]
        if field.get("provider_scope"):
            ev.append(evidence(
                WINDOWS_PROVIDER_SOURCE,
                "windows-build-26100.33296",
                f"Event 4624 provider template / {field['native_name']}",
                transformation="normalized-fact",
            ))
    return claim(field_id, "telemetry.field-semantics", value, ev)


def event_claims(item: dict[str, Any]) -> list[dict[str, Any]]:
    base_ev = [evidence(item["source_id"], item["source_version"], item["source_locator"])]
    claims = [
        claim(item["id"], "telemetry.represents", item["overview"], base_ev),
        claim(item["id"], "telemetry.requires-policy", item["collection"], base_ev),
        claim(item["id"], "security.relevance", {
            "analysis_author": "Cyber-Sentinel ATLAS",
            "analysis": item["analysis"],
            "correlations": item["correlations"],
            "canonical_vs_generated": "ATLAS-authored defensive analysis; not a source verdict",
        }, base_ev),
        claim(
            item["id"],
            "telemetry.source",
            {"kind": "primary-semantic-authority", "source_id": item["source_id"], "url": item["source_url"]},
            base_ev,
        ),
    ]
    if item.get("value_dictionaries"):
        claims.append(claim(
            item["id"],
            "telemetry.field-semantics",
            {"event_value_dictionaries": item["value_dictionaries"]},
            base_ev,
        ))
    external = item.get("external_reference")
    if external:
        claims.append(claim(
            item["id"],
            "telemetry.source",
            {
                "kind": external["role"],
                "source_id": external["source_id"],
                "url": external["url"],
                "redistribution": external["redistribution"],
            },
            [evidence(external["source_id"], "external-reference-2026-09-18", f"Event ID {item['native_event_id']}")],
        ))
    return claims


def build_records() -> list[dict[str, Any]]:
    blueprint = json.loads(BLUEPRINT.read_text(encoding="utf-8"))
    if blueprint.get("status") != "MAINTAINER_APPROVED_PRODUCTION_EXEMPLARS":
        raise ValueError("encyclopedia exemplar blueprint is not maintainer-approved")

    records: dict[str, dict[str, Any]] = {}
    for src in source_records():
        records[src["id"]] = src

    for item in blueprint["events"]:
        event = event_entity(item)
        records[event["id"]] = event
        for c in event_claims(item):
            records[c["id"]] = c
        for field in item["fields"]:
            entity = field_entity(item, field)
            records[entity["id"]] = entity
            semantics = field_semantics(item, field, entity["id"])
            records[semantics["id"]] = semantics
            rel = relationship(item["id"], entity["id"], "HAS_FIELD")
            records[rel["id"]] = rel

    return [records[key] for key in sorted(records)]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    records = build_records()
    payload = "".join(canonical_json(record) + "\n" for record in records)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    print(f"encyclopedia_exemplar_records={len(records)}", file=__import__("sys").stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
