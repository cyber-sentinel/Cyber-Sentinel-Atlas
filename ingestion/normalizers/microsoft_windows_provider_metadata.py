#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

NORMALIZER_ID = "atlas:normalizer:atlas.ingestion:microsoft-windows-provider-metadata"
NORMALIZER_VERSION = "1.0.0"
CANONICAL_SCHEMA_VERSION = "1.0.0"
INGESTION_CONTRACT_VERSION = "1.0.0"
EVENT_ID_RE = re.compile(r"^[0-9]+$")
VERSION_RE = re.compile(r"^[0-9]+$")


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


def digest_without_field(record: dict, field: str) -> str:
    payload = copy.deepcopy(record)
    payload.pop(field, None)
    return sha256_digest(payload)


def mapping_profile_digest(profile: dict) -> str:
    return digest_without_field(profile, "profile_digest")


def _lineage(output_record_id: str, psr_records: list[dict], profile: dict) -> dict:
    parsed_ids = sorted({record["parsed_record_id"] for record in psr_records})
    snapshots = sorted({record["source_snapshot_id"] for record in psr_records})
    body = {
        "ingestion_contract_version": INGESTION_CONTRACT_VERSION,
        "output_record_id": output_record_id,
        "normalizer_id": NORMALIZER_ID,
        "normalizer_version": NORMALIZER_VERSION,
        "mapping_profile": {
            "id": profile["profile_id"],
            "version": profile["profile_version"],
            "digest": profile["profile_digest"],
        },
        "parsed_record_ids": parsed_ids,
        "source_snapshot_ids": snapshots,
        "mapping_rule_ids": [
            "windows-provider.event-identity",
            "windows-provider.provider-channel-scope",
            "windows-provider.observed-event-versions",
            "windows-provider.structural-template-fields",
            "windows-provider.lifecycle-not-inferred",
        ],
    }
    digest = sha256_digest(body)
    return {
        **body,
        "lineage_id": f"atlas:normalization-lineage:atlas.ingestion:{digest}",
        "lineage_digest": digest,
    }


def normalize_psr(
    psr_records: list[dict],
    *,
    mapping_profile: dict,
    source_version: str,
    retrieved_at: str,
) -> dict:
    if mapping_profile.get("profile_digest") != mapping_profile_digest(mapping_profile):
        raise ValueError("mapping profile digest mismatch")
    if mapping_profile.get("normalizer_id") != NORMALIZER_ID:
        raise ValueError("mapping profile normalizer_id mismatch")
    if mapping_profile.get("normalizer_version") != NORMALIZER_VERSION:
        raise ValueError("mapping profile normalizer_version mismatch")
    if mapping_profile.get("source_version") != source_version:
        raise ValueError("mapping profile source_version mismatch")
    if mapping_profile.get("canonical_schema_version") != CANONICAL_SCHEMA_VERSION:
        raise ValueError("mapping profile canonical_schema_version mismatch")
    if mapping_profile.get("namespace") != "microsoft.windows.security":
        raise ValueError("mapping profile namespace mismatch")
    if mapping_profile.get("lifecycle_rule", {}).get("provider_inventory_observation") != "do-not-set-global-lifecycle":
        raise ValueError("provider inventory normalizer must not infer global lifecycle")

    grouped: dict[str, list[dict]] = defaultdict(list)
    quarantined: list[dict] = []
    diagnostics: list[str] = []
    identity_outcomes = {"CREATE": 0, "MATCH": 0, "AMBIGUOUS": 0}

    for psr in sorted(psr_records, key=lambda record: record.get("parsed_record_id", "")):
        if psr.get("source_id") != mapping_profile.get("source_id"):
            raise ValueError("PSR source_id does not match pinned Windows provider source")
        if psr.get("psr_version") != "1.0.0":
            raise ValueError("unsupported PSR version")
        if psr.get("native_type") != "windows-event-provider-definition":
            diagnostics.append(f"{psr.get('native_key')}: unsupported native type preserved outside canonical output")
            continue

        native = psr.get("native_fields", {})
        event_id = native.get("event_id")
        event_version = native.get("event_version")
        provider = native.get("provider")
        channel = native.get("channel")
        if not isinstance(event_id, str) or not EVENT_ID_RE.fullmatch(event_id):
            identity_outcomes["AMBIGUOUS"] += 1
            quarantined.append({
                "parsed_record_id": psr.get("parsed_record_id"),
                "native_key": psr.get("native_key"),
                "reason": "missing-or-invalid-event-id",
            })
            continue
        if not isinstance(event_version, str) or not VERSION_RE.fullmatch(event_version):
            raise ValueError(f"Windows Event ID {event_id}: invalid event version")
        if provider != mapping_profile["provider"]:
            raise ValueError(f"Windows Event ID {event_id}: provider mismatch")
        if channel != mapping_profile["channel"]:
            raise ValueError(f"Windows Event ID {event_id}: channel mismatch")
        grouped[event_id].append(psr)

    records: list[dict] = []
    lineage: list[dict] = []
    for event_id in sorted(grouped, key=int):
        group = grouped[event_id]
        versions = sorted({record["native_fields"]["event_version"] for record in group}, key=int)
        provider_guids = sorted({record["native_fields"].get("provider_guid") for record in group})
        if len(provider_guids) != 1 or not provider_guids[0]:
            raise ValueError(f"Windows Event ID {event_id}: inconsistent provider GUID across versions")

        version_structures = []
        for record in sorted(group, key=lambda r: int(r["native_fields"]["event_version"])):
            native = record["native_fields"]
            version_structures.append({
                "event_version": native["event_version"],
                "level": copy.deepcopy(native.get("level")),
                "opcode": copy.deepcopy(native.get("opcode")),
                "task": copy.deepcopy(native.get("task")),
                "keywords": copy.deepcopy(native.get("keywords", [])),
                "template_fields": copy.deepcopy(native.get("template_fields", [])),
            })

        entity_id = f"atlas:event:microsoft.windows.security:{event_id}"
        entity = {
            "schema_version": CANONICAL_SCHEMA_VERSION,
            "record_kind": "entity",
            "id": entity_id,
            "record_revision": 1,
            "created_at": retrieved_at,
            "updated_at": retrieved_at,
            "curation_status": "draft",
            "entity_type": "event",
            "namespace": "microsoft.windows.security",
            "canonical_key": event_id,
            "title": f"Windows Security Event {event_id}",
            "native_identifiers": [
                {
                    "type": "event_id",
                    "value": event_id,
                    "namespace": "microsoft.windows.security",
                    "context": {
                        "provider": mapping_profile["provider"],
                        "channel": mapping_profile["channel"],
                        "product": mapping_profile["product"],
                        "platform": mapping_profile["platform"],
                        "windows_version": mapping_profile["windows_version"],
                        "windows_build": mapping_profile["windows_build"],
                    },
                    "case_sensitive": False,
                    "primary": True,
                    "components": {
                        "provider_guid": provider_guids[0],
                        "provider_inventory_status": "observed",
                        "observed_event_versions": versions,
                        "event_version_structures": version_structures,
                        "source_version": source_version,
                    },
                }
            ],
        }
        records.append(entity)
        lineage.append(_lineage(entity_id, group, mapping_profile))
        identity_outcomes["CREATE"] += 1

    diagnostics.append(
        "Provider inventory observation creates canonical identity shells and structural metadata only; global lifecycle remains unset pending explicit lifecycle evidence/policy."
    )
    records.sort(key=lambda record: int(record["canonical_key"]))
    lineage.sort(key=lambda record: record["output_record_id"])
    return {
        "records": records,
        "lineage": lineage,
        "identity_outcomes": identity_outcomes,
        "quarantined": quarantined,
        "diagnostics": diagnostics,
        "candidate_digest": sha256_digest(records),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Normalize controlled Windows provider-metadata PSR into canonical Event identity shells.")
    ap.add_argument("psr", type=Path)
    ap.add_argument("--mapping-profile", type=Path, required=True)
    ap.add_argument("--source-version", required=True)
    ap.add_argument("--retrieved-at", required=True)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()

    psr_doc = json.loads(args.psr.read_text(encoding="utf-8"))
    mapping = json.loads(args.mapping_profile.read_text(encoding="utf-8"))
    result = normalize_psr(
        psr_doc["records"],
        mapping_profile=mapping,
        source_version=args.source_version,
        retrieved_at=args.retrieved_at,
    )
    rendered = json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
