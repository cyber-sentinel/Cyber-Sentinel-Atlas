#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

NORMALIZER_ID = "atlas:normalizer:atlas.ingestion:microsoft-sysmon-schema"
NORMALIZER_VERSION = "1.0.0"
CANONICAL_SCHEMA_VERSION = "1.0.0"
INGESTION_CONTRACT_VERSION = "1.0.0"


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


def _lineage(output_record_id: str, psr: dict, profile: dict) -> dict:
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
        "parsed_record_ids": [psr["parsed_record_id"]],
        "source_snapshot_ids": [psr["source_snapshot_id"]],
        "mapping_rule_ids": [
            "sysmon-schema.current-schema-filter",
            "sysmon-schema.numeric-event-identity",
            "sysmon-schema.provider-channel-scope",
            "sysmon-schema.event-structure",
            "sysmon-schema.lifecycle-not-inferred",
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
    if mapping_profile.get("namespace") != "microsoft.sysmon":
        raise ValueError("mapping profile namespace mismatch")
    if mapping_profile.get("lifecycle_rule", {}).get("schema_inventory_observation") != "do-not-set-global-lifecycle":
        raise ValueError("schema inventory normalizer must not infer global lifecycle")

    current_schema = mapping_profile.get("current_schema_version")
    if not isinstance(current_schema, str) or not current_schema:
        raise ValueError("mapping profile lacks current_schema_version")

    records: list[dict] = []
    lineage: list[dict] = []
    quarantined: list[dict] = []
    diagnostics: list[str] = []
    seen_numeric_ids: set[int] = set()
    identity_outcomes = {"CREATE": 0, "MATCH": 0, "AMBIGUOUS": 0}

    for psr in sorted(psr_records, key=lambda record: record.get("parsed_record_id", "")):
        if psr.get("source_id") != mapping_profile.get("source_id"):
            raise ValueError("PSR source_id does not match pinned Sysmon schema source")
        if psr.get("psr_version") != "1.0.0":
            raise ValueError("unsupported PSR version")
        if psr.get("native_type") != "sysmon-schema-event":
            diagnostics.append(f"{psr.get('native_key')}: unsupported native type preserved outside canonical output")
            continue

        native = psr.get("native_fields", {})
        if native.get("schema_version") != current_schema:
            continue
        if native.get("provider") != mapping_profile["provider"]:
            raise ValueError("current Sysmon schema provider mismatch")
        if native.get("channel") != mapping_profile["channel"]:
            raise ValueError("current Sysmon schema channel mismatch")

        event_id = native.get("event_id")
        numeric_id = native.get("event_id_numeric_value")
        if not isinstance(event_id, str) or not event_id:
            identity_outcomes["AMBIGUOUS"] += 1
            quarantined.append({
                "parsed_record_id": psr.get("parsed_record_id"),
                "native_key": psr.get("native_key"),
                "reason": "missing-event-id",
            })
            continue
        if not isinstance(numeric_id, int) or numeric_id < 0:
            identity_outcomes["AMBIGUOUS"] += 1
            quarantined.append({
                "parsed_record_id": psr.get("parsed_record_id"),
                "native_key": psr.get("native_key"),
                "reason": "missing-or-invalid-numeric-event-id",
            })
            continue
        if numeric_id in seen_numeric_ids:
            raise ValueError(f"duplicate current-schema Sysmon numeric Event ID {numeric_id}")
        seen_numeric_ids.add(numeric_id)

        canonical_key = str(numeric_id)
        entity_id = f"atlas:event:microsoft.sysmon:{canonical_key}"
        title = native.get("template") or native.get("rule_name") or native.get("event_name") or f"Sysmon Event {canonical_key}"
        if not isinstance(title, str) or not title.strip():
            title = f"Sysmon Event {canonical_key}"

        fields = copy.deepcopy(native.get("fields", []))
        entity = {
            "schema_version": CANONICAL_SCHEMA_VERSION,
            "record_kind": "entity",
            "id": entity_id,
            "record_revision": 1,
            "created_at": retrieved_at,
            "updated_at": retrieved_at,
            "curation_status": "draft",
            "entity_type": "event",
            "namespace": "microsoft.sysmon",
            "canonical_key": canonical_key,
            "title": title.strip(),
            "native_identifiers": [
                {
                    "type": "event_id",
                    "value": event_id,
                    "namespace": "microsoft.sysmon",
                    "context": {
                        "provider": mapping_profile["provider"],
                        "channel": mapping_profile["channel"],
                        "product": mapping_profile["product"],
                        "platform": mapping_profile["platform"],
                        "sysmon_version": mapping_profile["sysmon_version"],
                        "schema_version": current_schema,
                    },
                    "case_sensitive": False,
                    "primary": True,
                    "components": {
                        "numeric_event_id": numeric_id,
                        "schema_inventory_status": "observed",
                        "binary_version": native.get("binary_version"),
                        "event_version": native.get("event_version"),
                        "event_name": native.get("event_name"),
                        "level": native.get("level"),
                        "template": native.get("template"),
                        "rule_name": native.get("rule_name"),
                        "rule_default": native.get("rule_default"),
                        "fields": fields,
                        "source_version": source_version,
                    },
                }
            ],
        }
        records.append(entity)
        lineage.append(_lineage(entity_id, psr, mapping_profile))
        identity_outcomes["CREATE"] += 1

    records.sort(key=lambda record: int(record["canonical_key"]))
    lineage.sort(key=lambda record: record["output_record_id"])
    diagnostics.append(
        f"Only pinned current Sysmon schema {current_schema} is normalized into current acceptance identity shells; historical schema PSR remains preserved separately."
    )
    diagnostics.append(
        "Schema inventory observation creates structural identity metadata only; global lifecycle remains unset pending explicit lifecycle evidence/policy."
    )
    return {
        "records": records,
        "lineage": lineage,
        "identity_outcomes": identity_outcomes,
        "quarantined": quarantined,
        "diagnostics": diagnostics,
        "candidate_digest": sha256_digest(records),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Normalize current Sysmon schema PSR into canonical Event identity shells.")
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
