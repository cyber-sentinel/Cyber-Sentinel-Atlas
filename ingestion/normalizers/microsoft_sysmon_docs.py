#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from pathlib import Path

NORMALIZER_ID = "atlas:normalizer:atlas.ingestion:microsoft-sysmon-docs"
NORMALIZER_VERSION = "1.0.0"
CANONICAL_SCHEMA_VERSION = "1.0.0"
INGESTION_CONTRACT_VERSION = "1.0.0"
EVENT_ID_RE = re.compile(r"^[0-9]+$")


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


def _event_id(psr: dict) -> str | None:
    values = sorted(
        {
            item.get("value")
            for item in psr.get("native_identifiers", [])
            if item.get("type") == "event_id" and isinstance(item.get("value"), str)
        }
    )
    if len(values) != 1:
        return None
    return values[0]


def _lineage(output_record_id: str, psr: dict, profile: dict) -> dict:
    mapping_ref = {
        "id": profile["profile_id"],
        "version": profile["profile_version"],
        "digest": profile["profile_digest"],
    }
    body = {
        "ingestion_contract_version": INGESTION_CONTRACT_VERSION,
        "output_record_id": output_record_id,
        "normalizer_id": NORMALIZER_ID,
        "normalizer_version": NORMALIZER_VERSION,
        "mapping_profile": mapping_ref,
        "parsed_record_ids": [psr["parsed_record_id"]],
        "source_snapshot_ids": [psr["source_snapshot_id"]],
        "mapping_rule_ids": [
            "sysmon-docs.event-identity",
            "sysmon-docs.heading-title",
            "sysmon-docs.provider-channel-context",
            "sysmon-docs.documentation-status",
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
    if mapping_profile.get("lifecycle_rule", {}).get("documentation_only") != "unset-until-schema-or-provider-evidence":
        raise ValueError("documentation-only normalizer must not establish canonical lifecycle")

    records: list[dict] = []
    lineage: list[dict] = []
    quarantined: list[dict] = []
    diagnostics: list[str] = []
    seen_ids: set[str] = set()
    identity_outcomes = {"CREATE": 0, "MATCH": 0, "AMBIGUOUS": 0}

    for psr in sorted(psr_records, key=lambda r: r["parsed_record_id"]):
        if psr.get("source_id") != mapping_profile.get("source_id"):
            raise ValueError("PSR source_id does not match pinned Sysmon documentation source")
        if psr.get("psr_version") != "1.0.0":
            raise ValueError("unsupported PSR version")
        if psr.get("native_type") != "sysmon-event-heading":
            diagnostics.append(f"{psr.get('native_key')}: unsupported source-native type preserved outside canonical output")
            continue

        event_id = _event_id(psr)
        native = psr.get("native_fields", {})
        title = native.get("title")
        if not event_id or not EVENT_ID_RE.fullmatch(event_id):
            identity_outcomes["AMBIGUOUS"] += 1
            quarantined.append(
                {
                    "parsed_record_id": psr.get("parsed_record_id"),
                    "native_key": psr.get("native_key"),
                    "reason": "missing-or-invalid-unique-event-id",
                }
            )
            continue
        if not isinstance(title, str) or not title.strip():
            identity_outcomes["AMBIGUOUS"] += 1
            quarantined.append(
                {
                    "parsed_record_id": psr.get("parsed_record_id"),
                    "native_key": psr.get("native_key"),
                    "reason": "missing-event-heading-title",
                }
            )
            continue
        if native.get("document_release_version") != source_version:
            raise ValueError(f"Sysmon Event ID {event_id}: PSR document release does not match pinned source version")

        entity_id = f"atlas:event:microsoft.sysmon:{event_id}"
        if entity_id in seen_ids:
            identity_outcomes["AMBIGUOUS"] += 1
            quarantined.append(
                {
                    "parsed_record_id": psr["parsed_record_id"],
                    "native_key": psr.get("native_key"),
                    "reason": "canonical-identity-collision",
                }
            )
            continue
        seen_ids.add(entity_id)

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
            "canonical_key": event_id,
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
                    },
                    "case_sensitive": False,
                    "primary": True,
                    "components": {
                        "documentation_status": "documented",
                        "documentation_release_version": source_version,
                        "documentation_date": native.get("document_date"),
                    },
                }
            ],
        }
        records.append(entity)
        lineage.append(_lineage(entity_id, psr, mapping_profile))
        identity_outcomes["CREATE"] += 1

    records = sorted(records, key=lambda r: (int(r["canonical_key"]), r["id"]))
    lineage = sorted(lineage, key=lambda r: r["output_record_id"])
    diagnostics.append(
        "Canonical lifecycle intentionally remains unset: documentation listing is tracked independently from Sysmon schema/provider evidence."
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
    ap = argparse.ArgumentParser(description="Normalize Sysmon documentation PSR into canonical event candidates.")
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
