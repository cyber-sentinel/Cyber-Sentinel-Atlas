#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from pathlib import Path

NORMALIZER_ID = "atlas:normalizer:atlas.ingestion:mitre-d3fend"
NORMALIZER_VERSION = "1.0.0"
CANONICAL_SCHEMA_VERSION = "1.0.0"
INGESTION_CONTRACT_VERSION = "1.0.0"
D3FEND_ID_RE = re.compile(r"^D3-[A-Z0-9]+$")


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


def _d3fend_id(psr: dict) -> str | None:
    values = sorted({
        item.get("value") for item in psr.get("native_identifiers", [])
        if item.get("type") == "d3fend_id" and isinstance(item.get("value"), str)
    })
    return values[0] if len(values) == 1 else None


def _evidence_locator(psr: dict) -> dict:
    locator = psr.get("locator", {})
    if isinstance(locator.get("json_pointer"), str):
        return {"json_pointer": locator["json_pointer"]}
    if isinstance(locator.get("line_range"), str):
        return {"line_range": locator["line_range"]}
    if isinstance(locator.get("section"), str):
        return {"section": locator["section"]}
    if isinstance(locator.get("source_key"), str):
        return {"other": locator["source_key"]}
    return {"other": psr.get("native_key", "D3FEND source record")}


def _lineage(output_record_id: str, psr: dict, profile: dict, rules: list[str]) -> dict:
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
        "mapping_rule_ids": rules,
    }
    digest = sha256_digest(body)
    return {**body, "lineage_id": f"atlas:normalization-lineage:atlas.ingestion:{digest}", "lineage_digest": digest}


def _claim(subject_id: str, predicate: str, value: str, psr: dict, source_version: str, retrieved_at: str) -> dict:
    obj = {"kind": "literal", "datatype": "string", "value": value}
    semantic = {"subject_id": subject_id, "predicate": predicate, "object": obj}
    key = sha256_digest(semantic)
    return {
        "schema_version": CANONICAL_SCHEMA_VERSION,
        "record_kind": "claim",
        "id": f"atlas:claim:atlas.claim:{key}",
        "record_revision": 1,
        "created_at": retrieved_at,
        "updated_at": retrieved_at,
        "curation_status": "draft",
        "namespace": "atlas.claim",
        "canonical_key": key,
        "subject_id": subject_id,
        "predicate": predicate,
        "object": obj,
        "confidence": "high",
        "evidence": [{
            "source_id": psr["source_id"],
            "source_snapshot_id": psr["source_snapshot_id"],
            "source_version": source_version,
            "retrieved_at": retrieved_at,
            "locator": _evidence_locator(psr),
            "transformation_type": "direct-structured-import",
            "reviewer_status": "unreviewed",
        }],
    }


def normalize_psr(psr_records: list[dict], *, mapping_profile: dict, source_version: str, retrieved_at: str) -> dict:
    if mapping_profile.get("profile_digest") != mapping_profile_digest(mapping_profile):
        raise ValueError("mapping profile digest mismatch")
    if mapping_profile.get("normalizer_id") != NORMALIZER_ID or mapping_profile.get("normalizer_version") != NORMALIZER_VERSION:
        raise ValueError("mapping profile normalizer binding mismatch")
    if mapping_profile.get("source_version") != source_version:
        raise ValueError("mapping profile source_version mismatch")
    if mapping_profile.get("canonical_schema_version") != CANONICAL_SCHEMA_VERSION:
        raise ValueError("mapping profile canonical schema mismatch")

    records, lineage, quarantined, diagnostics = [], [], [], []
    identity_outcomes = {"CREATE": 0, "MATCH": 0, "AMBIGUOUS": 0}
    seen = set()
    for psr in sorted(psr_records, key=lambda row: row["parsed_record_id"]):
        if psr.get("source_id") != mapping_profile.get("source_id"):
            raise ValueError("PSR source_id does not match mapping profile")
        if psr.get("native_type") != "d3fend-defensive-technique":
            diagnostics.append(f"{psr.get('native_key')}: native type outside D3FEND canonical scope")
            continue
        identifier = _d3fend_id(psr)
        native = psr.get("native_fields", {})
        label = native.get("label")
        if not identifier or not D3FEND_ID_RE.fullmatch(identifier) or not isinstance(label, str) or not label.strip():
            identity_outcomes["AMBIGUOUS"] += 1
            quarantined.append({"parsed_record_id": psr.get("parsed_record_id"), "reason": "missing-or-invalid-d3fend-identity"})
            continue
        entity_id = f"atlas:defensive-technique:mitre.d3fend:{identifier.lower()}"
        if entity_id in seen:
            identity_outcomes["AMBIGUOUS"] += 1
            quarantined.append({"parsed_record_id": psr.get("parsed_record_id"), "reason": "canonical-identity-collision"})
            continue
        seen.add(entity_id)
        entity = {
            "schema_version": CANONICAL_SCHEMA_VERSION,
            "record_kind": "entity",
            "id": entity_id,
            "record_revision": 1,
            "created_at": retrieved_at,
            "updated_at": retrieved_at,
            "curation_status": "draft",
            "entity_type": "defensive-technique",
            "namespace": "mitre.d3fend",
            "canonical_key": identifier.lower(),
            "title": label.strip(),
            "native_identifiers": [{
                "type": "d3fend_id", "value": identifier, "namespace": "mitre.d3fend",
                "case_sensitive": True, "primary": True,
                "components": {"source_version": source_version, "iri": native.get("iri")},
            }],
        }
        records.append(entity)
        lineage.append(_lineage(entity_id, psr, mapping_profile, ["d3fend.identity"]))
        identity_outcomes["CREATE"] += 1
        definition = native.get("definition")
        if isinstance(definition, str) and definition.strip():
            claim = _claim(entity_id, mapping_profile["definition_claim_predicate"], definition.strip(), psr, source_version, retrieved_at)
            records.append(claim)
            lineage.append(_lineage(claim["id"], psr, mapping_profile, ["d3fend.definition-claim"]))
        if psr.get("unknown_fields"):
            diagnostics.append(f"{identifier}: unknown ontology predicates preserved for drift review")

    records.sort(key=lambda row: row["id"])
    lineage.sort(key=lambda row: row["output_record_id"])
    return {"records": records, "lineage": lineage, "identity_outcomes": identity_outcomes, "quarantined": quarantined, "diagnostics": diagnostics, "candidate_digest": sha256_digest(records)}


def main() -> int:
    ap = argparse.ArgumentParser(description="Normalize D3FEND PSR into Atlas canonical candidates.")
    ap.add_argument("psr", type=Path)
    ap.add_argument("--mapping-profile", type=Path, required=True)
    ap.add_argument("--source-version", required=True)
    ap.add_argument("--retrieved-at", required=True)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    psr = json.loads(args.psr.read_text(encoding="utf-8"))
    profile = json.loads(args.mapping_profile.read_text(encoding="utf-8"))
    result = normalize_psr(psr["records"], mapping_profile=profile, source_version=args.source_version, retrieved_at=args.retrieved_at)
    rendered = json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    if args.output: args.output.write_text(rendered, encoding="utf-8")
    else: print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
