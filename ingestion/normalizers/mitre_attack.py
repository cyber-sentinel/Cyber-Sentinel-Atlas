#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from pathlib import Path

NORMALIZER_ID = "atlas:normalizer:atlas.ingestion:mitre-attack-enterprise"
NORMALIZER_VERSION = "1.0.0"
CANONICAL_SCHEMA_VERSION = "1.0.0"
INGESTION_CONTRACT_VERSION = "1.0.0"
ATTACK_ID_RE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")


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


def sha_key(payload) -> str:
    return sha256_digest(payload)


def digest_without_field(record: dict, field: str) -> str:
    payload = copy.deepcopy(record)
    payload.pop(field, None)
    return sha256_digest(payload)


def mapping_profile_digest(profile: dict) -> str:
    return digest_without_field(profile, "profile_digest")


def _attack_id(psr: dict) -> str | None:
    values = [
        n.get("value") for n in psr.get("native_identifiers", [])
        if n.get("type") == "attack_id" and isinstance(n.get("value"), str)
    ]
    values = sorted(set(values))
    if len(values) != 1:
        return None
    return values[0]


def _lifecycle(native: dict) -> tuple[dict | None, list[str]]:
    diagnostics: list[str] = []
    revoked_present = "revoked" in native
    deprecated_present = "x_mitre_deprecated" in native
    revoked = native.get("revoked")
    deprecated = native.get("x_mitre_deprecated")
    if revoked_present and revoked is True:
        return {"state": "retired"}, diagnostics
    if deprecated_present and deprecated is True:
        return {"state": "deprecated"}, diagnostics
    if revoked_present and deprecated_present and revoked is False and deprecated is False:
        return {"state": "current"}, diagnostics
    diagnostics.append("ATT&CK lifecycle flags incomplete; lifecycle state not inferred")
    return None, diagnostics


def _claim_semantic_payload(subject_id: str, predicate: str, obj: dict) -> dict:
    return {"subject_id": subject_id, "predicate": predicate, "object": obj}


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
    expected_profile_digest = mapping_profile_digest(mapping_profile)
    if mapping_profile.get("profile_digest") != expected_profile_digest:
        raise ValueError("mapping profile digest mismatch")
    if mapping_profile.get("normalizer_id") != NORMALIZER_ID:
        raise ValueError("mapping profile normalizer_id mismatch")
    if mapping_profile.get("normalizer_version") != NORMALIZER_VERSION:
        raise ValueError("mapping profile normalizer_version mismatch")
    if mapping_profile.get("source_version") != source_version:
        raise ValueError("mapping profile source_version mismatch")
    if mapping_profile.get("canonical_schema_version") != CANONICAL_SCHEMA_VERSION:
        raise ValueError("mapping profile canonical_schema_version mismatch")
    if mapping_profile.get("domain") != "enterprise-attack":
        raise ValueError("mapping profile domain mismatch")

    records: list[dict] = []
    lineage: list[dict] = []
    quarantined: list[dict] = []
    diagnostics: list[str] = []
    seen_ids: set[str] = set()
    identity_outcomes = {"CREATE": 0, "MATCH": 0, "AMBIGUOUS": 0}

    for psr in sorted(psr_records, key=lambda r: r["parsed_record_id"]):
        if psr.get("source_id") != mapping_profile.get("source_id"):
            raise ValueError("PSR source_id does not match pinned mapping profile source")
        if psr.get("psr_version") != "1.0.0":
            raise ValueError("unsupported PSR version")
        if psr.get("native_type") != "attack-pattern":
            diagnostics.append(f"{psr.get('native_key')}: source-native type preserved but outside 5.3.2 canonical canary scope")
            continue
        attack_id = _attack_id(psr)
        native = psr.get("native_fields", {})
        if not attack_id or not ATTACK_ID_RE.fullmatch(attack_id):
            identity_outcomes["AMBIGUOUS"] += 1
            quarantined.append({
                "parsed_record_id": psr.get("parsed_record_id"),
                "native_key": psr.get("native_key"),
                "reason": "missing-or-invalid-unique-mitre-attack-id",
            })
            continue
        if not isinstance(native.get("name"), str) or not native["name"].strip():
            identity_outcomes["AMBIGUOUS"] += 1
            quarantined.append({
                "parsed_record_id": psr["parsed_record_id"],
                "native_key": psr.get("native_key"),
                "reason": "missing-technique-name",
            })
            continue

        key = attack_id.lower()
        entity_id = f"atlas:attack-technique:mitre.attack:{key}"
        if entity_id in seen_ids:
            identity_outcomes["AMBIGUOUS"] += 1
            quarantined.append({
                "parsed_record_id": psr["parsed_record_id"],
                "native_key": psr.get("native_key"),
                "reason": "canonical-identity-collision",
            })
            continue
        seen_ids.add(entity_id)

        created_at = native.get("created") if isinstance(native.get("created"), str) else retrieved_at
        updated_at = native.get("modified") if isinstance(native.get("modified"), str) else created_at
        lifecycle, life_diags = _lifecycle(native)
        diagnostics.extend(f"{attack_id}: {d}" for d in life_diags)

        components = {"stix_id": psr["native_key"], "source_version": source_version}
        if isinstance(native.get("x_mitre_version"), str):
            components["object_version"] = native["x_mitre_version"]
        if isinstance(native.get("x_mitre_is_subtechnique"), bool):
            components["is_subtechnique"] = native["x_mitre_is_subtechnique"]

        entity = {
            "schema_version": CANONICAL_SCHEMA_VERSION,
            "record_kind": "entity",
            "id": entity_id,
            "record_revision": 1,
            "created_at": created_at,
            "updated_at": updated_at,
            "curation_status": "draft",
            "entity_type": "attack-technique",
            "namespace": "mitre.attack",
            "canonical_key": key,
            "title": native["name"].strip(),
            "native_identifiers": [{
                "type": "attack_id",
                "value": attack_id,
                "namespace": "mitre.attack",
                "context": {"domain": mapping_profile["domain"]},
                "case_sensitive": False,
                "primary": True,
                "components": components,
            }],
        }
        if lifecycle is not None:
            entity["lifecycle"] = lifecycle
        records.append(entity)
        identity_outcomes["CREATE"] += 1
        lineage.append(_lineage(entity_id, psr, mapping_profile, ["attack-pattern.identity", "attack-pattern.lifecycle"]))

        description = native.get("description")
        if isinstance(description, str) and description.strip():
            obj = {"kind": "literal", "datatype": "string", "value": description.strip()}
            semantic = _claim_semantic_payload(entity_id, "behavior.description", obj)
            claim_key = sha_key(semantic)
            claim_id = f"atlas:claim:atlas.claim:{claim_key}"
            claim = {
                "schema_version": CANONICAL_SCHEMA_VERSION,
                "record_kind": "claim",
                "id": claim_id,
                "record_revision": 1,
                "created_at": created_at,
                "updated_at": updated_at,
                "curation_status": "draft",
                "namespace": "atlas.claim",
                "canonical_key": claim_key,
                "subject_id": entity_id,
                "predicate": "behavior.description",
                "object": obj,
                "confidence": "high",
                "evidence": [{
                    "source_id": psr["source_id"],
                    "source_snapshot_id": psr["source_snapshot_id"],
                    "source_version": source_version,
                    "retrieved_at": retrieved_at,
                    "locator": copy.deepcopy(psr["locator"]),
                    "transformation_type": "direct-structured-import",
                    "reviewer_status": "unreviewed",
                }],
            }
            records.append(claim)
            lineage.append(_lineage(claim_id, psr, mapping_profile, ["attack-pattern.description-claim"]))

    records = sorted(records, key=lambda r: r["id"])
    lineage = sorted(lineage, key=lambda r: r["output_record_id"])
    return {
        "records": records,
        "lineage": lineage,
        "identity_outcomes": identity_outcomes,
        "quarantined": quarantined,
        "diagnostics": diagnostics,
        "candidate_digest": sha256_digest(records),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Normalize MITRE ATT&CK PSR into Atlas canonical candidate records.")
    ap.add_argument("psr", type=Path, help="JSON document containing a records array")
    ap.add_argument("--mapping-profile", type=Path, required=True)
    ap.add_argument("--source-version", required=True)
    ap.add_argument("--retrieved-at", required=True)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    psr_doc = json.loads(args.psr.read_text(encoding="utf-8"))
    profile = json.loads(args.mapping_profile.read_text(encoding="utf-8"))
    result = normalize_psr(
        psr_doc["records"], mapping_profile=profile,
        source_version=args.source_version, retrieved_at=args.retrieved_at,
    )
    rendered = json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
