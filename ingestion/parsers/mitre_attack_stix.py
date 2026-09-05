#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

PARSER_ID = "atlas:parser:atlas.ingestion:mitre-attack-stix21"
PARSER_VERSION = "1.0.0"
PSR_VERSION = "1.0.0"

# Source-native ATT&CK/STIX fields that the parser recognizes structurally.
# Everything else is preserved verbatim under unknown_fields and reported.
KNOWN_FIELDS = {
    "type", "spec_version", "id", "created", "created_by_ref", "revoked",
    "external_references", "object_marking_refs", "modified", "name", "description",
    "kill_chain_phases", "x_mitre_attack_spec_version", "x_mitre_contributors",
    "x_mitre_deprecated", "x_mitre_detection", "x_mitre_domains",
    "x_mitre_is_subtechnique", "x_mitre_modified_by_ref", "x_mitre_platforms",
    "x_mitre_version", "x_mitre_contents",
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


def attack_external_id(obj: dict) -> str | None:
    refs = obj.get("external_references", [])
    if not isinstance(refs, list):
        return None
    values = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        if ref.get("source_name") == "mitre-attack" and isinstance(ref.get("external_id"), str):
            values.append(ref["external_id"])
    if not values:
        return None
    # Multiple different MITRE IDs on one object would be structural drift/ambiguity.
    if len(set(values)) != 1:
        raise ValueError(f"conflicting mitre-attack external IDs for {obj.get('id')!r}: {values!r}")
    return values[0]


def _validate_bundle_shape(bundle: dict) -> list[dict]:
    if not isinstance(bundle, dict):
        raise ValueError("ATT&CK input must be a JSON object")
    if bundle.get("type") != "bundle":
        raise ValueError("ATT&CK input type must be STIX bundle")
    if not isinstance(bundle.get("id"), str) or not bundle["id"].startswith("bundle--"):
        raise ValueError("ATT&CK bundle id is missing or malformed")
    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        raise ValueError("ATT&CK bundle objects must be a non-empty array")
    return objects


def parse_bundle(
    bundle: dict,
    *,
    source_id: str,
    source_snapshot_id: str,
    parser_id: str = PARSER_ID,
    parser_version: str = PARSER_VERSION,
    psr_version: str = PSR_VERSION,
) -> list[dict]:
    objects = _validate_bundle_shape(bundle)
    out: list[dict] = []
    seen_native_keys: set[str] = set()

    for index, obj in enumerate(objects):
        if not isinstance(obj, dict):
            raise ValueError(f"objects[{index}] must be an object")
        native_type = obj.get("type")
        native_key = obj.get("id")
        if not isinstance(native_type, str) or not native_type:
            raise ValueError(f"objects[{index}] missing STIX type")
        if not isinstance(native_key, str) or not native_key:
            raise ValueError(f"objects[{index}] missing STIX id")
        if native_key in seen_native_keys:
            raise ValueError(f"duplicate STIX object id: {native_key}")
        seen_native_keys.add(native_key)

        known = {k: copy.deepcopy(v) for k, v in obj.items() if k in KNOWN_FIELDS}
        unknown = {k: copy.deepcopy(v) for k, v in obj.items() if k not in KNOWN_FIELDS}
        native_identifiers = [{"type": "stix_id", "value": native_key, "namespace": "mitre.attack"}]
        external_id = attack_external_id(obj)
        if external_id:
            native_identifiers.append({"type": "attack_id", "value": external_id, "namespace": "mitre.attack"})

        locator = {"json_pointer": f"/objects/{index}"}
        semantic = {
            "source_id": source_id,
            "source_snapshot_id": source_snapshot_id,
            "parser_id": parser_id,
            "parser_version": parser_version,
            "psr_version": psr_version,
            "native_type": native_type,
            "native_key": native_key,
            "native_identifiers": native_identifiers,
            "native_fields": known,
            "unknown_fields": unknown,
            "locator": locator,
        }
        record_digest = sha256_digest(semantic)
        parsed_record_id = stable_artifact_id(
            "parsed-source-record",
            {
                "source_snapshot_id": source_snapshot_id,
                "parser_id": parser_id,
                "parser_version": parser_version,
                "locator": locator,
                "record_digest": record_digest,
            },
        )
        diagnostics = []
        if unknown:
            diagnostics.append("unknown structured fields preserved: " + ", ".join(sorted(unknown)))

        out.append({
            "psr_version": psr_version,
            "parsed_record_id": parsed_record_id,
            "source_id": source_id,
            "source_snapshot_id": source_snapshot_id,
            "parser_id": parser_id,
            "parser_version": parser_version,
            "native_type": native_type,
            "native_key": native_key,
            "native_identifiers": native_identifiers,
            "native_fields": known,
            "unknown_fields": unknown,
            "locator": locator,
            "record_digest": record_digest,
            "diagnostics": diagnostics,
        })
    return out


def parse_bytes(raw: bytes, *, source_id: str, source_snapshot_id: str) -> list[dict]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("ATT&CK STIX input must be UTF-8") from exc
    try:
        bundle = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid ATT&CK JSON: {exc}") from exc
    return parse_bundle(bundle, source_id=source_id, source_snapshot_id=source_snapshot_id)


def representation_digest(records: list[dict]) -> str:
    rows = sorted(
        ({"parsed_record_id": r["parsed_record_id"], "record_digest": r["record_digest"]} for r in records),
        key=lambda r: r["parsed_record_id"],
    )
    return sha256_digest(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse a pinned MITRE ATT&CK STIX 2.1 bundle into Atlas PSR.")
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
