#!/usr/bin/env python3
"""Build the self-contained ATLAS engineering-preview knowledge pack.

This pack is intentionally fixture-only and is not the Public Preview corpus.
It exists to prove the packaged Windows application can activate a verified
local pack and execute real Search -> Record -> Graph flows without network
access or an operator-side bootstrap step.

Private TUF signing keys are generated in process memory and are never written
to Git, the package, Actions artifacts, or disk. The emitted bootstrap root
contains public trust metadata only. Consequently this baseline is immutable:
production/public pack updates require the separately governed signing and key
custody design tracked by Phase 5.10.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import (
    TOP_LEVEL_ROLE_NAMES,
    MetaFile,
    Metadata,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer

from tools.pack.builder import build_verified_atlaspack
from tools.pack.tuf_runtime import CURRENT_RUNTIME_VERSION, sha256_prefixed
from tools.search.reference_search import build_projection_bundle
from tools.search.sqlite_search import build_index
from tools.content.build_encyclopedia_records import build_records as build_encyclopedia_records

ROOT = Path(__file__).resolve().parents[2]
PACK_ID = "atlas:pack:engineering-preview-fixture"
PACK_VERSION = "0.1.0-preview.1"
CREATED_AT = "2026-09-17T12:00:00Z"
ENCYCLOPEDIA_OVERRIDE_IDS = {
    "atlas:event:microsoft.windows.security:4688",
    "atlas:event:microsoft.sysmon:1",
}
EXPIRY = datetime(2030, 1, 1, tzinfo=timezone.utc)


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def metafile(metadata_bytes: bytes, version: int) -> MetaFile:
    return MetaFile(version, len(metadata_bytes), {"sha256": sha256_hex(metadata_bytes)})


def write_file(root: Path, relative: str, data: bytes) -> Path:
    path = root.joinpath(*relative.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def load_canonical_records() -> list[dict[str, Any]]:
    """Return a deterministic, positive fixture corpus with canonical records.

    Cross-domain entities provide usable analyst pivots such as Windows 4688,
    Sysmon 1, ATT&CK T1059.001, Linux EXECVE, AWS, Docker, and Kubernetes.
    Support records add first-party fixture provenance/relationship material.
    Duplicate IDs are accepted only when the bytes are semantically identical.
    """
    roots = [
        ROOT / "fixtures" / "phase-5.2" / "cross-domain",
        ROOT / "fixtures" / "phase-5.2" / "support",
    ]
    by_id: dict[str, dict[str, Any]] = {}
    for directory in roots:
        for path in sorted(directory.glob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8"))
            record_id = value.get("id")
            if not record_id or value.get("schema_version") != "1.0.0" or not value.get("record_kind"):
                continue
            previous = by_id.get(record_id)
            if previous is not None and previous != value:
                raise RuntimeError(f"conflicting canonical fixture id: {record_id}")
            by_id[record_id] = value
    for value in build_encyclopedia_records():
        record_id = value.get("id")
        if not record_id:
            raise RuntimeError("encyclopedia exemplar record is missing id")
        previous = by_id.get(record_id)
        if previous is not None and previous != value and record_id not in ENCYCLOPEDIA_OVERRIDE_IDS:
            raise RuntimeError(f"conflicting encyclopedia exemplar id: {record_id}")
        by_id[record_id] = value

    for required in (
        "atlas:event:microsoft.windows.security:4688",
        "atlas:event:microsoft.windows.security:4624",
        "atlas:event:microsoft.sysmon:1",
        "atlas:event:microsoft.sysmon:3",
    ):
        if required not in by_id:
            raise RuntimeError(f"required engineering-preview record is missing: {required}")
    return [by_id[key] for key in sorted(by_id)]


def make_signed_repository(repo: Path, pack_version: str) -> tuple[bytes, dict[str, Any]]:
    metadata_dir = repo / "metadata"
    targets_dir = repo / "targets"
    metadata_dir.mkdir(parents=True)
    targets_dir.mkdir(parents=True)

    records = load_canonical_records()
    canonical_bytes = b"".join(canonical_json_bytes(record) for record in records)

    graph_corpus = json.loads(
        (ROOT / "fixtures" / "phase-5.4.4" / "catalog-graph-corpus.json").read_text(
            encoding="utf-8"
        )
    )
    projection_ids = {record["id"] for record in graph_corpus.get("records", [])}
    claims_by_subject = {}
    for record in records:
        if record.get("record_kind") == "claim" and record.get("predicate") == "telemetry.represents":
            claims_by_subject[record.get("subject_id")] = record.get("object", {}).get("value", {})

    for record in records:
        if record.get("record_kind") != "entity" or record.get("entity_type") != "event":
            continue
        if record["id"] in projection_ids:
            continue
        native = []
        for item in record.get("native_identifiers", []):
            projected = {
                "type": item["type"],
                "value": item["value"],
                "namespace": item.get("namespace"),
                "case_sensitive": bool(item.get("case_sensitive")),
                "primary": bool(item.get("primary")),
            }
            if item.get("type") == "event_id":
                projected["numeric_semantics"] = True
            native.append(projected)
        scope = {}
        if record.get("native_identifiers"):
            scope = dict(record["native_identifiers"][0].get("context") or {})
        overview = claims_by_subject.get(record["id"]) or {}
        graph_corpus["records"].append({
            "id": record["id"],
            "entity_type": record["entity_type"],
            "title": record["title"],
            "namespace": record["namespace"],
            "scope": {
                "platform": scope.get("platform"),
                "product": scope.get("product"),
                "provider": scope.get("provider"),
                "channel": scope.get("channel"),
            },
            "lifecycle": (record.get("lifecycle") or {}).get("state"),
            "version": None,
            "description": overview.get("summary", ""),
            "native_identifiers": native,
            "aliases": record.get("aliases", []),
        })
        projection_ids.add(record["id"])
    graph_corpus["records"] = sorted(graph_corpus["records"], key=lambda item: item["id"])
    spc_bundle = build_projection_bundle(graph_corpus)
    spc_bytes = canonical_json_bytes(spc_bundle)

    search_path = targets_dir / "search" / "atlas-search.sqlite3"
    search_path.parent.mkdir(parents=True, exist_ok=True)
    build_index(spc_bundle, search_path)
    search_bytes = search_path.read_bytes()

    inventory = {
        "inventory_version": "1.0.0",
        "pack_id": PACK_ID,
        "pack_version": pack_version,
        "entries": [
            {
                "source_id": "fixture:atlas-engineering-preview",
                "source_name": "Cyber-Sentinel ATLAS repository-owned engineering fixtures",
                "upstream_url": "https://github.com/cyber-sentinel/Cyber-Sentinel-Atlas",
                "source_version_or_commit": "phase-5.10.5-fixture-baseline",
                "content_digest": sha256_prefixed(canonical_bytes),
                "redistribution_scope": "included",
                "license_status": "verified-redistributable",
                "license_identifier": "TEST-FIXTURE-ONLY",
                "notice_required": False,
                "attribution": "Synthetic/repository-owned ATLAS fixtures for engineering preview validation only; not the Public Preview corpus.",
                "evidence_url": "https://github.com/cyber-sentinel/Cyber-Sentinel-Atlas/tree/main/fixtures",
                "reviewed_at": CREATED_AT,
            }
        ],
    }
    inventory_bytes = canonical_json_bytes(inventory)

    artifact_bytes: dict[str, tuple[str, bool, bytes]] = {
        "content/canonical-records.jsonl": ("canonical-records", False, canonical_bytes),
        "search/spc.json": ("spc", True, spc_bytes),
        "search/atlas-search.sqlite3": ("search-index", True, search_bytes),
    }
    artifacts = [
        {
            "path": relative,
            "kind": kind,
            "digest": sha256_prefixed(data),
            "length": len(data),
            "derived": derived,
        }
        for relative, (kind, derived, data) in sorted(artifact_bytes.items())
    ]

    manifest = {
        "pack_format_version": "1.0.0",
        "pack_id": PACK_ID,
        "pack_version": pack_version,
        "created_at": CREATED_AT,
        "canonical_schema_version": "1.0.0",
        "ingestion_contract_version": "1.0.0",
        "search_contract_version": "1.0.0",
        "minimum_runtime_version": CURRENT_RUNTIME_VERSION,
        "canonical_records_digest": sha256_prefixed(canonical_bytes),
        "spc_digest": sha256_prefixed(spc_bytes),
        "source_license_inventory": {
            "path": "atlas/source-license-inventory.json",
            "digest": sha256_prefixed(inventory_bytes),
        },
        "artifacts": artifacts,
    }
    manifest_bytes = canonical_json_bytes(manifest)

    target_data: dict[str, bytes] = {
        "atlas/pack-manifest.json": manifest_bytes,
        "atlas/source-license-inventory.json": inventory_bytes,
        **{path: value[2] for path, value in artifact_bytes.items()},
    }
    for relative, data in sorted(target_data.items()):
        write_file(targets_dir, relative, data)

    md_root = Metadata(Root(expires=EXPIRY))
    md_targets = Metadata(Targets(expires=EXPIRY))
    md_snapshot = Metadata(Snapshot(expires=EXPIRY))
    md_timestamp = Metadata(Timestamp(expires=EXPIRY))
    md_root.signed.consistent_snapshot = True

    # Keys remain only in process memory. Never serialize private material.
    signers: dict[str, CryptoSigner] = {}
    for role in TOP_LEVEL_ROLE_NAMES:
        signer = CryptoSigner.generate_ed25519()
        md_root.signed.add_key(signer.public_key, role)
        signers[role] = signer

    for relative, data in sorted(target_data.items()):
        md_targets.signed.targets[relative] = TargetFile.from_data(relative, data, ["sha256"])

    serializer = JSONSerializer()
    md_targets.sign(signers[Targets.type])
    targets_metadata = md_targets.to_bytes(serializer)

    md_snapshot.signed.meta["targets.json"] = metafile(targets_metadata, md_targets.signed.version)
    md_snapshot.sign(signers[Snapshot.type])
    snapshot_metadata = md_snapshot.to_bytes(serializer)

    md_timestamp.signed.snapshot_meta = metafile(snapshot_metadata, md_snapshot.signed.version)
    md_timestamp.sign(signers[Timestamp.type])
    timestamp_metadata = md_timestamp.to_bytes(serializer)

    md_root.sign(signers[Root.type])
    root_metadata = md_root.to_bytes(serializer)

    write_file(metadata_dir, "root.json", root_metadata)
    write_file(metadata_dir, "targets.json", targets_metadata)
    write_file(metadata_dir, "snapshot.json", snapshot_metadata)
    write_file(metadata_dir, "timestamp.json", timestamp_metadata)

    evidence = {
        "schema_version": "1.0.0",
        "scope": "engineering-preview-fixture-only",
        "pack_id": PACK_ID,
        "pack_version": pack_version,
        "canonical_record_count": len(records),
        "canonical_entity_count": sum(1 for record in records if record.get("record_kind") == "entity"),
        "canonical_claim_count": sum(1 for record in records if record.get("record_kind") == "claim"),
        "canonical_relationship_count": sum(1 for record in records if record.get("record_kind") == "relationship"),
        "canonical_source_count": sum(1 for record in records if record.get("record_kind") == "source"),
        "search_projection_count": len(graph_corpus.get("records", [])),
        "graph_edge_count": len(graph_corpus.get("edges", [])),
        "legacy_fixture_graph_edge_count": len(graph_corpus.get("edges", [])),
        "contains_windows_4688": True,
        "contains_windows_4624": True,
        "contains_sysmon_1": True,
        "contains_sysmon_3": True,
        "encyclopedia_exemplar_count": 4,
        "private_keys_persisted": False,
        "public_preview_corpus": False,
    }
    return root_metadata, evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--pack-version", default=PACK_VERSION)
    args = parser.parse_args()

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    pack_path = output_dir / "atlas-engineering-preview.atlaspack"
    root_path = output_dir / "atlas-engineering-preview-root.json"
    evidence_path = output_dir / "ENGINEERING-PREVIEW-PACK.json"

    with tempfile.TemporaryDirectory(prefix="atlas-engineering-preview-") as temp:
        repo = Path(temp) / "signed-repository"
        bootstrap_root, evidence = make_signed_repository(repo, args.pack_version)
        result = build_verified_atlaspack(
            repo,
            pack_path,
            bootstrap_root=bootstrap_root,
            current_runtime_version=CURRENT_RUNTIME_VERSION,
        )

    root_path.write_bytes(bootstrap_root)
    evidence.update(
        {
            "atlaspack_sha256": result.sha256,
            "atlaspack_length": result.length,
            "atlaspack_file_count": result.file_count,
            "bootstrap_root_sha256": sha256_hex(bootstrap_root),
        }
    )
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
