#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import ipaddress
import json
import socket
import ssl
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[2]


def mod(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def load(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def blob_sha1(raw):
    return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()


def public_dns(host):
    ips = {entry[4][0] for entry in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
    if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
        raise RuntimeError(f"non-public DNS resolution for {host}: {sorted(ips)}")


def fetch(url, security_policy, foundation):
    errors = foundation.public_uri_errors(url, security_policy.get("allowed_hosts"), None)
    if errors:
        raise RuntimeError("unsafe URL: " + "; ".join(errors))
    if security_policy.get("tls_verify") is not True or security_policy.get("redirect_limit") != 0:
        raise RuntimeError("TLS verification + zero redirects required")

    public_dns(urlparse(url).hostname or "")
    opener = build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
    request = Request(
        url,
        headers={
            "User-Agent": "Cyber-Sentinel-Atlas/phase-5.3.2-canary",
            "Accept": "application/json",
        },
    )
    limit = int(security_policy["max_response_bytes"])
    parts = []
    total = 0
    with opener.open(request, timeout=float(security_policy["read_timeout_seconds"])) as response:
        if response.status != 200 or response.geturl() != url:
            raise RuntimeError(f"unexpected HTTP response {response.status} {response.geturl()}")
        if response.headers.get("Content-Length") and int(response.headers["Content-Length"]) > limit:
            raise RuntimeError("response too large")
        while True:
            block = response.read(min(1048576, limit - total + 1))
            if not block:
                break
            parts.append(block)
            total += len(block)
            if total > limit:
                raise RuntimeError("stream exceeded max_response_bytes")
        headers = {
            "content_type": response.headers.get("Content-Type"),
            "content_length": total,
            "etag": response.headers.get("ETag"),
            "last_modified": response.headers.get("Last-Modified"),
            "date": response.headers.get("Date"),
        }
    return b"".join(parts), {key: value for key, value in headers.items() if value is not None}


def check(foundation, schema, value, label):
    errors = list(foundation.ingestion_validator(schema).iter_errors(value))
    if errors:
        raise RuntimeError(label + ": " + "; ".join(error.message for error in errors[:10]))


def semantic_view(records):
    out = copy.deepcopy(records)
    for _, record in out:
        for evidence in record.get("evidence", []):
            evidence.pop("source_snapshot_id", None)
    return out


def raw_snapshot_id(
    foundation,
    *,
    acquisition_run_id: str,
    target_key: str,
    resource_key: str,
    raw_content_digest: str,
) -> str:
    """Build RawSnapshot identity exactly as defined by Phase 5.3.1."""
    return foundation.stable_artifact_id(
        "raw-snapshot",
        {
            "acquisition_run_id": acquisition_run_id,
            "target_key": target_key,
            "resource_key": resource_key,
            "raw_content_digest": raw_content_digest,
        },
    )


def main():
    source = load("ingestion/source-profiles/mitre-attack-enterprise.source.json")
    release = load("ingestion/source-profiles/mitre-attack-enterprise.release.json")
    connector = load("ingestion/connectors/mitre-attack-enterprise.json")
    mapping = load("ingestion/mappings/mitre-attack-enterprise-v1.json")

    foundation = mod("live_f", ROOT / "tools/ingestion/validate_ingestion_foundation.py")
    phase52 = mod("live_p52", ROOT / "tools/validate_phase52.py")
    parser = mod("live_parser", ROOT / "ingestion/parsers/mitre_attack_stix.py")
    normalizer = mod("live_norm", ROOT / "ingestion/normalizers/mitre_attack.py")

    started_at = now()
    raw, headers = fetch(release["bundle_url"], connector["security_policy"], foundation)
    finished_at = now()
    if len(raw) != release["bundle_size_bytes"]:
        raise RuntimeError(f"byte size mismatch: {len(raw)}")
    git_blob = blob_sha1(raw)
    if git_blob != release["bundle_git_blob_sha1"]:
        raise RuntimeError(f"Git blob mismatch: {git_blob}")

    raw_digest = foundation.sha256_digest(raw)
    key = raw_digest[7:31]
    run_id = f"atlas:acquisition-run:atlas.ingestion:attack-v19.2-{key}"
    target_key = "enterprise-bundle"
    resource_key = release["bundle_path"]
    snapshot_id = raw_snapshot_id(
        foundation,
        acquisition_run_id=run_id,
        target_key=target_key,
        resource_key=resource_key,
        raw_content_digest=raw_digest,
    )

    acquisition_run = {
        "ingestion_contract_version": "1.0.0",
        "acquisition_run_id": run_id,
        "connector_id": connector["connector_id"],
        "connector_version": connector["connector_version"],
        "source_id": source["id"],
        "started_at": started_at,
        "finished_at": finished_at,
        "trigger": "test",
        "execution_metadata": {
            "executor_ref": "github-actions-phase53-attack-canary",
            "attempt": 1,
            "environment_class": "ci",
        },
        "resource_results": [{
            "target_key": target_key,
            "resource_key": resource_key,
            "required": True,
            "status": "success",
            "requested_uri": release["bundle_url"],
            "resolved_uri": release["bundle_url"],
            "snapshot_id": snapshot_id,
            "diagnostics": [],
        }],
        "metrics": {
            "resource_count": 1,
            "success_count": 1,
            "failed_count": 0,
            "not_modified_count": 0,
            "skipped_count": 0,
            "bytes_received": len(raw),
        },
        "diagnostics": [],
        "result_status": "success",
        "publication_eligible": True,
    }
    snapshot = {
        "ingestion_contract_version": "1.0.0",
        "snapshot_id": snapshot_id,
        "source_id": source["id"],
        "source_version": release["release_version"],
        "connector_id": connector["connector_id"],
        "connector_version": connector["connector_version"],
        "acquisition_run_id": run_id,
        "target_key": target_key,
        "resource_key": resource_key,
        "retrieved_at": finished_at,
        "requested_resource": {
            "uri": release["bundle_url"],
            "media_type": "application/json",
            "encoding": "utf-8",
        },
        "resolved_resource": {
            "uri": release["bundle_url"],
            "media_type": "application/json",
            "encoding": "utf-8",
        },
        "media_type": "application/json",
        "encoding": "utf-8",
        "byte_length": len(raw),
        "raw_content_digest": raw_digest,
        "blob_ref": f"blob:{raw_digest}",
        "upstream_validators": {
            "publisher_version": release["release_version"],
            "git_commit": release["upstream_commit_sha"],
        },
        "transport_metadata": headers,
        "retention_mode": "transient",
        "integrity_state": "verified",
    }
    check(foundation, "acquisition-run.schema.json", acquisition_run, "AcquisitionRun")
    check(foundation, "raw-snapshot.schema.json", snapshot, "RawSnapshot")
    acquisition_errors = foundation.acquisition_semantic_errors(connector, acquisition_run)
    if acquisition_errors:
        raise RuntimeError("AcquisitionRun semantic failure: " + "; ".join(acquisition_errors))

    parser_started = now()
    records = parser.parse_bytes(raw, source_id=source["id"], source_snapshot_id=snapshot_id)
    parser_finished = now()
    representation_digest = parser.representation_digest(records)
    parser_run_id = foundation.stable_artifact_id(
        "parser-run",
        {
            "snapshot_id": snapshot_id,
            "parser_id": parser.PARSER_ID,
            "parser_version": parser.PARSER_VERSION,
        },
    )
    parser_run = {
        "ingestion_contract_version": "1.0.0",
        "parser_run_id": parser_run_id,
        "source_snapshot_id": snapshot_id,
        "parser_id": parser.PARSER_ID,
        "parser_version": parser.PARSER_VERSION,
        "psr_version": parser.PSR_VERSION,
        "started_at": parser_started,
        "finished_at": parser_finished,
        "result": "success",
        "input_blob_digest": raw_digest,
        "output_record_count": len(records),
        "representation_digest": representation_digest,
        "diagnostics": [],
    }
    check(foundation, "parser-run.schema.json", parser_run, "ParserRun")

    psr_validator = foundation.ingestion_validator("parsed-source-record.schema.json")
    for index, record in enumerate(records):
        schema_errors = list(psr_validator.iter_errors(record))
        if schema_errors:
            raise RuntimeError(f"PSR[{index}] invalid: {schema_errors[0].message}")
        payload = {
            key: record.get(key)
            for key in (
                "native_type",
                "native_key",
                "native_identifiers",
                "native_fields",
                "unknown_fields",
                "locator",
            )
        }
        if record["record_digest"] != foundation.sha256_digest(payload):
            raise RuntimeError(f"PSR[{index}] record_digest diverges from Phase 5.3.1 contract")
        expected_psr_id = foundation.stable_artifact_id(
            "parsed-source-record",
            {
                "source_snapshot_id": record["source_snapshot_id"],
                "parser_id": record["parser_id"],
                "parser_version": record["parser_version"],
                "psr_version": record["psr_version"],
                "native_type": record["native_type"],
                "native_key": record.get("native_key"),
                "record_digest": record["record_digest"],
            },
        )
        if record["parsed_record_id"] != expected_psr_id:
            raise RuntimeError(f"PSR[{index}] identity diverges from Phase 5.3.1 contract")

    bundle = json.loads(raw.decode())
    collections = [
        item for item in bundle.get("objects", [])
        if item.get("type") == "x-mitre-collection" and item.get("id") == release["collection_id"]
    ]
    if len(collections) != 1 or collections[0].get("x_mitre_version") != release["release_version"]:
        raise RuntimeError("expected Enterprise collection/release absent")

    normalization_started = now()
    output = normalizer.normalize_psr(
        records,
        mapping_profile=mapping,
        source_version=release["release_version"],
        retrieved_at=finished_at,
    )
    normalization_finished = now()
    if output["quarantined"] or output["identity_outcomes"]["AMBIGUOUS"]:
        raise RuntimeError(f"ambiguous ATT&CK identity: {output['quarantined'][:5]}")

    combined = [(ROOT / "ingestion/source-profiles/mitre-attack-enterprise.source.json", source)] + [
        (ROOT / f"live/attack/{index}.json", record)
        for index, record in enumerate(output["records"])
    ]
    errors = phase52.validate_schema_records(combined) + phase52.validate_semantics(
        semantic_view(combined), phase52.load_registries()
    )
    for _, record in combined:
        for evidence in record.get("evidence", []):
            if evidence.get("source_snapshot_id") != snapshot_id:
                errors.append("cross-corpus snapshot mismatch")
    if errors:
        raise RuntimeError("canonical validation: " + "; ".join(errors[:20]))

    lineage_validator = foundation.ingestion_validator("normalization-lineage.schema.json")
    for lineage in output["lineage"]:
        lineage_errors = list(lineage_validator.iter_errors(lineage))
        if lineage_errors:
            raise RuntimeError("lineage invalid: " + lineage_errors[0].message)

    counts = Counter(record["record_kind"] for record in output["records"])
    registry_digest = foundation.sha256_digest([
        load(str(path.relative_to(ROOT)))
        for path in sorted((ROOT / "model/registries").glob("*.json"))
    ])
    normalization_run = {
        "ingestion_contract_version": "1.0.0",
        "normalization_run_id": foundation.stable_artifact_id(
            "normalization-run",
            {"parser_run_id": parser_run_id, "candidate": output["candidate_digest"]},
        ),
        "parser_run_id": parser_run_id,
        "normalizer_id": normalizer.NORMALIZER_ID,
        "normalizer_version": normalizer.NORMALIZER_VERSION,
        "psr_version": parser.PSR_VERSION,
        "mapping_profile": {
            "id": mapping["profile_id"],
            "version": mapping["profile_version"],
            "digest": mapping["profile_digest"],
        },
        "registry_bundle": {"version": "1.0.0", "digest": registry_digest},
        "canonical_schema_version": "1.0.0",
        "started_at": normalization_started,
        "finished_at": normalization_finished,
        "result": "success",
        "identity_outcomes": output["identity_outcomes"],
        "output_counts": {
            "EntityRecord": counts["entity"],
            "ClaimRecord": counts["claim"],
        },
        "canonical_candidate_digest": output["candidate_digest"],
        "publishable": True,
        "diagnostics": output["diagnostics"],
    }
    check(foundation, "normalization-run.schema.json", normalization_run, "NormalizationRun")

    techniques = [record for record in output["records"] if record.get("entity_type") == "attack-technique"]
    if not any(record["id"] == "atlas:attack-technique:mitre.attack:t1059.001" for record in techniques):
        raise RuntimeError("T1059.001 missing")

    print(
        f"Phase 5.3.2 live ATT&CK canary PASSED: v{release['release_version']} "
        f"raw={len(raw)} sha256={raw_digest} psr={len(records)} techniques={len(techniques)} "
        f"claims={counts['claim']} candidate={output['candidate_digest']}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("Phase 5.3.2 live ATT&CK canary FAILED:", exc, file=sys.stderr)
        raise SystemExit(1)
