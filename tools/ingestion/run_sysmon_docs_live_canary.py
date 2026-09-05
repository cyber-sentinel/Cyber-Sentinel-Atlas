#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import ipaddress
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[2]


def mod(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def load(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def blob_sha1(raw: bytes) -> str:
    return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()


def assert_public_dns(host: str) -> None:
    ips = {entry[4][0] for entry in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
    if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
        raise RuntimeError(f"non-public DNS resolution for {host}: {sorted(ips)}")


def fetch(url: str, security_policy: dict, foundation) -> tuple[bytes, dict]:
    errors = foundation.public_uri_errors(url, security_policy.get("allowed_hosts"), None)
    if errors:
        raise RuntimeError("unsafe URL: " + "; ".join(errors))
    if security_policy.get("tls_verify") is not True or security_policy.get("redirect_limit") != 0:
        raise RuntimeError("TLS verification + zero redirects required")

    host = urlparse(url).hostname or ""
    assert_public_dns(host)
    opener = build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
    request = Request(
        url,
        headers={
            "User-Agent": "Cyber-Sentinel-Atlas/phase-5.3.3-sysmon-docs-canary",
            "Accept": "text/plain,text/markdown;q=0.9,*/*;q=0.1",
        },
    )
    limit = int(security_policy["max_response_bytes"])
    parts: list[bytes] = []
    total = 0
    with opener.open(request, timeout=float(security_policy["read_timeout_seconds"])) as response:
        if response.status != 200 or response.geturl() != url:
            raise RuntimeError(f"unexpected HTTP response {response.status} {response.geturl()}")
        if response.headers.get("Content-Length") and int(response.headers["Content-Length"]) > limit:
            raise RuntimeError("response too large")
        while True:
            block = response.read(min(262144, limit - total + 1))
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
    return b"".join(parts), {k: v for k, v in headers.items() if v is not None}


def check(foundation, schema: str, value: dict, label: str) -> None:
    errors = list(foundation.ingestion_validator(schema).iter_errors(value))
    if errors:
        raise RuntimeError(label + ": " + "; ".join(error.message for error in errors[:10]))


def main() -> int:
    source = load("ingestion/source-profiles/microsoft-sysmon-docs.source.json")
    release = load("ingestion/source-profiles/microsoft-sysmon-docs.release.json")
    connector = load("ingestion/connectors/microsoft-sysmon-docs.json")
    mapping = load("ingestion/mappings/microsoft-sysmon-docs-v1.json")
    inventory = load("ingestion/inventories/sysmon-docs-15.21.documentation.json")

    foundation = mod("sysmon_live_foundation", ROOT / "tools/ingestion/validate_ingestion_foundation.py")
    phase52 = mod("sysmon_live_phase52", ROOT / "tools/validate_phase52.py")
    parser = mod("sysmon_live_parser", ROOT / "ingestion/parsers/microsoft_sysmon_markdown.py")
    normalizer = mod("sysmon_live_normalizer", ROOT / "ingestion/normalizers/microsoft_sysmon_docs.py")

    if release["document_url"] != connector["targets"][0]["resource_uri"]:
        raise RuntimeError("release/connector URL pin mismatch")
    if release["release_version"] != mapping["source_version"]:
        raise RuntimeError("release/mapping source version mismatch")
    if inventory["digest"] != foundation.digest_without_field(inventory, "digest"):
        raise RuntimeError("documentation inventory digest mismatch")
    check(foundation, "inventory-definition.schema.json", inventory, "DocumentationInventory")

    started_at = now()
    raw, headers = fetch(release["document_url"], connector["security_policy"], foundation)
    finished_at = now()
    if blob_sha1(raw) != release["document_git_blob_sha1"]:
        raise RuntimeError("pinned sysmon.md Git blob identity mismatch")

    raw_digest = foundation.sha256_digest(raw)
    run_id = f"atlas:acquisition-run:atlas.ingestion:sysmon-docs-v15.21-{raw_digest[7:31]}"
    target_key = "sysmon-markdown"
    resource_key = release["document_path"]
    snapshot_id = foundation.stable_artifact_id(
        "raw-snapshot",
        {
            "acquisition_run_id": run_id,
            "target_key": target_key,
            "resource_key": resource_key,
            "raw_content_digest": raw_digest,
        },
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
            "executor_ref": "github-actions-phase53-sysmon-docs-canary",
            "attempt": 1,
            "environment_class": "ci",
        },
        "resource_results": [
            {
                "target_key": target_key,
                "resource_key": resource_key,
                "required": True,
                "status": "success",
                "requested_uri": release["document_url"],
                "resolved_uri": release["document_url"],
                "snapshot_id": snapshot_id,
                "diagnostics": [],
            }
        ],
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
        "requested_resource": {"uri": release["document_url"], "media_type": "text/markdown", "encoding": "utf-8"},
        "resolved_resource": {"uri": release["document_url"], "media_type": "text/markdown", "encoding": "utf-8"},
        "media_type": "text/markdown",
        "encoding": "utf-8",
        "byte_length": len(raw),
        "raw_content_digest": raw_digest,
        "blob_ref": f"blob:{raw_digest}",
        "upstream_validators": {
            "publisher_version": release["release_version"],
            "git_commit": release["upstream_commit_sha"],
            "git_blob": release["document_git_blob_sha1"],
        },
        "transport_metadata": headers,
        "retention_mode": "transient",
        "integrity_state": "verified",
    }
    check(foundation, "acquisition-run.schema.json", acquisition_run, "AcquisitionRun")
    check(foundation, "raw-snapshot.schema.json", snapshot, "RawSnapshot")
    semantic_errors = foundation.acquisition_semantic_errors(connector, acquisition_run)
    if semantic_errors:
        raise RuntimeError("AcquisitionRun semantic failure: " + "; ".join(semantic_errors))

    parser_started = now()
    records = parser.parse_bytes(raw, source_id=source["id"], source_snapshot_id=snapshot_id)
    parser_finished = now()
    representation_digest = parser.representation_digest(records)
    parser_run_id = foundation.stable_artifact_id(
        "parser-run",
        {"snapshot_id": snapshot_id, "parser_id": parser.PARSER_ID, "parser_version": parser.PARSER_VERSION},
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
        errors = list(psr_validator.iter_errors(record))
        if errors:
            raise RuntimeError(f"PSR[{index}] invalid: {errors[0].message}")
        payload = {
            key: record.get(key)
            for key in ("native_type", "native_key", "native_identifiers", "native_fields", "unknown_fields", "locator")
        }
        if record["record_digest"] != foundation.sha256_digest(payload):
            raise RuntimeError(f"PSR[{index}] record_digest diverges from Phase 5.3.1 contract")

    parsed_ids = [record["native_fields"]["event_id"] for record in records]
    expected_ids = release["expected_documented_event_ids"]
    if parsed_ids != expected_ids:
        raise RuntimeError(f"pinned Sysmon documentation inventory drift: parsed={parsed_ids!r}")
    inventory_ids = [item["event_id"] for item in inventory["scope_metadata"]["expected_identities"]]
    if parsed_ids != inventory_ids:
        raise RuntimeError("parsed Sysmon documentation IDs diverge from immutable documentation inventory")

    normalization_started = now()
    output = normalizer.normalize_psr(
        records,
        mapping_profile=mapping,
        source_version=release["release_version"],
        retrieved_at=finished_at,
    )
    normalization_finished = now()
    if output["quarantined"] or output["identity_outcomes"]["AMBIGUOUS"]:
        raise RuntimeError(f"ambiguous Sysmon identity: {output['quarantined'][:5]}")

    expected_canonical_ids = [f"atlas:event:microsoft.sysmon:{event_id}" for event_id in expected_ids]
    actual_canonical_ids = [record["id"] for record in output["records"]]
    if actual_canonical_ids != expected_canonical_ids:
        raise RuntimeError("canonical Sysmon event identity set/order mismatch")
    if any("lifecycle" in record for record in output["records"]):
        raise RuntimeError("documentation-only path must not set canonical lifecycle")

    combined = [(ROOT / "ingestion/source-profiles/microsoft-sysmon-docs.source.json", source)] + [
        (ROOT / f"live/sysmon-docs/{index}.json", record) for index, record in enumerate(output["records"])
    ]
    canonical_errors = phase52.validate_schema_records(combined) + phase52.validate_semantics(combined, phase52.load_registries())
    if canonical_errors:
        raise RuntimeError("canonical validation: " + "; ".join(canonical_errors[:20]))

    lineage_validator = foundation.ingestion_validator("normalization-lineage.schema.json")
    for lineage in output["lineage"]:
        errors = list(lineage_validator.iter_errors(lineage))
        if errors:
            raise RuntimeError("lineage invalid: " + errors[0].message)
        if lineage["source_snapshot_ids"] != [snapshot_id]:
            raise RuntimeError("lineage source snapshot binding mismatch")

    registry_digest = foundation.sha256_digest(
        [load(str(path.relative_to(ROOT))) for path in sorted((ROOT / "model/registries").glob("*.json"))]
    )
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
        "mapping_profile": {"id": mapping["profile_id"], "version": mapping["profile_version"], "digest": mapping["profile_digest"]},
        "registry_bundle": {"version": "1.0.0", "digest": registry_digest},
        "canonical_schema_version": "1.0.0",
        "started_at": normalization_started,
        "finished_at": normalization_finished,
        "result": "success",
        "identity_outcomes": output["identity_outcomes"],
        "output_counts": {"EntityRecord": len(output["records"])},
        "canonical_candidate_digest": output["candidate_digest"],
        "publishable": True,
        "diagnostics": output["diagnostics"],
    }
    check(foundation, "normalization-run.schema.json", normalization_run, "NormalizationRun")

    event1 = next(record for record in output["records"] if record["id"] == "atlas:event:microsoft.sysmon:1")
    native = event1["native_identifiers"][0]
    if native["value"] != "1" or native["context"]["provider"] != "Microsoft-Windows-Sysmon":
        raise RuntimeError("Sysmon Event ID 1 search-readiness context mismatch")

    print(
        f"Phase 5.3.3 Sysmon docs live canary PASSED: v{release['release_version']} "
        f"raw={len(raw)} sha256={raw_digest} psr={len(records)} events={len(output['records'])} "
        f"candidate={output['candidate_digest']} documentation_inventory={inventory['digest']}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("Phase 5.3.3 Sysmon docs live canary FAILED:", exc, file=sys.stderr)
        raise SystemExit(1)
