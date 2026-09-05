#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from rdflib import BNode, Graph, Namespace, RDF, RDFS
from rdflib.compare import to_canonical_graph

PARSER_ID = "atlas:parser:atlas.ingestion:mitre-d3fend-turtle"
PARSER_VERSION = "1.0.0"
PSR_VERSION = "1.0.0"
MAX_INPUT_BYTES = 32 * 1024 * 1024
D3FEND_ID_RE = re.compile(r"^D3-[A-Z0-9]+$")
D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")
KNOWN_PREDICATES = {RDF.type, RDFS.label, D3F["d3fend-id"], D3F.definition}


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


def _values(graph: Graph, subject, predicate) -> list[str]:
    return sorted({str(value) for value in graph.objects(subject, predicate)})


def _collect_subject_ids(graph: Graph) -> dict[str, list]:
    subject_ids: dict[str, list] = {}
    for subject, value in graph.subject_objects(D3F["d3fend-id"]):
        identifier = str(value)
        if D3FEND_ID_RE.fullmatch(identifier):
            subject_ids.setdefault(identifier, []).append(subject)
    return subject_ids


def _requires_blank_node_canonicalization(graph: Graph, subject_ids: dict[str, list]) -> bool:
    """Canonicalize only when blank-node identity can affect emitted PSR fields.

    Full RDF canonicalization over the complete D3FEND ontology is expensive and is
    unnecessary when all emitted subjects and their direct predicate objects are
    stable IRIs/literals. Unrelated blank nodes cannot influence the output because
    the parser emits only records rooted at subjects carrying a valid d3fend-id.
    """
    for subjects in subject_ids.values():
        for subject in subjects:
            if isinstance(subject, BNode):
                return True
            for _predicate, obj in graph.predicate_objects(subject):
                if isinstance(obj, BNode):
                    return True
    return False


def parse_bytes(
    raw: bytes,
    *,
    source_id: str,
    source_snapshot_id: str,
    expected_sha256: str | None = None,
) -> list[dict]:
    if not raw:
        raise ValueError("D3FEND Turtle input is empty")
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(f"D3FEND Turtle input exceeds {MAX_INPUT_BYTES} bytes")
    actual_digest = sha256_digest(raw)
    if expected_sha256 is not None and actual_digest != expected_sha256:
        raise ValueError(f"D3FEND distribution digest mismatch: {actual_digest} != {expected_sha256}")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("D3FEND Turtle input must be UTF-8") from exc

    graph = Graph()
    try:
        graph.parse(data=text, format="turtle")
    except Exception as exc:
        raise ValueError(f"invalid D3FEND Turtle: {exc}") from exc

    subject_ids = _collect_subject_ids(graph)
    if not subject_ids:
        raise ValueError("D3FEND ontology contains no defensive technique identifiers")

    # Preserve deterministic blank-node handling without canonicalizing the entire
    # ontology when blank nodes are irrelevant to the emitted records. This keeps
    # the official live canary bounded while retaining fail-safe determinism.
    if _requires_blank_node_canonicalization(graph, subject_ids):
        graph = to_canonical_graph(graph)
        subject_ids = _collect_subject_ids(graph)

    records: list[dict] = []
    for identifier in sorted(subject_ids):
        subjects = subject_ids[identifier]
        if len({str(subject) for subject in subjects}) != 1:
            raise ValueError(f"ambiguous D3FEND identifier {identifier}: multiple subjects")
        subject = subjects[0]
        labels = _values(graph, subject, RDFS.label)
        definitions = _values(graph, subject, D3F.definition)
        if len(labels) != 1:
            raise ValueError(f"D3FEND {identifier}: expected exactly one label")
        if len(definitions) > 1:
            raise ValueError(f"D3FEND {identifier}: multiple definitions are structurally ambiguous")

        types = _values(graph, subject, RDF.type)
        unknown: dict[str, list[str]] = {}
        for predicate, obj in graph.predicate_objects(subject):
            if predicate in KNOWN_PREDICATES:
                continue
            unknown.setdefault(str(predicate), []).append(str(obj))
        unknown = {key: sorted(set(values)) for key, values in sorted(unknown.items())}

        native_key = str(subject)
        native_identifiers = [
            {"type": "d3fend_id", "value": identifier, "namespace": "mitre.d3fend"},
            {"type": "iri", "value": native_key, "namespace": "mitre.d3fend"},
        ]
        native_fields = {
            "d3fend_id": identifier,
            "iri": native_key,
            "label": labels[0],
            "definition": definitions[0] if definitions else None,
            "rdf_types": types,
        }
        locator = {"source_key": native_key}
        record_payload = {
            "native_type": "d3fend-defensive-technique",
            "native_key": native_key,
            "native_identifiers": native_identifiers,
            "native_fields": native_fields,
            "unknown_fields": unknown,
            "locator": locator,
        }
        record_digest = sha256_digest(record_payload)
        parsed_record_id = stable_artifact_id(
            "parsed-source-record",
            {
                "source_snapshot_id": source_snapshot_id,
                "parser_id": PARSER_ID,
                "parser_version": PARSER_VERSION,
                "psr_version": PSR_VERSION,
                "native_type": "d3fend-defensive-technique",
                "native_key": native_key,
                "record_digest": record_digest,
            },
        )
        diagnostics = []
        if unknown:
            diagnostics.append("unknown direct ontology predicates preserved for drift review")
        records.append(
            {
                "psr_version": PSR_VERSION,
                "parsed_record_id": parsed_record_id,
                "source_id": source_id,
                "source_snapshot_id": source_snapshot_id,
                "parser_id": PARSER_ID,
                "parser_version": PARSER_VERSION,
                "native_type": "d3fend-defensive-technique",
                "native_key": native_key,
                "native_identifiers": native_identifiers,
                "native_fields": native_fields,
                "unknown_fields": unknown,
                "locator": locator,
                "record_digest": record_digest,
                "diagnostics": diagnostics,
            }
        )
    return records


def representation_digest(records: list[dict]) -> str:
    rows = sorted(
        ({"parsed_record_id": r["parsed_record_id"], "record_digest": r["record_digest"]} for r in records),
        key=lambda row: row["parsed_record_id"],
    )
    return sha256_digest(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse a digest-pinned MITRE D3FEND Turtle ontology into Atlas PSR.")
    ap.add_argument("input", type=Path)
    ap.add_argument("--source-id", required=True)
    ap.add_argument("--snapshot-id", required=True)
    ap.add_argument("--expected-sha256")
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    records = parse_bytes(
        args.input.read_bytes(),
        source_id=args.source_id,
        source_snapshot_id=args.snapshot_id,
        expected_sha256=args.expected_sha256,
    )
    payload = {"psr_version": PSR_VERSION, "representation_digest": representation_digest(records), "records": records}
    rendered = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
