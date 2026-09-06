#!/usr/bin/env python3
"""Build ephemeral, public-only Phase 5.5.3 cross-language spike fixtures.

Private TUF signing keys remain inside this process via the existing Phase 5.5.2
helper and are never copied into the spike workspace or Git artifacts.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from tests.phase55.phase552_helpers import (
    bump_repository_metadata,
    canonical_json_bytes,
    make_signed_repository,
)
from tools.search.reference_search import ReferenceResolver, build_projection_bundle
from tools.search.sqlite_search import SQLiteSearchCore, build_index

ROOT = Path(__file__).resolve().parents[3]
REQUIRED_QUERIES = [
    "4688",
    "Event ID 4688",
    "windows 4688",
    "sysmon 1",
    "1",
    "592",
    "T1059",
    "T1059.001",
    "CreateAccessKey",
    "EXECVE",
    "exec_start",
    "kubectl exec",
    "FileAccessed",
    "platform:windows process",
]
EXACT_CONTRACT_STAGES = {
    "canonical_identifier",
    "native_identifier",
    "scoped_identifier",
    "alias",
}


def compact_json_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_prefixed(data: bytes) -> str:
    return "sha256-" + hashlib.sha256(data).hexdigest()


def copy_repo(source: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)


def mutate_targets_signature(path: Path) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    signatures = value.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise RuntimeError("targets metadata has no signature to mutate")
    signature = signatures[0].get("sig")
    if not isinstance(signature, str) or not signature:
        raise RuntimeError("targets metadata signature is malformed")
    signatures[0]["sig"] = ("0" if signature[0] != "0" else "1") + signature[1:]
    path.write_bytes(compact_json_bytes(value))


def targets_for(result: dict) -> list[str]:
    return [str(item["target_id"]) for item in result.get("matches", [])]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    generated = out / "_generated"
    generated.mkdir()

    valid_fixture = make_signed_repository(generated / "valid-source")
    copy_repo(valid_fixture.root, out / "valid")
    (out / "bootstrap-root.json").write_bytes(valid_fixture.bootstrap_root)

    wrong_root_fixture = make_signed_repository(generated / "wrong-root-source")
    (out / "wrong-bootstrap-root.json").write_bytes(wrong_root_fixture.bootstrap_root)

    copy_repo(valid_fixture.root, out / "tampered-target")
    tampered_target = out / "tampered-target" / "targets" / "content" / "canonical-records.jsonl"
    tampered_target.write_bytes(tampered_target.read_bytes() + b"tamper\n")

    copy_repo(valid_fixture.root, out / "tampered-signature")
    mutate_targets_signature(out / "tampered-signature" / "metadata" / "targets.json")

    expired_fixture = make_signed_repository(
        generated / "expired-source",
        expiry=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    copy_repo(expired_fixture.root, out / "expired")

    undeclared_fixture = make_signed_repository(
        generated / "undeclared-source",
        extra_tuf_target=("extra/undeclared.txt", b"signed-but-not-declared\n"),
    )
    copy_repo(undeclared_fixture.root, out / "undeclared")

    rollback_fixture = make_signed_repository(generated / "rollback-source")
    copy_repo(rollback_fixture.root, out / "rollback-v1")
    (out / "rollback-bootstrap-root.json").write_bytes(rollback_fixture.bootstrap_root)
    bump_repository_metadata(rollback_fixture)
    copy_repo(rollback_fixture.root, out / "rollback-v2")

    acceptance = json.loads(
        (ROOT / "fixtures" / "phase-5.4.1" / "acceptance-corpus.json").read_text(
            encoding="utf-8"
        )
    )
    spc = build_projection_bundle(acceptance)
    search_dir = out / "search"
    search_dir.mkdir()
    (search_dir / "spc.json").write_bytes(canonical_json_bytes(spc))
    index_path = search_dir / "atlas-search.sqlite3"
    build_index(spc, index_path)

    resolver = ReferenceResolver(spc)
    reference = {query: resolver.resolve(query) for query in REQUIRED_QUERIES}
    with SQLiteSearchCore.open(index_path, expected_bundle=spc) as core:
        production = {query: core.resolve(query) for query in REQUIRED_QUERIES}
        sqlite_manifest = core.manifest()

    # Phase 5.4.1 freezes exact/scoped/alias identity semantics. Its lexical
    # containment implementation is explicitly a reference path, not the production
    # lexical engine. Phase 5.4.3 SQLite/FTS5 is therefore the authoritative oracle
    # for lexical result sets/ranking in this cross-language spike. Exact stages must
    # still match the Phase 5.4.1 resolver byte-for-byte at the target-set boundary.
    for query in REQUIRED_QUERIES:
        if production[query]["match_stage"] in EXACT_CONTRACT_STAGES:
            if targets_for(reference[query]) != targets_for(production[query]):
                raise RuntimeError(
                    f"reference/production exact search mismatch for {query!r}"
                )

    vector = {
        "a": "<>&",
        "bool": True,
        "nested": {"a": None, "z": "Ω"},
        "number": 1,
        "unicode": "Nóra — Atlas",
    }
    vector_compact = compact_json_bytes(vector)
    vector_newline = canonical_json_bytes(vector)
    expected = {
        "evidence_schema_version": "1.0.0",
        "queries": REQUIRED_QUERIES,
        "query_expectations": {
            query: {
                "targets": targets_for(production[query]),
                "stage": production[query]["match_stage"],
                "status": production[query]["status"],
            }
            for query in REQUIRED_QUERIES
        },
        "reference_query_diagnostics": {
            query: {
                "targets": targets_for(reference[query]),
                "stage": reference[query]["match_stage"],
                "status": reference[query]["status"],
            }
            for query in REQUIRED_QUERIES
        },
        "spc_bundle_digest": spc["bundle_digest"],
        "search_index_sha256": sha256_prefixed(index_path.read_bytes()),
        "sqlite_manifest": sqlite_manifest,
        "serialization_vector": vector,
        "compact_json_base64": base64.b64encode(vector_compact).decode("ascii"),
        "compact_json_sha256": sha256_prefixed(vector_compact),
        "newline_json_base64": base64.b64encode(vector_newline).decode("ascii"),
        "newline_json_sha256": sha256_prefixed(vector_newline),
        "valid_manifest_sha256": sha256_prefixed(
            (out / "valid" / "targets" / "atlas" / "pack-manifest.json").read_bytes()
        ),
    }
    (out / "expected.json").write_text(
        json.dumps(expected, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )

    # The private signers live only in helper objects above. Remove generator working
    # trees after all public metadata/targets have been copied.
    shutil.rmtree(generated)
    print(json.dumps({"workspace": str(out), "spc": spc["bundle_digest"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
