#!/usr/bin/env python3
"""Build ephemeral, public-only Phase 5.5.3 cross-language spike fixtures.

Private TUF signing keys remain inside this process via the existing Phase 5.5.2
helper and are never copied into the spike workspace or Git artifacts.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import shutil
import stat
import zipfile
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


def digest_value(value: object) -> str:
    return sha256_prefixed(compact_json_bytes(value))


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


def projection_doc(target_id: str, title: str, description: str) -> dict:
    doc = {
        "target_id": target_id,
        "entity_type": "benchmark",
        "title": title,
        "lifecycle": "current",
        "scope": {
            "namespace": "atlas.benchmark",
            "platform": "benchmark",
            "product": "phase553",
            "provider": "atlas",
            "channel": "stress",
        },
        "lexical_fields": {"description": description},
    }
    doc["projection_digest"] = digest_value(doc)
    return doc


def build_stress_search_fixture(spc: dict, output: Path) -> dict:
    """Build high-fanout and duplicate-numeric cutoff evidence on production schema."""
    stress = copy.deepcopy(spc)
    stress.pop("bundle_digest", None)
    binding = dict(stress["build_binding"])
    binding["canonical_corpus_id"] = "phase-5.5.3-synthetic-search-stress"
    binding["canonical_corpus_digest"] = digest_value(
        {"purpose": "high-fanout-and-numeric-cutoff", "version": "1.0.0"}
    )
    binding["projection_profile_version"] = "phase-5.5.3-stress-v1"
    binding["projection_profile_digest"] = digest_value(
        {"profile": "phase-5.5.3-stress-v1"}
    )
    stress["build_binding"] = binding

    fanout_ids = [f"atlas:benchmark-fanout:{i:08d}" for i in range(80)]
    numeric_ids = [f"atlas:benchmark-numeric:{i:08d}" for i in range(30)]
    for target_id in fanout_ids:
        stress["documents"].append(
            projection_doc(target_id, "Benchmark Fanout", "benchmarkfanout")
        )
    for target_id in numeric_ids:
        stress["documents"].append(
            projection_doc(target_id, "Benchmark Numeric Tie", "numeric deterministic cutoff")
        )
        stress["identifiers"].append(
            {
                "target_id": target_id,
                "identifier_type": "event_id",
                "value": "1",
                "namespace": "atlas.benchmark.numeric",
                "case_sensitive": False,
                "primary": True,
                "numeric_semantics": True,
                "derived_numeric_value": 1,
            }
        )

    stress["documents"] = sorted(stress["documents"], key=lambda item: item["target_id"])
    stress["identifiers"] = sorted(
        stress["identifiers"],
        key=lambda item: (
            item["target_id"], item["identifier_type"], item["namespace"], item["value"]
        ),
    )
    stress["bundle_digest"] = digest_value(stress)
    path = output / "stress-search.sqlite3"
    build_index(stress, path)
    with SQLiteSearchCore.open(path, expected_bundle=stress) as core:
        lexical = core.resolve("benchmarkfanout", limit=20)
        numeric = core.numeric_browse(
            namespace="atlas.benchmark.numeric", identifier_type="event_id", limit=10
        )
    expected_lexical = fanout_ids[:20]
    expected_numeric = numeric_ids[:10]
    if targets_for(lexical) != expected_lexical:
        raise RuntimeError("Python production oracle failed high-fanout stress ordering")
    if [row["target_id"] for row in numeric] != expected_numeric:
        raise RuntimeError("Python production oracle failed duplicate numeric cutoff ordering")
    return {
        "index_sha256": sha256_prefixed(path.read_bytes()),
        "bundle_digest": stress["bundle_digest"],
        "lexical_query": "benchmarkfanout",
        "lexical_expected_targets": expected_lexical,
        "numeric_namespace": "atlas.benchmark.numeric",
        "numeric_identifier_type": "event_id",
        "numeric_limit": 10,
        "numeric_expected_targets": expected_numeric,
        "fanout_document_count": len(fanout_ids),
        "numeric_duplicate_count": len(numeric_ids),
    }


def zip_tree(source: Path, destination: Path) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_STORED) as archive:
        for path in sorted(p for p in source.rglob("*") if p.is_file()):
            archive.write(path, path.relative_to(source).as_posix())


def minimal_archive_entries() -> list[tuple[str, bytes]]:
    return [
        ("metadata/root.json", b"{}"),
        ("metadata/timestamp.json", b"{}"),
        ("metadata/snapshot.json", b"{}"),
        ("metadata/targets.json", b"{}"),
        ("targets/atlas/pack-manifest.json", b"{}"),
    ]


def write_case(path: Path, entries: list[tuple[str, bytes]], *, compression=zipfile.ZIP_STORED) -> None:
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        for name, data in entries:
            archive.writestr(name, data)


def build_archive_cases(valid_repo: Path, output: Path) -> dict:
    cases = output / "archive-cases"
    cases.mkdir()
    zip_tree(valid_repo, cases / "valid.atlaspack")
    base = minimal_archive_entries()
    write_case(cases / "traversal.atlaspack", base + [("../targets/content/evil.json", b"x")])
    write_case(cases / "non-nfc.atlaspack", base + [("targets/content/cafe\u0301.json", b"x")])
    write_case(
        cases / "case-collision.atlaspack",
        base + [("targets/content/Records.json", b"a"), ("targets/content/records.json", b"b")],
    )
    write_case(cases / "active-code.atlaspack", base + [("targets/content/run.ps1", b"x")])
    write_case(cases / "unsupported-compression.atlaspack", base, compression=zipfile.ZIP_BZIP2)

    symlink_path = cases / "symlink.atlaspack"
    with zipfile.ZipFile(symlink_path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in base:
            archive.writestr(name, data)
        info = zipfile.ZipInfo("targets/content/link.json")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, b"target")

    return {
        "valid": "archive-cases/valid.atlaspack",
        "reject": {
            "traversal": "archive-cases/traversal.atlaspack",
            "non_nfc": "archive-cases/non-nfc.atlaspack",
            "case_collision": "archive-cases/case-collision.atlaspack",
            "active_code": "archive-cases/active-code.atlaspack",
            "symlink": "archive-cases/symlink.atlaspack",
            "unsupported_compression": "archive-cases/unsupported-compression.atlaspack",
        },
    }


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

    for query in REQUIRED_QUERIES:
        if production[query]["match_stage"] in EXACT_CONTRACT_STAGES:
            if targets_for(reference[query]) != targets_for(production[query]):
                raise RuntimeError(
                    f"reference/production exact search mismatch for {query!r}"
                )

    stress = build_stress_search_fixture(spc, search_dir)
    archive_cases = build_archive_cases(out / "valid", out)

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
        "search_stress": stress,
        "archive_cases": archive_cases,
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

    shutil.rmtree(generated)
    print(json.dumps({"workspace": str(out), "spc": spc["bundle_digest"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
