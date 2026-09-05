#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FOUNDATION_PATH = ROOT / "tools" / "ingestion" / "validate_ingestion_foundation.py"

SPEC = importlib.util.spec_from_file_location("atlas_ingestion_foundation", FOUNDATION_PATH)
foundation = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(foundation)

ALLOWED_METADATA_KEYS = {
    "ingestion_contract_version",
    "reference_export_contract_version",
    "source_id",
    "source_version",
    "export_type",
    "collection_method",
    "reference_environment",
    "collector",
    "collected_at",
    "scope",
    "controls",
    "retention_mode",
    "fixture_only",
    "diagnostics",
}


def load_metadata(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("reference-export metadata must be a JSON object")
    unknown = sorted(set(value) - ALLOWED_METADATA_KEYS)
    if unknown:
        raise ValueError(f"reference-export metadata contains unsupported keys: {unknown!r}")
    missing = sorted(ALLOWED_METADATA_KEYS - set(value))
    if missing:
        raise ValueError(f"reference-export metadata missing required builder keys: {missing!r}")
    return value


def build_descriptor(metadata: dict, artifact_path: Path, *, media_type: str, encoding: str) -> dict:
    if not artifact_path.is_file():
        raise ValueError(f"reference-export raw artifact is not a regular file: {artifact_path}")
    raw = artifact_path.read_bytes()
    if not raw:
        raise ValueError("reference-export raw artifact must not be empty")

    descriptor = copy.deepcopy(metadata)
    digest = foundation.sha256_digest(raw)
    descriptor["artifact"] = {
        "logical_name": artifact_path.name,
        "media_type": media_type,
        "encoding": encoding,
        "byte_length": len(raw),
        "sha256": digest,
        "blob_ref": f"blob:{digest}",
    }
    descriptor["reference_export_id"] = foundation.stable_artifact_id("reference-export", descriptor)

    validator = foundation.ingestion_validator("extensions/reference-export.schema.json")
    errors = sorted(validator.iter_errors(descriptor), key=lambda error: list(error.path))
    if errors:
        rendered = "; ".join(
            f"{'/'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
            for error in errors[:20]
        )
        raise ValueError(f"reference-export descriptor schema validation failed: {rendered}")
    return descriptor


def write_descriptor(descriptor: dict, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(descriptor, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and validate an immutable Atlas controlled ReferenceExport descriptor.")
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--media-type", required=True)
    parser.add_argument("--encoding", default="utf-8")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    metadata = load_metadata(args.metadata)
    descriptor = build_descriptor(
        metadata,
        args.artifact,
        media_type=args.media_type,
        encoding=args.encoding,
    )
    write_descriptor(descriptor, args.output)
    print(
        f"ReferenceExport descriptor built: {descriptor['reference_export_id']} "
        f"artifact={descriptor['artifact']['logical_name']} sha256={descriptor['artifact']['sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
