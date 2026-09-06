#!/usr/bin/env python3
"""Compare the frozen Atlas deterministic JSON profile with RFC 8785 ordering.

This is intentionally a bounded comparison helper, not a replacement JCS library.
It implements the RFC 8785 UTF-16 object-member ordering for the JSON value domain
used by these fixtures (objects, arrays, strings, booleans, null and integers).
The purpose is to prove where the existing Atlas profile is byte-compatible and
where it is not, without migrating any existing digest identity.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_prefixed(data: bytes) -> str:
    return "sha256-" + hashlib.sha256(data).hexdigest()


def atlas_compact(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def jcs_string(value: str) -> str:
    # CPython's JSON string escaping is sufficient for the bounded fixture strings:
    # no lone surrogates, no NaN/Infinity and no implementation-specific objects.
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be")


def restricted_jcs(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return jcs_string(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(restricted_jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("JCS object keys must be strings")
        ordered = sorted(value, key=utf16_sort_key)
        return "{" + ",".join(
            jcs_string(key) + ":" + restricted_jcs(value[key]) for key in ordered
        ) + "}"
    raise TypeError(f"fixture value outside bounded JCS comparison domain: {type(value)!r}")


def evidence_bytes(value: Any) -> dict[str, str]:
    atlas = atlas_compact(value)
    jcs = restricted_jcs(value).encode("utf-8")
    return {
        "atlas_base64": base64.b64encode(atlas).decode("ascii"),
        "atlas_sha256": sha256_prefixed(atlas),
        "jcs_base64": base64.b64encode(jcs).decode("ascii"),
        "jcs_sha256": sha256_prefixed(jcs),
        "bytes_equal": atlas == jcs,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    expected = json.loads((args.workspace / "expected.json").read_text(encoding="utf-8"))
    protocol = expected["serialization_vector"]
    protocol_compare = evidence_bytes(protocol)
    if protocol_compare["atlas_sha256"] != expected["compact_json_sha256"]:
        raise RuntimeError("serialization comparison is not bound to the frozen Atlas vector")

    # This pair has deliberately different ordering under Unicode code-point sorting
    # (Python sort_keys) and RFC 8785 UTF-16 code-unit sorting. It prevents the
    # architecture from inferring general JCS equivalence from a friendly test vector.
    ordering_contrast = {"\ue000": "bmp-private-use", "\U00010000": "supplementary"}
    contrast_compare = evidence_bytes(ordering_contrast)
    if contrast_compare["bytes_equal"]:
        raise RuntimeError("ordering contrast failed to distinguish Atlas profile from JCS")

    evidence = {
        "evidence_schema_version": "1.0.0",
        "profile": "atlas-deterministic-json-v1-vs-rfc8785-bounded-comparison",
        "protocol_vector": protocol_compare,
        "ordering_contrast": contrast_compare,
        "general_profile_equivalent_to_jcs": False,
        "existing_digest_migration": False,
        "decision_for_phase_5_5_3": "retain-existing-atlas-deterministic-json-profile",
        "difference": "Atlas v1 uses Python-style Unicode code-point key sorting; RFC 8785/JCS orders object member names by UTF-16 code units. The frozen protocol vector happens to match, but the profiles are not generally byte-equivalent.",
        "scope_note": "This helper is a standards-oriented bounded comparison, not a general-purpose RFC 8785 implementation. A future canonicalization migration requires a separate accepted ADR, versioning and compatibility evidence.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"profile_equal": False, "migration": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
