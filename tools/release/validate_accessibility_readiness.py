#!/usr/bin/env python3
"""Validate PPR-07 accessibility release evidence without allowing source-only PASS."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "docs" / "releases" / "accessibility-readiness.json"
CONTRACT = ROOT / "docs" / "releases" / "accessibility-release-review.md"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MATRIX_KEYS = (
    "keyboard_navigation",
    "focus_visibility",
    "accessible_names",
    "semantic_structure",
    "windows_narrator",
    "high_contrast",
    "display_scaling",
    "text_zoom_reflow",
    "color_independence",
    "error_handling",
    "motion",
    "localization_resilience",
)
ALLOWED = {"NOT_RUN", "PASS", "FAIL", "BLOCKED"}

def validate(data: dict, strict: bool) -> list[str]:
    errors: list[str] = []
    if data.get("schema_version") != "1.0.0":
        errors.append("schema_version must be 1.0.0")
    if data.get("gate") != "PPR-07":
        errors.append("gate must be PPR-07")
    if data.get("state") not in {"PARTIAL", "PASS"}:
        errors.append("state must be PARTIAL or PASS")
    if not CONTRACT.is_file():
        errors.append("accessibility release contract missing")
    matrix = data.get("matrix")
    if not isinstance(matrix, dict):
        errors.append("matrix must be an object")
        matrix = {}
    for key in MATRIX_KEYS:
        if matrix.get(key) not in ALLOWED:
            errors.append(f"{key}: invalid or missing result")
    package_sha = data.get("release_package_sha256")
    if package_sha is not None and (not isinstance(package_sha, str) or not SHA256_RE.fullmatch(package_sha)):
        errors.append("release_package_sha256 must be null or 64 lowercase hex characters")
    for name in ("severity_1_open", "severity_2_open"):
        if not isinstance(data.get(name), int) or data.get(name) < 0:
            errors.append(f"{name} must be a non-negative integer")
    if not isinstance(data.get("manual_review_complete"), bool):
        errors.append("manual_review_complete must be boolean")
    evidence = data.get("evidence")
    if not isinstance(evidence, list) or not evidence or any(not isinstance(x, str) or not x.strip() for x in evidence):
        errors.append("evidence must contain non-empty references")

    env = data.get("environment")
    if not isinstance(env, dict):
        errors.append("environment must be an object")
        env = {}

    pass_ready = (
        isinstance(package_sha, str)
        and bool(SHA256_RE.fullmatch(package_sha))
        and data.get("manual_review_complete") is True
        and data.get("severity_1_open") == 0
        and data.get("severity_2_open") == 0
        and all(matrix.get(key) == "PASS" for key in MATRIX_KEYS)
        and all(isinstance(env.get(k), str) and env.get(k).strip() for k in (
            "windows_build", "webview2_version", "screen_reader", "reviewer", "reviewed_at_utc"
        ))
        and isinstance(env.get("display_configurations"), list)
        and len(env.get("display_configurations")) >= 5
    )

    if data.get("state") == "PASS" and not pass_ready:
        errors.append("PPR-07 cannot PASS without exact package binding and completed executable review")
    if strict and not pass_ready:
        errors.append("strict accessibility release mode requires complete PASS evidence")
    return errors

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()
    try:
        data = json.loads(STATE.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"PPR-07 accessibility validation FAILED: {exc}")
        return 1
    errors = validate(data, args.release)
    if errors:
        print("PPR-07 accessibility validation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 1
    mode = "strict release" if args.release else "baseline"
    print(f"PPR-07 accessibility validation passed ({mode} mode; state={data.get('state')}).")
    return 0

if __name__ == "__main__":
    sys.exit(main())
