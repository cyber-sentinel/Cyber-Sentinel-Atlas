#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path, PurePosixPath
import importlib.util
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
FOUNDATION_PATH = ROOT / "tools" / "ingestion" / "validate_ingestion_foundation.py"

SPEC = importlib.util.spec_from_file_location("atlas_ingestion_foundation", FOUNDATION_PATH)
foundation = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(foundation)

# Phase-aware implementation authorization. Every real connector/parser/normalizer
# must be explicitly listed by an Architecture-authorized slice. Unknown files
# remain fail-closed and are rejected.
AUTHORIZED_IMPLEMENTATIONS = {
    "ingestion/connectors/mitre-attack-enterprise.json": "phase-5.3.2",
    "ingestion/parsers/mitre-attack-stix21.definition.json": "phase-5.3.2",
    "ingestion/parsers/mitre_attack_stix.py": "phase-5.3.2",
    "ingestion/normalizers/mitre-attack-enterprise.definition.json": "phase-5.3.2",
    "ingestion/normalizers/mitre_attack.py": "phase-5.3.2",
    "ingestion/connectors/microsoft-sysmon-docs.json": "phase-5.3.3",
    "ingestion/parsers/microsoft-sysmon-markdown.definition.json": "phase-5.3.3",
    "ingestion/parsers/microsoft_sysmon_markdown.py": "phase-5.3.3",
    "ingestion/normalizers/microsoft-sysmon-docs.definition.json": "phase-5.3.3",
    "ingestion/normalizers/microsoft_sysmon_docs.py": "phase-5.3.3",
}

BLANKET_DENIAL_PREFIX = "broad/live ingestion implementation is not authorized: "
CONTROLLED_DIRS = {
    "ingestion/connectors",
    "ingestion/parsers",
    "ingestion/normalizers",
}


def _git_tracked_paths(root: Path) -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        capture_output=True,
        text=False,
    )
    return [p.decode("utf-8") for p in proc.stdout.split(b"\0") if p]


def implementation_authorization_errors(tracked_paths: list[str]) -> list[str]:
    errors: list[str] = []
    tracked = {str(PurePosixPath(path.replace("\\", "/"))) for path in tracked_paths}

    for path in sorted(tracked):
        pp = PurePosixPath(path)
        if str(pp.parent) not in CONTROLLED_DIRS or pp.name == "README.md":
            continue
        if path not in AUTHORIZED_IMPLEMENTATIONS:
            errors.append(f"undeclared ingestion implementation is not authorized: {path}")

    for path, slice_id in sorted(AUTHORIZED_IMPLEMENTATIONS.items()):
        if path not in tracked:
            errors.append(f"authorized implementation missing from repository ({slice_id}): {path}")

    return errors


def validate_repository(root: Path | None = None) -> list[str]:
    root = Path(root or ROOT)
    errors = foundation.validate_repository(root)
    filtered: list[str] = []

    for error in errors:
        if error.startswith(BLANKET_DENIAL_PREFIX):
            path = error[len(BLANKET_DENIAL_PREFIX):]
            if path in AUTHORIZED_IMPLEMENTATIONS:
                continue
        filtered.append(error)

    try:
        tracked = _git_tracked_paths(root)
        filtered.extend(implementation_authorization_errors(tracked))
    except (OSError, subprocess.CalledProcessError) as exc:
        filtered.append(f"unable to enforce ingestion implementation authorization: {exc}")

    return filtered


def main() -> int:
    errors = validate_repository(ROOT)
    if errors:
        for error in errors:
            print(error)
        print(f"Atlas ingestion validation FAILED with {len(errors)} error(s).")
        return 1

    print("Atlas ingestion foundation + phase-aware implementation authorization passed.")
    print("Authorized implementation slices: Phase 5.3.2 MITRE ATT&CK canary and Phase 5.3.3 Sysmon documentation path only.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
