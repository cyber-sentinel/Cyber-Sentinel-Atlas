#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

EXPECTED_CANDIDATES = {"tauri-v2", "electron", "dotnet-wpf"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--summary", required=True)
    args = parser.parse_args()

    evidence_dir = Path(args.evidence_dir)
    packaging_path = evidence_dir / "packaging-feasibility.json"
    summary_path = Path(args.summary)

    require(packaging_path.is_file(), f"missing G-D8 evidence: {packaging_path}")
    require(summary_path.is_file(), f"missing candidate summary: {summary_path}")

    packaging = json.loads(packaging_path.read_text(encoding="utf-8-sig"))
    require(packaging.get("evidence_version") == 1, "unsupported G-D8 evidence version")
    require(packaging.get("phase") == "5.6.2", "G-D8 evidence phase mismatch")
    require(packaging.get("gate") == "G-D8-installer-and-portable-mode-feasibility", "G-D8 gate mismatch")
    require(packaging.get("scope") == "portable-relocation-executable-proof-plus-installer-feasibility", "G-D8 scope mismatch")
    require(packaging.get("installer_build_proven") is False, "G-D8 must not claim a production installer build")
    require(packaging.get("clean_machine_installer_smoke") == "DEFERRED_TO_5.6.4", "clean-machine installer smoke must remain deferred to 5.6.4")
    require(packaging.get("selection_authorized") is False, "G-D8 evidence must not select a framework")

    rows = packaging.get("candidates")
    require(isinstance(rows, list), "G-D8 candidates must be an array")
    by_id: dict[str, dict] = {}
    for row in rows:
        require(isinstance(row, dict), "G-D8 candidate row must be an object")
        candidate = row.get("candidate")
        require(candidate in EXPECTED_CANDIDATES, f"unexpected G-D8 candidate: {candidate!r}")
        require(candidate not in by_id, f"duplicate G-D8 candidate: {candidate}")
        require(row.get("relocated_probe") is True, f"portable relocation was not proven for {candidate}")
        require(row.get("relocated_path_contains_spaces") is True, f"portable relocation path did not exercise spaces for {candidate}")
        require(row.get("probe_exit_code") == 0, f"portable probe failed for {candidate}")
        require(row.get("network_listener") is False, f"portable probe exposed a network listener for {candidate}")
        require(row.get("offline_capable") is True, f"portable probe lost offline capability for {candidate}")
        sidecar_hash = row.get("sidecar_sha256")
        require(isinstance(sidecar_hash, str) and len(sidecar_hash) == 64, f"invalid portable sidecar hash for {candidate}")
        require(isinstance(row.get("portable_size_bytes"), int) and row["portable_size_bytes"] > 0, f"invalid portable size for {candidate}")
        require(isinstance(row.get("runtime_prerequisite"), str) and row["runtime_prerequisite"], f"runtime prerequisite missing for {candidate}")
        options = row.get("installer_options")
        require(isinstance(options, list) and len(options) >= 2 and all(isinstance(item, str) and item for item in options), f"installer options missing for {candidate}")
        require(row.get("installer_payload_model") == "host + atlas-core.exe + atlas-core.exe.sha256 + candidate runtime files", f"installer payload model mismatch for {candidate}")
        require(isinstance(row.get("signing_boundary"), str) and "Authenticode" in row["signing_boundary"], f"signing boundary missing for {candidate}")
        require(row.get("binary_auto_update") == "disabled/not part of First Preview", f"binary auto-update scope mismatch for {candidate}")
        by_id[candidate] = row

    require(set(by_id) == EXPECTED_CANDIDATES, "G-D8 candidate set is incomplete")

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    gates = summary.get("observed_hard_gates")
    require(isinstance(gates, dict), "candidate summary hard-gate object missing")
    require(gates.get("G-D3-offline-no-default-network-listener") == "PASS", "G-D8 requires verified G-D3 evidence")
    require(gates.get("G-D7-desktop-security-surface") == "PASS", "G-D8 requires G-D7 to pass in the same candidate run")

    summary["packaging_feasibility"] = {
        candidate: {
            "portable_relocated_probe": True,
            "portable_size_bytes": evidence["portable_size_bytes"],
            "runtime_prerequisite": evidence["runtime_prerequisite"],
            "installer_options": evidence["installer_options"],
            "installer_payload_model": evidence["installer_payload_model"],
            "signing_boundary": evidence["signing_boundary"],
        }
        for candidate, evidence in sorted(by_id.items())
    }
    gates["G-D8-installer-and-portable-mode-feasibility"] = "PASS_FEASIBILITY"
    summary["selection_authorized"] = False
    summary["selection_reason"] = "ADR-0026 remains blocked until G-D9 and remaining reproducibility requirements are closed. Production installer build and clean-machine smoke remain Phase 5.6.4 work."

    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary["packaging_feasibility"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
