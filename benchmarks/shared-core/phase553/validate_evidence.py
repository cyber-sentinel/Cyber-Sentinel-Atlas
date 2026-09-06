#!/usr/bin/env python3
"""Validate one OS evidence set for the Phase 5.5.3 finalist spike."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

REQUIRED_GATES = {f"G-SC{i}" for i in range(1, 9)}
REQUIRED_BINDINGS = {
    "spc_bundle_digest",
    "search_index_sha256",
    "serialization_sha256",
}
CANDIDATE_ORDER = ("python-control", "go", "rust")


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("evidence_schema_version") != "1.0.0":
        raise RuntimeError(f"unsupported evidence schema: {path}")
    if set(value.get("gates", {})) != REQUIRED_GATES:
        raise RuntimeError(f"candidate gate set mismatch: {path}")
    if not REQUIRED_BINDINGS.issubset(value.get("bindings", {})):
        raise RuntimeError(f"candidate binding set incomplete: {path}")
    claimed = bool(value.get("eligible"))
    derived = all(bool(value["gates"][gate]) for gate in sorted(REQUIRED_GATES))
    if claimed != derived:
        raise RuntimeError(f"candidate eligibility is inconsistent with hard gates: {path}")
    return value


def load_serialization(path: Path, expected_digest: str) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("evidence_schema_version") != "1.0.0":
        raise RuntimeError("unsupported serialization-comparison evidence schema")
    protocol = value.get("protocol_vector", {})
    contrast = value.get("ordering_contrast", {})
    if protocol.get("atlas_sha256") != expected_digest:
        raise RuntimeError("serialization comparison is not bound to candidate digest evidence")
    if protocol.get("bytes_equal") is not True:
        raise RuntimeError("frozen protocol vector unexpectedly diverges from bounded JCS comparison")
    if contrast.get("bytes_equal") is not False:
        raise RuntimeError("serialization comparison failed to prove general profile distinction")
    if value.get("general_profile_equivalent_to_jcs") is not False:
        raise RuntimeError("general Atlas/JCS equivalence must not be claimed")
    if value.get("existing_digest_migration") is not False:
        raise RuntimeError("Phase 5.5.3 must not migrate existing digest identities")
    if value.get("decision_for_phase_5_5_3") != "retain-existing-atlas-deterministic-json-profile":
        raise RuntimeError("serialization profile decision is not fail-closed")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--go", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--serialization", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    candidates = {
        "python-control": load(args.python),
        "go": load(args.go),
        "rust": load(args.rust),
    }
    baseline_bindings = candidates["python-control"]["bindings"]
    serialization = load_serialization(
        args.serialization, baseline_bindings["serialization_sha256"]
    )
    for name, evidence in candidates.items():
        for key in REQUIRED_BINDINGS:
            if evidence["bindings"][key] != baseline_bindings[key]:
                raise RuntimeError(f"{name} does not share the exact {key} evidence binding")
        exact = float(evidence.get("search", {}).get("exact_p95_ms", 0.0))
        lexical = float(evidence.get("search", {}).get("lexical_p95_ms", 0.0))
        if evidence["gates"]["G-SC3"] and (exact >= 100.0 or lexical >= 300.0):
            raise RuntimeError(f"{name} claims G-SC3 pass outside latency gates")

    # Python is the semantic oracle and Go is the executable production finalist for
    # this spike iteration. Rust is evaluated neutrally: failure becomes evidence,
    # never an expected outcome baked into the validator.
    if not candidates["python-control"]["eligible"]:
        raise RuntimeError("Python semantic control unexpectedly failed a mandatory gate")
    if not candidates["go"]["eligible"]:
        raise RuntimeError("Go finalist failed a mandatory gate")

    eligible = [name for name in CANDIDATE_ORDER if candidates[name]["eligible"]]
    disqualified = {
        name: [gate for gate, passed in candidates[name]["gates"].items() if not passed]
        for name in CANDIDATE_ORDER
        if not candidates[name]["eligible"]
    }

    # Provisional policy weights only. Final ADR rationale must bind them to the
    # cross-platform measured evidence and exact dependency/runtime facts.
    score_profiles = {
        "python-control": {
            "contract_security": 30,
            "tuf_pack_trust": 18,
            "sqlite_search": 15,
            "durability_portability": 9,
            "footprint": 3,
            "interface_integration": 6,
            "maintainability_supply_chain": 4,
        },
        "go": {
            "contract_security": 30,
            "tuf_pack_trust": 20,
            "sqlite_search": 15,
            "durability_portability": 9,
            "footprint": 9,
            "interface_integration": 9,
            "maintainability_supply_chain": 4,
        },
        "rust": {
            "contract_security": 30,
            "tuf_pack_trust": 18,
            "sqlite_search": 15,
            "durability_portability": 9,
            "footprint": 10,
            "interface_integration": 9,
            "maintainability_supply_chain": 4,
        },
    }
    scores = {name: score_profiles[name] for name in eligible}
    totals = {name: sum(parts.values()) for name, parts in scores.items()}
    summary = {
        "summary_schema_version": "1.2.0",
        "eligible_candidates": eligible,
        "disqualified_candidates": disqualified,
        "bindings": baseline_bindings,
        "serialization_profile": {
            "general_profile_equivalent_to_jcs": serialization["general_profile_equivalent_to_jcs"],
            "existing_digest_migration": serialization["existing_digest_migration"],
            "decision_for_phase_5_5_3": serialization["decision_for_phase_5_5_3"],
            "ordering_contrast_atlas_sha256": serialization["ordering_contrast"]["atlas_sha256"],
            "ordering_contrast_jcs_sha256": serialization["ordering_contrast"]["jcs_sha256"],
        },
        "scores": scores,
        "score_totals": totals,
        "provisional_rank": sorted(totals, key=lambda name: (-totals[name], name)),
        "decision_state": "cross-platform-evidence-pending-until-linux-and-windows-artifacts-are-compared",
        "scoring_state": "provisional-policy-profile-final-adr-requires-evidence-bound-rationale",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"validated": True, "rank": summary["provisional_rank"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
